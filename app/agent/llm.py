"""Vultr Serverless Inference client (OpenAI-compatible) and the model-output schema."""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
import os
from pathlib import Path
from typing import Any, Literal, Protocol

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.agent.settings import API_KEY_ENV, AgentSettings

logger = logging.getLogger(__name__)

Classification = Literal["benign", "suspicious", "malicious", "inconclusive"]


class ModelError(Exception):
    """The model gave no usable answer. The message is safe to log and to show."""


class Indicator(BaseModel):
    model_config = ConfigDict(extra="ignore")
    claim: str = Field(max_length=400)
    evidence_seqs: list[int] = Field(default_factory=list, max_length=20)


class ProposedAction(BaseModel):
    model_config = ConfigDict(extra="ignore")
    kind: str = Field(max_length=60)
    target: str = Field(default="", max_length=2048)
    reason: str = Field(default="", max_length=400)


class Analysis(BaseModel):
    model_config = ConfigDict(extra="ignore")
    classification: Classification
    confidence: float = Field(ge=0, le=1)
    summary: str = Field(max_length=1200)
    injection_detected: bool = False
    indicators: list[Indicator] = Field(default_factory=list, max_length=12)
    proposed_actions: list[ProposedAction] = Field(default_factory=list, max_length=8)


class ChatClient(Protocol):
    model: str

    async def analyse(self, messages: list[dict[str, Any]]) -> tuple[Analysis, str]:
        """Returns the validated analysis and the raw model text."""
        ...


class CallBudget:
    """A hard daily call cap, persisted so a restart cannot reset the spend."""

    def __init__(self, path: Path, per_day: int) -> None:
        self._path, self._per_day = path, per_day
        self._lock = asyncio.Lock()

    async def take(self) -> None:
        async with self._lock:
            today = dt.datetime.now(dt.UTC).date().isoformat()
            try:
                state = json.loads(self._path.read_text())
            except (OSError, ValueError):
                state = {}
            calls = int(state.get("calls", 0)) if state.get("day") == today else 0
            if calls >= self._per_day:
                raise ModelError("The daily model budget is used up.")
            self._path.parent.mkdir(parents=True, exist_ok=True)
            temp = self._path.with_suffix(".tmp")
            temp.write_text(json.dumps({"day": today, "calls": calls + 1}))
            temp.replace(self._path)


def _schema() -> dict[str, Any]:
    return {"type": "json_schema", "json_schema": {"name": "analysis", "schema": Analysis.model_json_schema()}}


def parse_analysis(text: str) -> Analysis:
    body = text.strip()
    if body.startswith("```"):
        body = body.strip("`").removeprefix("json").strip()
    return Analysis.model_validate_json(body)


class VultrChatClient:
    def __init__(self, settings: AgentSettings, budget: CallBudget, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._settings, self._budget, self._transport = settings, budget, transport
        self.model = settings.model

    async def analyse(self, messages: list[dict[str, Any]]) -> tuple[Analysis, str]:
        last = "The model returned an invalid answer."
        for _ in range(2):  # one retry, for transient faults and malformed output alike
            await self._budget.take()
            try:
                text = await self._post(messages)
                return parse_analysis(text), text
            except ModelError:
                raise
            except (ValidationError, ValueError):
                logger.warning("model output failed validation")
            except httpx.HTTPStatusError as exc:
                last = f"The model service answered HTTP {exc.response.status_code}."
                logger.warning("%s", last)
                if exc.response.status_code < 500 and exc.response.status_code != 429:
                    break
            except httpx.HTTPError as exc:
                # The exception class only: its text could carry request details.
                last = f"The model service could not be reached ({type(exc).__name__})."
                logger.warning("%s", last)
        raise ModelError(last)

    async def _post(self, messages: list[dict[str, Any]]) -> str:
        key = os.environ.get(API_KEY_ENV, "").strip()
        if not key:
            raise ModelError("No model API key is configured.")
        body = {
            "model": self._settings.model,
            "messages": messages,
            "temperature": 0,
            "max_tokens": self._settings.max_output_tokens,
            "response_format": _schema(),
        }
        if self._settings.reasoning_effort:
            body["reasoning_effort"] = self._settings.reasoning_effort
        async with httpx.AsyncClient(timeout=self._settings.request_timeout_s, transport=self._transport) as client:
            response = await client.post(
                f"{self._settings.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {key}"},
                json=body,
            )
        response.raise_for_status()
        try:
            choice = response.json()["choices"][0]
            content = str(choice["message"].get("content") or "")
        except (KeyError, IndexError, TypeError, AttributeError) as exc:
            raise ValueError("unexpected response shape") from exc
        if not content and choice.get("finish_reason") == "length":
            raise ModelError("The model used its whole token budget reasoning and gave no answer.")
        return content
