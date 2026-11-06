# Pre-kickoff disclosure

Kickoff is 2026-11-03 17:00 CET. This page states what existed before then and what comes after.

## The rule, as we understand it

In paraphrase: lablab's guide says core AI functionality should be built during the event window, while prior non-AI scaffolding is generally allowed. This is our summary rather than a quotation, so the guide's own wording takes precedence.

## Written before kickoff: non-AI scaffolding

| Area | Files | What it does |
|---|---|---|
| Sandbox | `app/sandbox.py`, `worker/` | Runs a browser in a throwaway container and records evidence |
| Test fixtures | `worker/fixtures/` | Harmless test pages with a fictional brand |
| Orchestration | `app/scans.py`, `app/config.py`, `app/models.py`, `app/ratelimit.py`, `app/urlpolicy.py` | Job queue, storage, settings, rate limits, URL validation |
| API and UI | `app/main.py`, `app/static/` | Routes, security headers, report pages |
| Blast Radius | `app/blast_radius.py` | A pure, rule-based function from events to report rows |
| Verdict seam | `app/verdict.py` | A protocol, plus an engine that always returns `pending` |
| Deployment | `deploy/`, `Makefile` | Firewall, provisioning, verification, systemd units, Caddy |
| Tests and docs | `tests/`, `docs/`, `README.md` | Offline tests and documentation |

Three items sit close to the line, so we name them:

- **The verdict seam** defines where AI will plug in. It contains no AI logic and never produces a verdict.
- **The `hostile-injection` fixture** contains concealed instructions, as test data. The worker extracts hidden text with plain DOM rules, and nothing sends it to a model. The report marks it `observed` without classifying it.
- **The report UI** has a place for a verdict. Today it says the verdict engine is not connected.

The scaffolding was written with help from an AI coding assistant. That is a tool for writing the code, and is not AI functionality in the product.

## Written after kickoff: all AI

None of this exists before kickoff:

- Any LLM client or call
- Any prompt
- The agent planning loop
- AI verdict logic, meaning a real `VerdictEngine`
- Classification of prompt injection by a model
- The AI parts of the demo video

## Commits

Commits are never backdated. Their timestamps are the real times of the work.

**Correction:** the first commit was made after kickoff, not before it. The scaffolding was finished at about 01:05 CET on 2026-11-03, roughly 16 hours before kickoff, and those are the file modification times at the moment it was staged, but it was not committed in time. Git history therefore cannot prove the timing on its own. The first commit contains the scaffolding and no AI code, and all AI code arrives in later commits. If this page turns out to be wrong, we will correct it in a new commit rather than rewrite the history.
