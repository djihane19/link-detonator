#!/usr/bin/env python3
"""Link Detonator sandbox worker.

Opens one target in headless Chromium and streams evidence to stdout as one
JSON object per line. The host assigns seq, source and its own timestamp and
treats everything here as hostile input (see docs/CONTRACT.md).

The worker observes only: it never clicks, types or submits. Every page string
is attacker-controlled. Chromium runs with --no-sandbox because the container
is the boundary.
"""

from __future__ import annotations

import time

# Taken before the slow imports below: the internal deadline covers them too.
STARTED_AT = time.monotonic()

import argparse
import asyncio
import base64
import ipaddress
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
from collections import Counter
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import urlsplit

from playwright.async_api import (
    BrowserContext,
    CDPSession,
    Dialog,
    Download,
    Error as PlaywrightError,
    Frame,
    Page,
    Playwright,
    Request,
    Response,
    Route,
    TimeoutError as PlaywrightTimeoutError,
    WebSocket,
    WebSocketRoute,
    async_playwright,
)

# Timing. The host kills at 60 s by default and passes --deadline at 75% of its own
# deadline, so the worker finishes first. The default matches that share of 60 s.
DEFAULT_DEADLINE_S = 45.0
DEFAULT_DWELL_S = 12.0
MIN_DEADLINE_S = 5.0
MAX_DEADLINE_S = 300.0
TEARDOWN_RESERVE_S = 3.0
WATCHDOG_MARGIN_S = 1.5
FINAL_CAPTURE_RESERVE_S = 5.0
SCREENSHOT_INTERVAL_S = 3.0
URL_CHECK_INTERVAL_S = 1.0

START_TIMEOUT_S = 15.0
LAUNCH_TIMEOUT_S = 20.0
NAVIGATION_TIMEOUT_MS = 15_000
LOAD_TIMEOUT_MS = 8_000
SCREENSHOT_TIMEOUT_MS = 4_000
EXTRACT_TIMEOUT_MS = 6_000
CLOSED_ROOTS_TIMEOUT_MS = 3_000
PROBE_TIMEOUT_MS = 2_000
POST_NAVIGATION_LOAD_TIMEOUT_MS = 3_000
URL_QUIET_S = 0.3
URL_SETTLE_LIMIT_S = 2.0
SETTLE_TIMEOUT_S = 2.0
POPUP_URL_WAIT_MS = 1_500
HUNG_OPERATIONS_TO_GIVE_UP = 2

# Output caps. These sit below the host's hard caps so that a noisy page costs
# some detail, not the whole scan: exceeding a host cap kills the sandbox.
LINE_BYTES_CAP = 7 * 1024 * 1024
TOTAL_BYTES_CAP = 56 * 1024 * 1024
TOTAL_EVENTS_CAP = 4_500
EVENT_TYPE_CAPS = {
    "request": 500,
    "request_failed": 500,
    "response": 200,
    "navigation": 200,
    "screenshot": 25,
    "download_attempt": 50,
    "dialog": 100,
    "popup": 50,
    "form": 100,
    "text_layers": 10,
    "page_unresponsive": 50,
}
# A response from a private address is the strongest evidence a scan can produce, so a
# page cannot use up the total cap first to hide it.
ESSENTIAL_EVENTS = frozenset({"worker_started", "page_unresponsive", "page_crash", "response"})

DEFAULT_STRING_CAP = 4_096
STRING_CAPS: dict[str, int | None] = {
    "b64": None,
    "visible_text": 20_000,
    "text": 2_000,
    "selector": 256,
    "message": 2_000,
    "error": 512,
    "suggested_filename": 512,
    "field_names": 128,
}

MAX_CONCEALED_PER_SOURCE = 50
MAX_FIELD_NAMES = 100
MAX_FRAMES = 16
MAX_CLOSED_SHADOW_ROOTS = 32
MAX_PENDING_TRACKED = 5_000
REQUEST_TRACKING_LIMIT = 2_000
MAX_LOG_LINES = 100
PS_TIMEOUT_S = 0.5
WORKDIR_REMOVAL_WAIT_S = 1.0
PEER_ADDRESS_TIMEOUT_S = 1.0

JPEG_QUALITY = 60
VIEWPORT = {"width": 1280, "height": 800}
PENDING_REQUEST_ERROR = "no response before the scan ended"

# Fixtures exist only inside this process; no hostile page is ever hosted.
FIXTURE_HOST = "fixtures.invalid"
FIXTURE_ORIGIN = f"http://{FIXTURE_HOST}"
FIXTURE_ROUTE_PATTERN = f"{FIXTURE_ORIGIN}/**"
ALL_REQUESTS_PATTERN = "**/*"
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
NON_NETWORK_SCHEMES = frozenset({"data", "blob", "about"})
# Live scans open a stranger's page from this VM's address. Reading is what a scan needs;
# a page's POSTs to third parties (form spam, login stuffing) are stopped and recorded.
LIVE_ALLOWED_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# Names that only mean something inside a network. Mirrors app/urlpolicy.py, which
# re-judges every event: this copy only decides what is worth reporting.
LOCAL_NAME_SUFFIXES = ("localhost", "local", "internal", "intranet", "lan", "home", "corp", "private", "home.arpa")
# Chromium honours only the last --disable-features, so this repeats Playwright 1.64.1's own
# list (chromiumSwitches.ts) before adding to it. tests/test_worker_offline.py compares the
# two. The last three are Chromium's local-network gate: from an http page it fails requests
# to private addresses itself with net::ERR_FAILED, after connecting, so a report could not
# tell that from the firewall. Requests must reach the firewall to test it.
PLAYWRIGHT_DISABLED_FEATURES = (
    "AvoidUnnecessaryBeforeUnloadCheckSync",
    "DestroyProfileOnBrowserClose",
    "DialMediaRouteProvider",
    "GlobalMediaControls",
    "HttpsUpgrades",
    "LensOverlay",
    "MediaRouter",
    "PaintHolding",
    "ThirdPartyStoragePartitioning",
    "BlockOriginHeaderModificationOnRedirect",
    "AvoidCorsURLLoaderRestartOnRedirect",
    "Translate",
    "AutoDeElevate",
    "OptimizationHints",
    "NetworkTimeServiceQuerying",
    "AimEnabled",
    "msForceBrowserSignIn",
    "msEdgeUpdateLaunchServicesPreferredVersion",
)
LOCAL_NETWORK_GATE_FEATURES = (
    "LocalNetworkAccessChecks",
    "BlockInsecurePrivateNetworkRequests",
    "PrivateNetworkAccessSendPreflights",
)
# What a request ends with when an --offline mechanism stopped it: the route
# abort, or the dead proxy and resolver for traffic the route cannot see.
LOCAL_BLOCK_ERROR_PREFIXES = (
    "net::ERR_BLOCKED_BY_CLIENT",
    "net::ERR_PROXY_CONNECTION_FAILED",
    "net::ERR_TUNNEL_CONNECTION_FAILED",
    "net::ERR_NAME_NOT_RESOLVED",
)


@dataclass(frozen=True)
class FixtureRoute:
    """One fixture URL. Redirects are client-side because Playwright does not
    route the next hop of an HTTP redirect, so that hop could never be served."""

    file: str | None = None
    attachment: str | None = None
    meta_refresh_to: str | None = None
    script_redirect_to: str | None = None


FIXTURE_NAMES = (
    "benign",
    "phish-login",
    "hostile-injection",
    "hostile-download",
    "hostile-ssrf",
    "hostile-freeze",
    "hostile-memory",
    "hostile-gauntlet",
)

FIXTURE_ROUTES: dict[str, FixtureRoute] = {
    "/benign": FixtureRoute(file="benign.html"),
    "/phish-login": FixtureRoute(meta_refresh_to="/phish-login/verify"),
    "/phish-login/verify": FixtureRoute(script_redirect_to="/phish-login/signin"),
    "/phish-login/signin": FixtureRoute(file="phish-login.html"),
    "/hostile-injection": FixtureRoute(file="hostile-injection.html"),
    "/hostile-download": FixtureRoute(file="hostile-download.html"),
    "/hostile-download/larkspur-statement.txt": FixtureRoute(
        file="download-payload.txt", attachment="larkspur-statement.txt"
    ),
    "/hostile-ssrf": FixtureRoute(file="hostile-ssrf.html"),
    "/hostile-freeze": FixtureRoute(file="hostile-freeze.html"),
    "/hostile-memory": FixtureRoute(file="hostile-memory.html"),
    "/hostile-gauntlet": FixtureRoute(meta_refresh_to="/hostile-gauntlet/landing"),
    "/hostile-gauntlet/landing": FixtureRoute(file="hostile-gauntlet.html"),
    "/hostile-gauntlet/larkspur-statement.txt": FixtureRoute(
        file="download-payload.txt", attachment="larkspur-statement.txt"
    ),
}

# Runs in an isolated world, whose JS builtins and DOM wrappers are separate
# from the page's, so page-defined overrides of DOM APIs never reach it. Named
# children can still clobber properties on a form or document in any world
# (<input name="getAttribute">), so DOM access goes through uncurried prototype
# accessors rather than plain property reads.
EXTRACT_FUNCTION = r"""
function (entryRoot) {
  'use strict';
  const MAX_PER_SOURCE = 50, MAX_TEXT = 2000, MAX_VISIBLE = 20000;
  const MAX_NODES = 60000, MAX_MS = 2500, MAX_FIELDS = 100, MAX_RAW_TEXT = 65536;
  const TINY_PX = 3, MIN_CONTRAST = 1.15, FAR_RIGHT_PX = 1000, FAR_DOWN_PX = 20000;
  const HTML_NS = 'http://www.w3.org/1999/xhtml';
  const UNRENDERED_TEXT_PARENTS = new Set(['script', 'style', 'noscript', 'template',
    'option', 'optgroup', 'datalist', 'textarea']);
  const TECHNICAL_META = new Set(['viewport', 'theme-color', 'color-scheme', 'referrer',
    'format-detection', 'charset', 'robots', 'generator']);
  const LABEL_ATTRIBUTES = ['aria-label', 'aria-description', 'aria-roledescription',
    'aria-placeholder', 'aria-valuetext', 'title'];
  const VISIBILITY_CHECKS = { checkOpacity: true, checkVisibilityCSS: true,
    opacityProperty: true, visibilityProperty: true };
  const NOT_FIELDS = new Set(['submit', 'button', 'reset', 'image']);

  const getter = (proto, prop) => {
    const get = Object.getOwnPropertyDescriptor(proto, prop).get;
    return (target) => get.call(target);
  };
  const method = (proto, prop) => {
    const fn = proto[prop];
    return (target, ...args) => fn.apply(target, args);
  };
  const parentNodeOf = getter(Node.prototype, 'parentNode');
  const nodeTypeOf = getter(Node.prototype, 'nodeType');
  const nodeValueOf = getter(Node.prototype, 'nodeValue');
  const textContentOf = getter(Node.prototype, 'textContent');
  const baseUriOf = getter(Node.prototype, 'baseURI');
  const nameOf = getter(Element.prototype, 'localName');
  const namespaceOf = getter(Element.prototype, 'namespaceURI');
  const openShadowOf = getter(Element.prototype, 'shadowRoot');
  const hostOf = getter(ShadowRoot.prototype, 'host');
  const fieldsOf = getter(HTMLFormElement.prototype, 'elements');
  const formOwnerOf = getter(HTMLInputElement.prototype, 'form');
  const attr = method(Element.prototype, 'getAttribute');
  const rectOf = method(Element.prototype, 'getBoundingClientRect');
  const isRendered = method(Element.prototype, 'checkVisibility');
  const createWalker = method(Document.prototype, 'createTreeWalker');
  const styleOf = window.getComputedStyle;
  const frameDocument = window.document;

  const started = performance.now();
  const concealed = [];
  const counts = Object.create(null);
  const seen = new Set();
  const forms = [];
  const orphanPasswordFields = [];
  const visibleParts = [];
  let visibleLength = 0;
  let lastBlock = null;

  const normalize = (text) => String(text).slice(0, MAX_RAW_TEXT).replace(/\s+/g, ' ').trim();

  const composedParent = (node) => {
    const parent = parentNodeOf(node);
    if (!parent) return null;
    const type = nodeTypeOf(parent);
    if (type === 1) return parent;
    if (type === 11) {
      try { return hostOf(parent); } catch (e) { return null; }
    }
    return null;
  };

  const selectorOf = (el) => {
    const parts = [];
    let current = el;
    for (let depth = 0; current && depth < 5; depth += 1) {
      let part = nameOf(current);
      const id = attr(current, 'id');
      if (id) {
        parts.unshift(part + '#' + id.slice(0, 40));
        break;
      }
      const classes = attr(current, 'class');
      if (classes && classes.trim()) {
        part += '.' + classes.trim().split(/\s+/).slice(0, 2).join('.').slice(0, 40);
      }
      parts.unshift(part);
      current = composedParent(current);
    }
    return parts.join(' > ');
  };

  const addConcealed = (source, rawText, el) => {
    const text = normalize(rawText);
    if (!text) return;
    const key = source + '\u0000' + text;
    if (seen.has(key)) return;
    seen.add(key);
    counts[source] = (counts[source] || 0) + 1;
    if (counts[source] > MAX_PER_SOURCE) return;
    concealed.push({ source, text: text.slice(0, MAX_TEXT), selector: el ? selectorOf(el) : '' });
  };

  const parseColor = (value) => {
    let m = /^rgba?\(\s*([\d.]+)[\s,]+([\d.]+)[\s,]+([\d.]+)(?:\s*[,/]\s*([\d.]+)(%?))?\s*\)$/.exec(value);
    if (m) {
      const alpha = m[4] === undefined ? 1 : (m[5] ? parseFloat(m[4]) / 100 : parseFloat(m[4]));
      return [parseFloat(m[1]), parseFloat(m[2]), parseFloat(m[3]), alpha];
    }
    m = /^color\(srgb\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)(?:\s*\/\s*([\d.]+))?\s*\)$/.exec(value);
    if (m) {
      return [m[1] * 255, m[2] * 255, m[3] * 255, m[4] === undefined ? 1 : parseFloat(m[4])];
    }
    return null;
  };

  const luminance = (c) => {
    const channel = (v) => {
      const s = v / 255;
      return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
    };
    return 0.2126 * channel(c[0]) + 0.7152 * channel(c[1]) + 0.0722 * channel(c[2]);
  };

  const contrast = (a, b) => {
    const la = luminance(a), lb = luminance(b);
    return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
  };

  // Null means "cannot tell" (for example a background image), and no claim is made.
  const effectiveBackground = (el) => {
    for (let a = el; a; a = composedParent(a)) {
      const style = styleOf(a);
      if (style.backgroundImage !== 'none') return null;
      const color = parseColor(style.backgroundColor);
      if (!color) return null;
      if (color[3] >= 0.95) return color;
    }
    return [255, 255, 255, 1];
  };

  const blendsIntoBackground = (el, style) => {
    const paint = parseColor(style.webkitTextFillColor || style.color);
    if (!paint) return false;
    if (paint[3] <= 0.05) return true;
    const background = effectiveBackground(el);
    return background !== null && contrast(paint, background) < MIN_CONTRAST;
  };

  const clipsEverything = (style) => {
    if (style.contentVisibility === 'hidden') return true;
    const path = style.clipPath;
    if (path && path !== 'none' && /^(inset\((50|100)%|circle\(0|ellipse\(0)/.test(path)) return true;
    if (style.position === 'absolute' || style.position === 'fixed') {
      const m = /^rect\(\s*(-?[\d.]+)px[\s,]+(-?[\d.]+)px[\s,]+(-?[\d.]+)px[\s,]+(-?[\d.]+)px/.exec(style.clip || '');
      if (m && (parseFloat(m[3]) <= parseFloat(m[1]) || parseFloat(m[2]) <= parseFloat(m[4]))) return true;
    }
    return false;
  };

  const clippedAway = (el, rect) => {
    let inSummary = false;
    for (let a = el, depth = 0; a && depth < 48; a = composedParent(a), depth += 1) {
      const style = styleOf(a);
      if (clipsEverything(style)) return true;
      const name = nameOf(a);
      if (name === 'summary') inSummary = true;
      if (name === 'details') {
        if (!inSummary && attr(a, 'open') === null) return true;
        inSummary = false;
      }
      const cuts = (v) => v === 'hidden' || v === 'clip';
      if (name !== 'html' && name !== 'body' && (cuts(style.overflowX) || cuts(style.overflowY))) {
        const box = rectOf(a);
        if (box.width <= 1 || box.height <= 1) return true;
        if (rect.right <= box.left || rect.left >= box.right ||
            rect.bottom <= box.top || rect.top >= box.bottom) return true;
      }
    }
    return false;
  };

  const isPositioned = (el) => {
    for (let a = el, depth = 0; a && depth < 48; a = composedParent(a), depth += 1) {
      const position = styleOf(a).position;
      if (position === 'absolute' || position === 'fixed') return true;
    }
    return false;
  };

  // Text above or left of the document origin cannot be scrolled to. Text far to
  // the right or far below can, but only something positioned ends up that far.
  const isOffscreen = (el, rect) => {
    const left = rect.left + window.scrollX, top = rect.top + window.scrollY;
    if (rect.right + window.scrollX <= 0 || rect.bottom + window.scrollY <= 0) return true;
    if (left >= window.innerWidth + FAR_RIGHT_PX) return true;
    return top >= FAR_DOWN_PX && isPositioned(el);
  };

  const frameIsHidden = (() => {
    if (window.innerWidth <= 1 || window.innerHeight <= 1) return true;
    try {
      const owner = window.frameElement;
      return Boolean(owner) && !isRendered(owner, VISIBILITY_CHECKS);
    } catch (e) {
      return false;
    }
  })();

  const textRange = new Range();

  const concealmentOf = (textNode, parent) => {
    if (frameIsHidden || !isRendered(parent, VISIBILITY_CHECKS)) return 'hidden_css';
    const style = styleOf(parent);
    if ((parseFloat(style.fontSize) || 0) < TINY_PX) return 'tiny_text';
    textRange.selectNodeContents(textNode);
    const rect = textRange.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return 'hidden_css';
    if (rect.height < TINY_PX) return 'tiny_text';
    if (isOffscreen(parent, rect)) return 'offscreen';
    if (clippedAway(parent, rect)) return 'hidden_css';
    if (blendsIntoBackground(parent, style)) return 'same_color';
    return null;
  };

  const blockOf = (el) => {
    for (let a = el, depth = 0; a && depth < 16; a = composedParent(a), depth += 1) {
      const display = styleOf(a).display;
      if (!display.startsWith('inline') && display !== 'contents') return a;
    }
    return el;
  };

  const addVisible = (text, el) => {
    if (visibleLength >= MAX_VISIBLE) return;
    const block = blockOf(el);
    const glue = visibleParts.length === 0 ? '' : (block === lastBlock ? ' ' : '\n');
    lastBlock = block;
    visibleParts.push(glue + text);
    visibleLength += glue.length + text.length;
  };

  const visitText = (node) => {
    const text = normalize(nodeValueOf(node));
    if (!text) return;
    const parent = composedParent(node);
    if (!parent) return;
    const name = nameOf(parent);
    if (UNRENDERED_TEXT_PARENTS.has(name)) return;
    if (name === 'title' && namespaceOf(parent) === HTML_NS) return;
    const source = concealmentOf(node, parent);
    if (source) addConcealed(source, text, parent);
    else addVisible(text, parent);
  };

  const isPasswordField = (el) => {
    if ((attr(el, 'type') || '').toLowerCase() === 'password') return true;
    const security = styleOf(el).webkitTextSecurity;
    return Boolean(security) && security !== 'none';
  };

  const fieldLabel = (el) => attr(el, 'name') || attr(el, 'id') || '';

  const describeForm = (form) => {
    const fieldNames = [];
    let hasPassword = false;
    const fields = fieldsOf(form);
    for (let i = 0; i < fields.length; i += 1) {
      const field = fields[i];
      const name = nameOf(field);
      if (name !== 'input' && name !== 'select' && name !== 'textarea') continue;
      if (name === 'input' && NOT_FIELDS.has((attr(field, 'type') || '').toLowerCase())) continue;
      if (name === 'input' && isPasswordField(field)) hasPassword = true;
      const label = fieldLabel(field);
      if (label && fieldNames.length < MAX_FIELDS) fieldNames.push(label);
    }
    // Attribute, not property: form.action returns a child named "action".
    const rawAction = attr(form, 'action');
    let action = rawAction || '';
    try { action = new URL(rawAction === null ? '' : rawAction, baseUriOf(frameDocument)).href; } catch (e) {}
    return { action, method: (attr(form, 'method') || 'get').toLowerCase(),
      has_password: hasPassword, field_names: fieldNames };
  };

  const visitMeta = (el) => {
    if (attr(el, 'http-equiv') !== null) return;
    const name = (attr(el, 'name') || attr(el, 'property') || '').toLowerCase();
    if (TECHNICAL_META.has(name)) return;
    const content = attr(el, 'content');
    if (content) addConcealed('meta', content, el);
  };

  const visitElement = (el, pendingRoots) => {
    const name = nameOf(el);
    const shadow = openShadowOf(el);
    if (shadow) pendingRoots.push(shadow);
    if (name === 'meta') visitMeta(el);
    if (name === 'form') forms.push(describeForm(el));
    if (name === 'input' && isPasswordField(el) && !formOwnerOf(el)) orphanPasswordFields.push(el);
    const alt = attr(el, 'alt');
    if (alt) addConcealed('alt', alt, el);
    let ownText = null;
    for (const attribute of LABEL_ATTRIBUTES) {
      const value = attr(el, attribute);
      if (!value) continue;
      if (ownText === null) ownText = normalize(textContentOf(el));
      if (normalize(value) !== ownText) addConcealed('aria_label', value, el);
    }
  };

  const pendingRoots = [entryRoot];
  const mask = NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT | NodeFilter.SHOW_COMMENT;
  let visited = 0;
  let exhausted = false;
  while (pendingRoots.length && !exhausted) {
    const walker = createWalker(frameDocument, pendingRoots.pop(), mask);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      visited += 1;
      if (visited > MAX_NODES || performance.now() - started > MAX_MS) {
        exhausted = true;
        break;
      }
      const type = nodeTypeOf(node);
      if (type === 1) visitElement(node, pendingRoots);
      else if (type === 3) visitText(node);
      else if (type === 8) addConcealed('comment', nodeValueOf(node), composedParent(node));
    }
  }

  if (orphanPasswordFields.length) {
    const names = orphanPasswordFields.map(fieldLabel).filter(Boolean).slice(0, MAX_FIELDS);
    forms.push({ action: '', method: '', has_password: true, field_names: names });
  }
  return { visible: visibleParts.join('').slice(0, MAX_VISIBLE), concealed, forms };
}
"""


@dataclass(frozen=True)
class Config:
    target_url: str
    mode: str
    offline: bool
    deadline_s: float
    dwell_s: float
    work_root: Path


_log_lines_left = MAX_LOG_LINES


def log(message: str) -> None:
    """Diagnostics go to stderr; stdout carries only events. Capped: a page can trigger these."""
    global _log_lines_left
    if _log_lines_left <= 0:
        return
    _log_lines_left -= 1
    try:
        print(f"worker: {message}", file=sys.stderr, flush=True)
    except (OSError, ValueError):
        pass


def first_line(exc: BaseException) -> str:
    text = str(exc)
    return text.splitlines()[0] if text else type(exc).__name__


def _clean(value: Any, key: str = "") -> Any:
    if isinstance(value, str):
        cap = STRING_CAPS.get(key, DEFAULT_STRING_CAP)
        clipped = value if cap is None else value[:cap]
        # A lone surrogate survives JSON escaping but breaks UTF-8 encoding downstream.
        return clipped.encode("utf-8", "replace").decode("utf-8")
    if isinstance(value, dict):
        return {str(k): _clean(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clean(item, key) for item in value]
    return value


class EventWriter:
    """Writes one flushed ASCII JSON line per event.

    Unbuffered so evidence survives a kill, and ASCII so a page string can never
    split a line, whatever the reader treats as a line separator.
    """

    def __init__(self, fd: int = 1) -> None:
        self._fd = fd
        self.on_reader_gone: Callable[[], None] = lambda: None
        self._lock = threading.Lock()
        self._type_counts: Counter[str] = Counter()
        self._omitted: Counter[str] = Counter()
        self._total_events = 0
        self._total_bytes = 0
        self._finished = False
        # Reported in worker_finished so the host need not parse free text.
        self.tracking_shed = False
        self.deadline_reached = False

    def emit(self, event_type: str, data: dict[str, Any]) -> bool:
        with self._lock:
            if self._finished or not self._within_caps(event_type):
                return False
            return self._write_event(event_type, data)

    def finish(self, status: str, error: str | None) -> None:
        """Writes worker_finished once; anything later is dropped."""
        with self._lock:
            if self._finished:
                return
            self._finished = True
            data: dict[str, Any] = {"status": status, "error": error}
            if self._omitted:
                data["omitted"] = dict(self._omitted)
            if self.tracking_shed:
                data["tracking_shed"] = True
            if self.deadline_reached:
                data["deadline_reached"] = True
            self._write_event("worker_finished", data)

    def _within_caps(self, event_type: str) -> bool:
        cap = EVENT_TYPE_CAPS.get(event_type)
        over_type_cap = cap is not None and self._type_counts[event_type] >= cap
        over_total = self._total_events >= TOTAL_EVENTS_CAP or self._total_bytes >= TOTAL_BYTES_CAP
        if over_type_cap or (over_total and event_type not in ESSENTIAL_EVENTS):
            self._omitted[event_type] += 1
            return False
        return True

    def _write_event(self, event_type: str, data: dict[str, Any]) -> bool:
        event = {"type": event_type, "ts": time.time(), "data": _clean(data)}
        line = json.dumps(event, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"
        if len(line) > LINE_BYTES_CAP:
            self._omitted[event_type] += 1
            return False
        self._type_counts[event_type] += 1
        self._total_events += 1
        self._total_bytes += len(line)
        try:
            view = memoryview(line)
            while view:
                view = view[os.write(self._fd, view) :]
        except OSError:
            # Nobody can receive evidence any more. The caller holds the lock
            # that the exit path also takes, so exit from another thread.
            threading.Thread(target=self.on_reader_gone, daemon=True).start()
            return False
        return True


def _has_proc() -> bool:
    return Path("/proc/self/stat").exists()


def _ps(*columns: str) -> list[list[str]]:
    argv = ["ps", "-A"]
    for column in columns:
        argv += ["-o", f"{column}="]
    listing = subprocess.run(
        argv, capture_output=True, text=True, errors="replace", timeout=PS_TIMEOUT_S, check=False
    ).stdout
    return [row.split(None, len(columns) - 1) for row in listing.splitlines() if row.strip()]


def _parent_links() -> list[tuple[int, int]]:
    """Returns (pid, ppid) rows."""
    links: list[tuple[int, int]] = []
    if _has_proc():
        for entry in Path("/proc").iterdir():
            if entry.name.isdigit():
                try:
                    links.append((int(entry.name), int((entry / "stat").read_text().rsplit(")", 1)[1].split()[1])))
                except (OSError, ValueError, IndexError):
                    continue
        return links
    return [(int(row[0]), int(row[1])) for row in _ps("pid", "ppid") if len(row) == 2]


def _descendants(root: int) -> set[int]:
    children: dict[int, list[int]] = {}
    for pid, ppid in _parent_links():
        children.setdefault(ppid, []).append(pid)
    found: set[int] = set()
    stack = [root]
    while stack:
        for child in children.get(stack.pop(), []):
            if child not in found:
                found.add(child)
                stack.append(child)
    return found


def _pids_mentioning(marker: str) -> set[int]:
    if _has_proc():
        found: set[int] = set()
        for entry in Path("/proc").iterdir():
            if entry.name.isdigit():
                try:
                    if marker.encode() in (entry / "cmdline").read_bytes():
                        found.add(int(entry.name))
                except OSError:
                    continue
        return found
    return {int(row[0]) for row in _ps("pid", "command") if len(row) == 2 and marker in row[1]}


def kill_browser_processes(marker: str) -> None:
    """SIGKILLs every descendant, then anything whose command line carries marker.

    Playwright starts Chromium in its own session, so killing a process group
    misses it, and a frozen renderer would otherwise spin forever outside a
    container. The marker catches browsers already orphaned by a dead driver.
    Reading parent links comes first because it is cheap enough to survive a
    badly overloaded machine; reading command lines may not be.
    """
    me = os.getpid()
    for find in (lambda: _descendants(me), lambda: _pids_mentioning(marker)):
        try:
            doomed = find()
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            log(f"cannot list processes: {type(exc).__name__}")
            continue
        for pid in doomed - {me}:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass


class Terminator:
    """Single exit path, callable from any thread, that never waits on the event loop."""

    def __init__(self, writer: EventWriter, workdir: Path) -> None:
        self._writer = writer
        self._workdir = workdir
        self._once = threading.Lock()

    def mark_deadline_reached(self) -> None:
        self._writer.deadline_reached = True

    def exit(self, code: int, status: str, error: str | None) -> NoReturn:
        if not self._once.acquire(blocking=False):
            # Another thread is already exiting and will end the process.
            threading.Event().wait()
        # The write can block on a full pipe, so it must not hold up the exit.
        finisher = threading.Thread(target=self._writer.finish, args=(status, error), daemon=True)
        finisher.start()
        finisher.join(0.5)
        kill_browser_processes(str(self._workdir))
        remover = threading.Thread(
            target=shutil.rmtree, args=(self._workdir,), kwargs={"ignore_errors": True}, daemon=True
        )
        remover.start()
        remover.join(WORKDIR_REMOVAL_WAIT_S)
        os._exit(code)


@lru_cache(maxsize=None)
def _load_fixture_file(name: str) -> bytes:
    return (FIXTURES_DIR / name).read_bytes()


def _interstitial(head: str) -> bytes:
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        f"<title>Redirecting</title>{head}</head>"
        "<body><p>Redirecting to Larkspur Bank.</p>"
        "<footer>Link Detonator test fixture</footer></body></html>"
    ).encode()


def fixture_response(path: str) -> dict[str, Any]:
    """Builds route.fulfill arguments for a fixture path."""
    entry = FIXTURE_ROUTES.get(path)
    headers = {"Cache-Control": "no-store"}
    if entry is None:
        headers["Content-Type"] = "text/plain; charset=utf-8"
        return {"status": 404, "headers": headers, "body": b"not found\n"}
    if entry.attachment is not None:
        headers["Content-Type"] = "text/plain; charset=utf-8"
        headers["Content-Disposition"] = f'attachment; filename="{entry.attachment}"'
    else:
        headers["Content-Type"] = "text/html; charset=utf-8"
    if entry.meta_refresh_to is not None:
        body = _interstitial(f'<meta http-equiv="refresh" content="0;url={entry.meta_refresh_to}">')
    elif entry.script_redirect_to is not None:
        body = _interstitial(f'<script>location.replace("{entry.script_redirect_to}");</script>')
    else:
        assert entry.file is not None
        body = _load_fixture_file(entry.file)
    return {"status": 200, "headers": headers, "body": body}


def fixture_path(url: str) -> str | None:
    """Returns the path if url is on the fixture host, else None."""
    try:
        parts = urlsplit(url)
        return parts.path if parts.scheme == "http" and parts.hostname == FIXTURE_HOST else None
    except ValueError:
        return None


def url_scheme(url: str) -> str:
    try:
        return urlsplit(url).scheme.lower()
    except ValueError:
        return ""


def address_is_non_public(text: str) -> bool:
    """True for anything that is not a globally routable unicast address."""
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    return address.is_multicast or not address.is_global


def url_is_non_public(url: str) -> bool:
    """Judges a URL by its text alone. Chromium has already normalized the host."""
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return False
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return "." not in host or any(host == name or host.endswith(f".{name}") for name in LOCAL_NAME_SUFFIXES)
    return address_is_non_public(host)


def chromium_args(offline: bool) -> list[str]:
    features = ",".join((*PLAYWRIGHT_DISABLED_FEATURES, *LOCAL_NETWORK_GATE_FEATURES))
    args = ["--no-sandbox", "--disable-gpu", f"--disable-features={features}"]
    if offline:
        # context.route misses preconnects, WebRTC and the next hop of an HTTP
        # redirect. They die here, so a local run cannot reach the real network.
        args += [
            "--host-resolver-rules=MAP * ~NOTFOUND",
            "--proxy-server=http://127.0.0.1:9",
            "--proxy-bypass-list=<-loopback>",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        ]
    return args


def chromium_env(workdir: Path) -> dict[str, str]:
    """A minimal environment: nothing from the parent reaches a page-facing process."""
    home = workdir / "home"
    temp = workdir / "tmp"
    home.mkdir(exist_ok=True)
    temp.mkdir(exist_ok=True)
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "TMPDIR": str(temp),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "LANG": "C.UTF-8",
    }


def flatten_frame_ids(tree: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    stack = [tree]
    while stack:
        node = stack.pop()
        ids.append(node["frame"]["id"])
        stack.extend(reversed(node.get("childFrames", [])))
    return ids


def closed_shadow_roots(document: dict[str, Any], root_frame_id: str) -> dict[str, list[int]]:
    """Maps frame id to backend node ids of closed shadow roots found by CDP's DOM walk."""
    found: dict[str, list[int]] = {}
    stack: list[tuple[dict[str, Any], str]] = [(document, root_frame_id)]
    while stack:
        node, frame_id = stack.pop()
        for shadow in node.get("shadowRoots", []):
            if shadow.get("shadowRootType") == "closed":
                found.setdefault(frame_id, []).append(shadow["backendNodeId"])
            stack.append((shadow, frame_id))
        stack.extend((child, frame_id) for child in node.get("children", []))
        content = node.get("contentDocument")
        if content is not None:
            stack.append((content, node.get("frameId", frame_id)))
    return found


def merge_frame_layers(frames: list[dict[str, Any]]) -> tuple[str, list[dict[str, str]], list[dict[str, Any]]]:
    """Merges per-frame extraction results into visible text, concealed entries and forms."""
    visible_parts: list[str] = []
    concealed: list[dict[str, str]] = []
    forms: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    per_source: Counter[str] = Counter()
    for index, frame in enumerate(frames):
        if frame["visible"]:
            visible_parts.append(frame["visible"])
        forms.extend(frame["forms"])
        prefix = f"frame[{index}] " if index else ""
        for entry in frame["concealed"]:
            key = (entry["source"], entry["text"])
            if key in seen or per_source[entry["source"]] >= MAX_CONCEALED_PER_SOURCE:
                continue
            seen.add(key)
            per_source[entry["source"]] += 1
            concealed.append({"source": entry["source"], "text": entry["text"], "selector": prefix + entry["selector"]})
    return "\n".join(visible_parts), concealed, forms


def unwrap_extraction(response: dict[str, Any]) -> dict[str, Any]:
    value = response.get("result", {}).get("value")
    if response.get("exceptionDetails") or not isinstance(value, dict):
        raise PlaywrightError(f"extraction failed: {response.get('exceptionDetails', {}).get('text', 'no result')}")
    return value


@dataclass
class FrameWorld:
    """One frame's isolated world and what extraction has found in it so far."""

    session: CDPSession
    frame_id: str
    root_frame_id: str
    context_id: int
    layers: dict[str, Any]


MISSING: Any = object()


class Deadline:
    def __init__(self, total_s: float) -> None:
        self.total_s = total_s

    def remaining(self) -> float:
        return self.total_s - (time.monotonic() - STARTED_AT)

    def soft_remaining(self) -> float:
        """Time left for scanning, keeping back enough to tear down in order."""
        return self.remaining() - TEARDOWN_RESERVE_S


class Scan:
    def __init__(self, config: Config, writer: EventWriter, deadline: Deadline, workdir: Path) -> None:
        self.config = config
        self.out = writer
        self.deadline = deadline
        self.workdir = workdir
        self.playwright: Playwright | None = None
        self.context: BrowserContext | None = None
        self.page: Page | None = None
        self._stop = asyncio.Event()
        self._hung_operations = 0
        self._saw_unresponsive = False
        self._crashed = False
        self._closed_early = False
        self._navigation_error: str | None = None
        self._last_navigation_url: str | None = None
        self._pending: set[Request] = set()
        self._captured_url: str | None = None
        self._navigation_count = 0
        self._requests_seen = 0
        self._cdp_sessions: list[CDPSession] = []
        self._seen_forms: set[str] = set()
        self._last_layers: str | None = None
        self._screenshots_taken = 0
        self._peer_lookups: set[asyncio.Task[None]] = set()

    async def run(self) -> tuple[str, str | None]:
        await self._launch()
        reached_page = await self._navigate()
        if reached_page:
            await self._wait_for_load()
            await self._wait_until_url_settles()
            await self._observe()
        else:
            await self._screenshot("navigation_failed")
        self.flush_pending_requests()
        return self._outcome()

    async def close(self) -> None:
        if self.context is not None:
            await self._settle(self.context.close())
        if self.playwright is not None:
            await self._settle(self.playwright.stop(), timeout_s=1.0)

    def flush_pending_requests(self) -> None:
        """Reports requests with no answer yet.

        The firewall rejects blocked traffic, so those requests normally fail fast.
        Anything still open here (a silent drop upstream, a server that never
        answers) would otherwise leave no outcome in the evidence.
        """
        for request in list(self._pending):
            self._pending.discard(request)
            self.out.emit("request_failed", self._failure_data(request, PENDING_REQUEST_ERROR))

    def _outcome(self) -> tuple[str, str | None]:
        if self._crashed:
            return "partial", "page crashed"
        if self._closed_early:
            return "partial", "page closed before the scan ended"
        if self._navigation_error is not None:
            return "partial", self._navigation_error
        if self._saw_unresponsive:
            return "partial", "page unresponsive"
        return "ok", None

    async def _launch(self) -> None:
        self.playwright = await asyncio.wait_for(async_playwright().start(), START_TIMEOUT_S)
        offline = self.config.offline
        self.context = await asyncio.wait_for(
            self.playwright.chromium.launch_persistent_context(
                user_data_dir=str(self.workdir / "profile"),
                headless=True,
                args=chromium_args(offline),
                env=chromium_env(self.workdir),
                viewport=VIEWPORT,
                # Denied downloads are reported but never written to disk.
                accept_downloads=False,
                downloads_path=str(self.workdir / "downloads"),
                ignore_https_errors=True,
                # Service worker traffic would bypass request logging.
                service_workers="block",
                # Covers https pages only. For http pages, see LOCAL_NETWORK_GATE_FEATURES.
                permissions=["local-network-access"],
                timeout=LAUNCH_TIMEOUT_S * 1000,
            ),
            LAUNCH_TIMEOUT_S,
        )
        self.context.on("request", self._on_request)
        self.context.on("requestfailed", self._on_request_failed)
        self.context.on("response", self._on_response)
        self.context.on("dialog", self._on_dialog)
        if self.config.mode == "fixture":
            # On the VM only fixture URLs are intercepted: everything else simply
            # goes to the network, where the firewall does the real blocking.
            pattern = ALL_REQUESTS_PATTERN if offline else FIXTURE_ROUTE_PATTERN
            await self.context.route(pattern, self._route_fixture_mode)
        else:
            await self.context.route(ALL_REQUESTS_PATTERN, self._route_live_mode)
        if offline:
            await self.context.route_web_socket(ALL_REQUESTS_PATTERN, self._block_web_socket)
        pages = self.context.pages
        self.page = pages[0] if pages else await self.context.new_page()
        self.page.on("crash", self._on_crash)
        self.page.on("close", self._on_main_page_closed)
        self.page.on("framenavigated", self._on_frame_navigated)
        self.page.on("download", self._on_download)
        self.page.on("websocket", self._on_websocket)
        self.context.on("page", self._on_new_page)

    async def _navigate(self) -> bool:
        assert self.page is not None
        url = self.config.target_url
        budget_s = max(0.1, min(NAVIGATION_TIMEOUT_MS / 1000, self.deadline.soft_remaining()))
        try:
            await asyncio.wait_for(
                self.page.goto(url, wait_until="commit", timeout=budget_s * 1000), budget_s
            )
            return True
        except (asyncio.TimeoutError, PlaywrightTimeoutError):
            self._navigation_error = f"navigation timed out after {int(budget_s * 1000)} ms"
        except PlaywrightError as exc:
            message = first_line(exc)
            if "Download is starting" in message:
                return True
            self._navigation_error = message
        if self._last_navigation_url is None:
            self._emit_navigation(url, None, None)
        return False

    async def _wait_for_load(self, timeout_ms: int = LOAD_TIMEOUT_MS) -> None:
        # A slow subresource is not an unresponsive page, so a load timeout emits
        # nothing. If the renderer really is hung, the next screenshot reports it.
        assert self.page is not None
        budget_s = min(timeout_ms / 1000, self.deadline.soft_remaining())
        if budget_s <= 0:
            return
        try:
            await asyncio.wait_for(
                self.page.wait_for_load_state("load", timeout=budget_s * 1000), budget_s
            )
        except (asyncio.TimeoutError, PlaywrightError) as exc:
            log(f"load wait ended early: {type(exc).__name__}")

    async def _wait_until_url_settles(self) -> None:
        """Lets instant client-side redirects finish before the first capture.

        A screenshot that straddles a navigation stalls until its timeout, which
        would delay the evidence from the page the redirect lands on.
        """
        give_up_at = time.monotonic() + URL_SETTLE_LIMIT_S
        while time.monotonic() < give_up_at:
            seen = self._navigation_count
            await self._sleep(URL_QUIET_S)
            if self._stop.is_set() or self._navigation_count == seen:
                return
            await self._wait_for_load(POST_NAVIGATION_LOAD_TIMEOUT_MS)

    async def _observe(self) -> None:
        assert self.page is not None
        await self._capture("loaded")
        observed_from = time.monotonic()
        # A long load must not push the final capture past the deadline.
        usable_s = self.deadline.soft_remaining() - FINAL_CAPTURE_RESERVE_S
        end = observed_from + min(self.config.dwell_s, usable_s)
        next_screenshot = observed_from + SCREENSHOT_INTERVAL_S
        while await self._page_alive():
            remaining = end - time.monotonic()
            if remaining <= 0:
                break
            await self._sleep(min(URL_CHECK_INTERVAL_S, remaining))
            now = time.monotonic()
            if self._stop.is_set() or now >= end:
                break
            if self.page.url != self._captured_url:
                await self._wait_for_load(POST_NAVIGATION_LOAD_TIMEOUT_MS)
                await self._capture("navigated")
            elif now >= next_screenshot:
                await self._screenshot(f"t+{int(now - observed_from)}s")
                next_screenshot = now + SCREENSHOT_INTERVAL_S
        if not self._stop.is_set() and self._hung_operations < HUNG_OPERATIONS_TO_GIVE_UP:
            await self._capture("final")

    async def _capture(self, label: str) -> None:
        assert self.page is not None
        self._captured_url = self.page.url
        await self._screenshot(label)
        if await self._page_alive():
            await self._capture_layers()

    async def _page_alive(self) -> bool:
        """False once the page crashed, closed, or two operations in a row hung.

        After one hung operation an independent probe decides: a screenshot can
        stall on its own while the renderer is still answering.
        """
        if self._stop.is_set():
            return False
        if self._hung_operations == 1:
            assert self.page is not None
            await self._guarded("evaluate", self.page.evaluate("1"), PROBE_TIMEOUT_MS)
        return not self._stop.is_set() and self._hung_operations < HUNG_OPERATIONS_TO_GIVE_UP

    async def _sleep(self, seconds: float) -> None:
        try:
            await asyncio.wait_for(self._stop.wait(), seconds)
        except asyncio.TimeoutError:
            pass

    async def _guarded(self, operation: str, work: Coroutine[Any, Any, Any], timeout_ms: int) -> Any:
        """Runs one browser operation under its own timeout.

        Python's side times out independently because evaluate and CDP calls have
        no timeout of their own and never return while the renderer is blocked.
        """
        wanted_s = timeout_ms / 1000
        budget_s = min(wanted_s, self.deadline.soft_remaining())
        if budget_s <= 0.05:
            work.close()
            return MISSING
        navigations_before = self._navigation_count
        try:
            result = await asyncio.wait_for(work, budget_s)
        except (asyncio.TimeoutError, PlaywrightTimeoutError):
            # A budget cut short by the deadline, or an operation that straddled a
            # navigation, proves nothing about whether the page is responsive.
            if budget_s >= wanted_s and self._navigation_count == navigations_before:
                self._hung_operations += 1
                self._saw_unresponsive = True
                self.out.emit("page_unresponsive", {"operation": operation, "timeout_ms": timeout_ms})
            return MISSING
        except PlaywrightError as exc:
            log(f"{operation} failed: {first_line(exc)}")
            return MISSING
        self._hung_operations = 0
        return result

    async def _settle(self, work: Coroutine[Any, Any, Any], timeout_s: float = SETTLE_TIMEOUT_S) -> None:
        try:
            await asyncio.wait_for(work, timeout_s)
        except (asyncio.TimeoutError, PlaywrightError) as exc:
            log(f"settle ended early: {type(exc).__name__}")

    async def _screenshot(self, label: str) -> None:
        if self.page is None or self._screenshots_taken >= EVENT_TYPE_CAPS["screenshot"]:
            return
        jpeg = await self._guarded(
            "screenshot",
            self.page.screenshot(
                type="jpeg", quality=JPEG_QUALITY, full_page=False, timeout=SCREENSHOT_TIMEOUT_MS
            ),
            SCREENSHOT_TIMEOUT_MS,
        )
        if jpeg is MISSING:
            return
        self._screenshots_taken += 1
        self.out.emit(
            "screenshot",
            {"label": label, "mime": "image/jpeg", "b64": base64.b64encode(jpeg).decode("ascii")},
        )

    async def _capture_layers(self) -> None:
        worlds: list[FrameWorld] = []
        await self._guarded("text_layers", self._extract_frames(worlds), EXTRACT_TIMEOUT_MS)
        if worlds and self._hung_operations == 0:
            await self._extract_closed_roots_quietly(worlds)
        await self._release_cdp_sessions()
        # Keep what finished before a hang: a late frame must not cost earlier evidence.
        if not worlds:
            return
        visible_text, concealed, forms = merge_frame_layers([world.layers for world in worlds])
        self._emit_forms(forms)
        data = {"visible_text": visible_text, "concealed": concealed}
        fingerprint = json.dumps(data, sort_keys=True)
        if fingerprint != self._last_layers:
            self._last_layers = fingerprint
            self.out.emit("text_layers", data)

    async def _extract_frames(self, worlds: list[FrameWorld]) -> None:
        assert self.context is not None and self.page is not None
        self._cdp_sessions.append(await self.context.new_cdp_session(self.page))
        for frame in self.page.frames[1 : MAX_FRAMES + 1]:
            try:
                self._cdp_sessions.append(await self.context.new_cdp_session(frame))
            except PlaywrightError:
                # Same-process frame: it is already in the parent session's frame tree.
                continue
        for session in list(self._cdp_sessions):
            await self._extract_session_frames(session, worlds)

    async def _extract_session_frames(self, session: CDPSession, worlds: list[FrameWorld]) -> None:
        tree = await session.send("Page.getFrameTree")
        frame_ids = flatten_frame_ids(tree["frameTree"])
        for frame_id in frame_ids:
            if len(worlds) >= MAX_FRAMES:
                return
            try:
                worlds.append(await self._extract_frame(session, frame_id, frame_ids[0]))
            except PlaywrightError as exc:
                # An out-of-process child is unreachable from its parent's session.
                log(f"frame skipped: {first_line(exc)}")

    async def _extract_frame(self, session: CDPSession, frame_id: str, root_frame_id: str) -> FrameWorld:
        created = await session.send(
            "Page.createIsolatedWorld",
            {"frameId": frame_id, "worldName": "link-detonator-evidence", "grantUniveralAccess": True},
        )
        context_id = created["executionContextId"]
        evaluated = await session.send(
            "Runtime.evaluate",
            {
                "expression": f"({EXTRACT_FUNCTION})(document)",
                "contextId": context_id,
                "returnByValue": True,
            },
        )
        return FrameWorld(session, frame_id, root_frame_id, context_id, unwrap_extraction(evaluated))

    async def _extract_closed_roots_quietly(self, worlds: list[FrameWorld]) -> None:
        # The DOM dump's cost grows with the page, so running out of time here says
        # nothing about the renderer and must not be reported as a hung page.
        budget_s = min(CLOSED_ROOTS_TIMEOUT_MS / 1000, self.deadline.soft_remaining())
        if budget_s <= 0:
            return
        try:
            await asyncio.wait_for(self._extract_closed_roots(worlds), budget_s)
        except (asyncio.TimeoutError, PlaywrightError) as exc:
            log(f"closed shadow roots incomplete: {type(exc).__name__}")

    async def _extract_closed_roots(self, worlds: list[FrameWorld]) -> None:
        """Script cannot reach a closed shadow root, but CDP's own DOM walk can."""
        roots_by_session: dict[CDPSession, dict[str, list[int]]] = {}
        for world in worlds:
            if world.session not in roots_by_session:
                document = await world.session.send("DOM.getDocument", {"depth": -1, "pierce": True})
                roots_by_session[world.session] = closed_shadow_roots(document["root"], world.root_frame_id)
            for backend_node_id in roots_by_session[world.session].get(world.frame_id, [])[:MAX_CLOSED_SHADOW_ROOTS]:
                inner = await self._extract_closed_root(world, backend_node_id)
                layers = world.layers
                layers["visible"] = "\n".join(part for part in (layers["visible"], inner["visible"]) if part)
                layers["concealed"].extend(inner["concealed"])
                layers["forms"].extend(inner["forms"])

    async def _extract_closed_root(self, world: FrameWorld, backend_node_id: int) -> dict[str, Any]:
        resolved = await world.session.send(
            "DOM.resolveNode", {"backendNodeId": backend_node_id, "executionContextId": world.context_id}
        )
        called = await world.session.send(
            "Runtime.callFunctionOn",
            {
                "functionDeclaration": f"function () {{ return ({EXTRACT_FUNCTION})(this); }}",
                "objectId": resolved["object"]["objectId"],
                "returnByValue": True,
            },
        )
        return unwrap_extraction(called)

    async def _release_cdp_sessions(self) -> None:
        # A session with the DOM domain on keeps relaying a busy page's mutations.
        sessions, self._cdp_sessions = self._cdp_sessions, []
        if self._hung_operations:
            return
        for session in sessions:
            await self._settle(session.detach(), timeout_s=0.5)

    def _emit_forms(self, forms: list[dict[str, Any]]) -> None:
        for form in forms:
            names = form["field_names"][:MAX_FIELD_NAMES]
            data = {
                "action": form["action"],
                "method": form["method"],
                "has_password": bool(form["has_password"]),
                "field_names": names,
            }
            key = json.dumps(data, sort_keys=True)
            if key not in self._seen_forms:
                self._seen_forms.add(key)
                self.out.emit("form", data)

    def _failure_data(self, request: Request, error: str) -> dict[str, Any]:
        return {
            "url": request.url,
            "error": error,
            "resource_type": request.resource_type,
            "blocked_locally": self.config.offline and error.startswith(LOCAL_BLOCK_ERROR_PREFIXES),
        }

    def _is_main_navigation(self, request: Request) -> bool:
        try:
            return (
                self.page is not None
                and request.is_navigation_request()
                and request.frame == self.page.main_frame
            )
        except PlaywrightError:
            # Service worker requests, and navigations that outran their frame.
            return False

    def _emit_navigation(self, url: str, status: int | None, redirected_from: str | None) -> None:
        if status is None and url == self._last_navigation_url:
            return
        self._last_navigation_url = url
        self.out.emit("navigation", {"url": url, "status": status, "redirected_from": redirected_from})

    def _on_request(self, request: Request) -> None:
        self._requests_seen += 1
        if self._requests_seen >= REQUEST_TRACKING_LIMIT:
            self._shed_request_tracking()
            return
        if len(self._pending) < MAX_PENDING_TRACKED:
            self._pending.add(request)
        self.out.emit(
            "request",
            {"url": request.url, "method": request.method, "resource_type": request.resource_type},
        )

    def _shed_request_tracking(self) -> None:
        """Stops paying per-request costs during a flood.

        The cap stopped these reaching the host long ago, and handling them was
        delaying the screenshots and text that matter more. Unsubscribing also
        stops the driver sending them. The omitted count becomes a lower bound.
        """
        assert self.context is not None
        self.out.tracking_shed = True
        self.context.remove_listener("request", self._on_request)
        self.context.remove_listener("requestfailed", self._on_request_failed)
        self.context.remove_listener("response", self._on_response)
        self._pending.clear()

    def _navigation_origin(self, request: Request) -> str | None:
        """The URL this navigation came from.

        The worker never clicks or types, so any main-frame navigation after the
        first was driven by the page: a client-side redirect, reported the same
        way as an HTTP one.
        """
        previous = request.redirected_from
        return previous.url if previous else self._last_navigation_url

    def _on_request_failed(self, request: Request) -> None:
        self._pending.discard(request)
        self.out.emit("request_failed", self._failure_data(request, request.failure or "unknown"))
        if self._is_main_navigation(request):
            self._emit_navigation(request.url, None, self._navigation_origin(request))

    def _on_response(self, response: Response) -> None:
        request = response.request
        self._pending.discard(request)
        if self._is_main_navigation(request):
            self._navigation_count += 1
            self._emit_navigation(response.url, response.status, self._navigation_origin(request))
        self._check_response_destination(response)

    def _check_response_destination(self, response: Response) -> None:
        """Reports any answer from a non-public address, whatever kind of request it was.

        A page reaches a metadata service with fetch or an image far more often than by
        navigating to it. A later ERR_ABORTED or CORS failure does not undo the answer.
        """
        url = response.url
        if fixture_path(url) is not None or url_scheme(url) in NON_NETWORK_SCHEMES:
            return
        if url_is_non_public(url):
            self._emit_response(response, None)
            return
        # A public-looking name can resolve anywhere, so ask where the browser connected.
        lookup = asyncio.create_task(self._check_peer_address(response))
        self._peer_lookups.add(lookup)
        lookup.add_done_callback(self._peer_lookups.discard)

    async def _check_peer_address(self, response: Response) -> None:
        try:
            server = await asyncio.wait_for(response.server_addr(), PEER_ADDRESS_TIMEOUT_S)
        except (asyncio.TimeoutError, PlaywrightError):
            return
        peer = server.get("ipAddress") if server else None
        if peer and address_is_non_public(peer):
            self._emit_response(response, peer)

    def _emit_response(self, response: Response, peer_ip: str | None) -> None:
        self.out.emit("response", {"url": response.url, "status": response.status, "peer_ip": peer_ip})

    def _on_frame_navigated(self, frame: Frame) -> None:
        # Same-document navigations (pushState, hash) send no request.
        if self.page is None or frame != self.page.main_frame:
            return
        self._navigation_count += 1
        url = frame.url
        if url and url != "about:blank" and not url.startswith("chrome-error:"):
            self._emit_navigation(url, None, None)

    def _on_crash(self, _page: Page) -> None:
        self._crashed = True
        self.out.emit("page_crash", {})
        self._stop.set()

    def _on_main_page_closed(self, _page: Page) -> None:
        self._closed_early = True
        self._stop.set()

    async def _on_dialog(self, dialog: Dialog) -> None:
        self.out.emit("dialog", {"dialog_type": dialog.type, "message": dialog.message})
        await self._settle(dialog.dismiss())

    async def _on_download(self, download: Download) -> None:
        self.out.emit(
            "download_attempt",
            {"url": download.url, "suggested_filename": download.suggested_filename},
        )
        await self._settle(download.cancel())
        await self._settle(download.delete())

    def _on_websocket(self, socket: WebSocket) -> None:
        self.out.emit("request", {"url": socket.url, "method": "GET", "resource_type": "websocket"})
        socket.on(
            "socketerror",
            lambda error: self.out.emit(
                "request_failed",
                {
                    "url": socket.url,
                    "error": str(error),
                    "resource_type": "websocket",
                    "blocked_locally": False,
                },
            ),
        )

    async def _on_new_page(self, popup: Page) -> None:
        popup.on("download", self._on_download)
        popup.on("websocket", self._on_websocket)
        if popup.url in ("", "about:blank"):
            # A scripted popup is created blank and navigates a moment later.
            try:
                await popup.wait_for_event("framenavigated", timeout=POPUP_URL_WAIT_MS)
            except PlaywrightError:
                pass
        self.out.emit("popup", {"url": popup.url})
        await self._settle(popup.close(run_before_unload=False))

    async def _route_fixture_mode(self, route: Route) -> None:
        request = route.request
        path = fixture_path(request.url)
        try:
            if path is not None:
                await route.fulfill(**fixture_response(path))
            elif self.config.offline and url_scheme(request.url) not in NON_NETWORK_SCHEMES:
                await route.abort("blockedbyclient")
            else:
                # Data and blob URLs have no network to be blocked from.
                await route.continue_()
        except PlaywrightError as exc:
            log(f"route failed: {type(exc).__name__}")

    async def _route_live_mode(self, route: Route) -> None:
        request = route.request
        try:
            if request.method in LIVE_ALLOWED_METHODS or url_scheme(request.url) in NON_NETWORK_SCHEMES:
                await route.continue_()
            else:
                await route.abort("blockedbyclient")
        except PlaywrightError as exc:
            log(f"route failed: {type(exc).__name__}")

    async def _block_web_socket(self, socket: WebSocketRoute) -> None:
        self.out.emit("request", {"url": socket.url, "method": "GET", "resource_type": "websocket"})
        self.out.emit(
            "request_failed",
            {
                "url": socket.url,
                "error": "websocket aborted by --offline",
                "resource_type": "websocket",
                "blocked_locally": True,
            },
        )
        await self._settle(socket.close())


async def execute(config: Config, writer: EventWriter, deadline: Deadline, workdir: Path, stopper: Terminator) -> NoReturn:
    """Runs the scan and always leaves through the Terminator."""
    scan = Scan(config, writer, deadline, workdir)
    code = 0
    try:
        status, error = await asyncio.wait_for(scan.run(), max(0.1, deadline.soft_remaining()))
    except asyncio.TimeoutError:
        writer.deadline_reached = True
        scan.flush_pending_requests()
        status, error = "partial", "internal deadline reached"
    except Exception as exc:  # Anything unexpected must still report and exit cleanly.
        log(f"scan failed: {exc!r}")
        status, error, code = "error", first_line(exc), 1
    # Report first, so a teardown that hangs on a hostile page costs no evidence.
    writer.finish(status, error)
    try:
        await scan.close()
    except Exception as exc:  # The Terminator kills whatever is left either way.
        log(f"teardown failed: {exc!r}")
    stopper.exit(code, status, error)


def parse_args(argv: list[str] | None = None) -> Config:
    parser = argparse.ArgumentParser(description="Link Detonator sandbox worker")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--url", help="http(s) URL to open")
    target.add_argument("--fixture", choices=FIXTURE_NAMES, help="built-in fixture to open")
    parser.add_argument("--offline", action="store_true", help="abort every non-fixture request (fixture mode only)")
    parser.add_argument("--deadline", type=float, default=DEFAULT_DEADLINE_S, help="exit within this many seconds")
    parser.add_argument("--dwell", type=float, default=DEFAULT_DWELL_S, help="seconds to observe after load")
    parser.add_argument("--work-root", type=Path, default=Path("/tmp"), help="parent directory for the throwaway profile")
    args = parser.parse_args(argv)
    if args.offline and args.fixture is None:
        parser.error("--offline requires --fixture")
    if not MIN_DEADLINE_S <= args.deadline <= MAX_DEADLINE_S:
        parser.error(f"--deadline must be between {MIN_DEADLINE_S:g} and {MAX_DEADLINE_S:g}")
    if args.dwell < 0:
        parser.error("--dwell must not be negative")
    if args.url is not None and url_scheme(args.url) not in ("http", "https"):
        parser.error("--url must be http or https")
    return Config(
        target_url=args.url if args.url is not None else f"{FIXTURE_ORIGIN}/{args.fixture}",
        mode="live" if args.url is not None else "fixture",
        offline=args.offline,
        deadline_s=args.deadline,
        dwell_s=args.dwell,
        work_root=args.work_root,
    )


def install_exit_triggers(stopper: Terminator, deadline: Deadline) -> None:
    """Exit paths that keep working if the event loop is stuck."""

    def on_deadline() -> None:
        stopper.mark_deadline_reached()
        stopper.exit(0, "partial", "internal deadline reached")

    watchdog = threading.Timer(max(0.1, deadline.remaining() - WATCHDOG_MARGIN_S), on_deadline)
    watchdog.daemon = True
    watchdog.start()

    def on_signal(_number: int, _frame: Any) -> None:
        # On its own thread: the handler may have interrupted a write holding the lock.
        threading.Thread(
            target=stopper.exit, args=(0, "partial", "terminated by signal"), daemon=True
        ).start()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)


def main(argv: list[str] | None = None) -> int:
    config = parse_args(argv)
    writer = EventWriter()
    writer.emit(
        "worker_started",
        {"url": config.target_url, "mode": config.mode, "offline": config.offline},
    )
    try:
        workdir = Path(tempfile.mkdtemp(prefix="ld-", dir=config.work_root))
    except OSError as exc:
        writer.finish("error", f"cannot create work directory: {exc.strerror or exc}")
        return 1
    deadline = Deadline(config.deadline_s)
    stopper = Terminator(writer, workdir)
    writer.on_reader_gone = lambda: stopper.exit(1, "error", "stdout closed")
    install_exit_triggers(stopper, deadline)
    try:
        asyncio.run(execute(config, writer, deadline, workdir, stopper))
    finally:
        # Reached only if the event loop itself failed.
        stopper.exit(1, "error", "worker failed")


if __name__ == "__main__":
    sys.exit(main())
