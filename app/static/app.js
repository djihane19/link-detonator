"use strict";

/*
  Link Detonator UI. No framework, no build step.

  Security rule for this whole file: every string that came from a scanned page
  or from the worker is attacker-controlled. Such strings only ever reach the DOM
  through text nodes (see scannedText). This file must never use HTML-parsing DOM
  APIs, and never turns a scanned string into a link, image source or style.
*/

const SVG_NS = "http://www.w3.org/2000/svg";

const TERMINAL_STATES = new Set(["ok", "partial", "error", "interrupted", "finished"]);
const STATE_LABELS = {
  loading: "Loading",
  queued: "Queued",
  running: "Live",
  ok: "Finished",
  partial: "Partial",
  error: "Error",
  interrupted: "Interrupted",
  finished: "Finished",
};

const STATUS_LABELS = {
  contained: "Contained",
  observed: "Observed",
  not_observed: "Not observed",
  clear: "Clear",
  failed: "Failed",
  not_applicable: "N/A",
};

const SPOKE_NAMES = {
  downloads: "DOWNLOADS",
  private_network: "PRIVATE NET",
  freeze: "FREEZE",
  memory: "MEMORY",
  concealed_text: "CONCEALED",
  secrets: "SECRETS",
  limits: "LIMITS",
  destroyed: "DESTROYED",
};

const CONCEALED_SOURCES = {
  hidden_css: "Hidden by CSS",
  offscreen: "Pushed off-screen",
  tiny_text: "Tiny text",
  same_color: "Same colour as background",
  comment: "HTML comment",
  meta: "Meta tag",
  aria_label: "ARIA label",
  alt: "Image alt text",
};

const IMAGE_URL_SHAPE = /^\/api\/scans\/[A-Za-z0-9_-]+\/screenshots\/[0-9]+\.jpg$/;
const REPORT_URL_SHAPE = /^\/r\/[A-Za-z0-9_-]+$/;

/* Bidi overrides, zero-width characters, tag characters and C0/C1 controls can make a string read differently than it is. */
const INVISIBLE_CLASS = "[\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F-\\u009F\\u{FFF9}-\\u{FFFB}\\p{Default_Ignorable_Code_Point}]";
const INVISIBLE_RUN = new RegExp(`(${INVISIBLE_CLASS})\\1*`, "gu");
const INVISIBLE_ANY = new RegExp(INVISIBLE_CLASS, "gu");
/* A page can send hundreds of thousands of invisible characters. Markers are DOM nodes, so
   they are capped per string and per report, or a page could freeze its own evidence away. */
const MAX_MARKERS_PER_STRING = 32;
const MAX_MARKERS_PER_REPORT = 4000;
const POLL_INTERVAL_MS = 3000;
let markerBudget = MAX_MARKERS_PER_REPORT;

const MAX_WAVES = 3;
const WAVE_GAP_MS = 170;
const MAX_SEQ_LINKS = 5;
const MAX_DOTS = 14;

const prefersCalm = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const byId = (id) => document.getElementById(id);

/* ------------------------------------------------------------------ DOM helpers */

function assemble(node, attrs, kids) {
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "on") {
      for (const [type, listener] of Object.entries(value)) node.addEventListener(type, listener);
    } else {
      node.setAttribute(key, value === true ? "" : String(value));
    }
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    node.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return node;
}

const h = (tag, attrs, ...kids) => assemble(document.createElement(tag), attrs, kids);
const svg = (tag, attrs, ...kids) => assemble(document.createElementNS(SVG_NS, tag), attrs, kids);

function codePointLabel(char) {
  return `U+${char.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}`;
}

/* Builds text nodes for a hostile string, revealing invisible characters as visible markers. */
function scannedText(value) {
  const fragment = document.createDocumentFragment();
  const text = value === null || value === undefined ? "" : String(value);
  let cursor = 0;
  let markers = 0;
  for (const match of text.matchAll(INVISIBLE_RUN)) {
    if (markers >= MAX_MARKERS_PER_STRING || markerBudget <= 0) break;
    markers += 1;
    markerBudget -= 1;
    fragment.append(document.createTextNode(text.slice(cursor, match.index)));
    fragment.append(invisibleMarker(codePointLabel(match[1]), [...match[0]].length));
    cursor = match.index + match[0].length;
  }
  const rest = text.slice(cursor);
  const visibleRest = rest.replace(INVISIBLE_ANY, "");
  fragment.append(document.createTextNode(visibleRest));
  const hidden = [...rest].length - [...visibleRest].length;
  if (hidden > 0) fragment.append(invisibleMarker("invisible characters not shown one by one", hidden));
  return fragment;
}

function invisibleMarker(label, count) {
  const text = count > 1 ? `${label} x${count}` : label;
  return h("span", { class: "ctrl", title: "Invisible character in the scanned string" }, text);
}

function clear(node) {
  node.replaceChildren();
}

async function fetchJson(url) {
  const response = await fetch(url, { headers: { Accept: "application/json" } });
  if (!response.ok) {
    const error = new Error(`Request failed with status ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return response.json();
}

/* ------------------------------------------------------------------ Home page */

function initHome() {
  const form = byId("arm");
  const urlField = byId("target-url");
  const errorBox = byId("arm-error");

  if (document.body.dataset.runner === "dev") {
    urlField.disabled = true;
    urlField.placeholder = "Live URLs are refused by the dev runner";
    byId("access-code").disabled = true;
    byId("arm-submit").disabled = true;
    byId("arm-hint").textContent = "The dev runner only plays offline test charges. Use one below.";
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const url = urlField.value.trim();
    if (!url) {
      showError(errorBox, "Paste a URL first.");
      urlField.focus();
      return;
    }
    const accessCode = byId("access-code").value.trim();
    startScan(accessCode ? { url, access_code: accessCode } : { url }, errorBox);
  });

  byId("run-gauntlet").addEventListener("click", () => {
    startScan({ fixture: "hostile-gauntlet" }, byId("rack-error"));
  });

  loadFixtures();
}

async function loadFixtures() {
  const rack = byId("fixture-rack");
  const errorBox = byId("rack-error");
  try {
    const catalog = await fetchJson("/api/fixtures");
    const fixtures = catalog.fixtures || [];
    if (!fixtures.some((fixture) => fixture.name === "hostile-gauntlet")) {
      byId("gauntlet-slot").hidden = true;
    }
    rack.replaceChildren(
      ...fixtures.filter((fixture) => fixture.name !== "hostile-gauntlet").map(fixtureCard),
    );
  } catch {
    showError(errorBox, "Could not load the test charges. Reload to try again.");
  }
}

function fixtureCard(fixture) {
  const kind = fixture.name === "benign" ? "control" : "hostile";
  return h("li", null,
    h("button", {
      class: "rack-item",
      type: "button",
      "data-kind": kind,
      on: { click: () => startScan({ fixture: fixture.name }, byId("rack-error")) },
    },
      h("span", { class: "rack-name" }, fixture.title || fixture.name),
      h("span", { class: "rack-copy" }, fixture.description || ""),
    ),
  );
}

function showError(box, message) {
  box.textContent = message;
  box.hidden = false;
}

function launchControls() {
  return document.querySelectorAll(".detonate, .rack-item");
}

function setLaunching(isLaunching) {
  for (const control of launchControls()) {
    if (document.body.dataset.runner === "dev" && control.id === "arm-submit") continue;
    control.disabled = isLaunching;
  }
}

async function startScan(payload, errorBox) {
  for (const box of [byId("arm-error"), byId("rack-error")]) box.hidden = true;
  setLaunching(true);
  try {
    const response = await fetch("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(payload),
    });
    if (response.status === 202) {
      const created = await response.json();
      if (REPORT_URL_SHAPE.test(created.report_url)) {
        window.location.assign(created.report_url);
        return;
      }
      showError(errorBox, "The server returned an unexpected report address.");
    } else {
      showError(errorBox, await refusalMessage(response));
    }
  } catch {
    showError(errorBox, "Could not reach the server. Check your connection and try again.");
  }
  setLaunching(false);
}

async function refusalMessage(response) {
  if (response.status === 429) {
    const wait = Number(response.headers.get("Retry-After"));
    const when = Number.isFinite(wait) && wait > 0 ? `in ${wait} seconds` : "shortly";
    return `Scan limit reached for now. Try again ${when}.`;
  }
  try {
    const body = await response.json();
    if (typeof body.detail === "string") return body.detail;
  } catch {
    /* Fall through to the generic message. */
  }
  return response.status === 503 ? "The server is busy. Try again in a minute." : "That request was refused.";
}

/* ------------------------------------------------------------------ Report: state */

const report = {
  id: null,
  status: "loading",
  startTs: null,
  endTs: null,
  lastSeq: 0,
  eventCount: 0,
  rows: new Map(),
  stream: null,
  chamber: null,
  frames: [],
  hops: [],
  lightboxIndex: -1,
  requestGroup: null,
  tickTimer: null,
  lastWaveAt: 0,
  activeWaves: 0,
  hasRenderedRows: false,
  sandboxSeen: false,
};

function initReport() {
  report.id = window.location.pathname.split("/").filter(Boolean).pop() || "";
  report.chamber = createChamber(byId("chamber"));
  wireLightbox();
  wireCopyLink();
  loadReport();
}

async function loadReport() {
  try {
    const snapshot = await fetchJson(`/api/scans/${encodeURIComponent(report.id)}`);
    applySnapshot(snapshot);
    if (!TERMINAL_STATES.has(snapshot.status)) openStream();
  } catch (error) {
    renderLoadFailure(error);
  }
}

function renderLoadFailure(error) {
  const missing = error.status === 404;
  setState("error", missing ? "Not found" : "Unavailable");
  byId("target-text").textContent = missing
    ? "No scan with this address exists. It may have passed its retention period."
    : "The report could not be loaded. Reload to try again.";
}

function applySnapshot(snapshot) {
  applyRunner(snapshot.runner);
  renderTarget(snapshot.target);
  report.startTs = report.startTs ?? snapshot.created_at ?? null;
  setState(snapshot.status);
  /* Rows first: however heavy a page made its events, the summary must already be on screen. */
  renderRows(snapshot.blast_radius || [], false);
  for (const event of snapshot.events || []) applyEvent(event, false);
  renderVerdict(snapshot.verdict);
  updateReadout();
  setPhase();
}

function applyRunner(runner) {
  if (runner === "dev") document.body.dataset.runner = "dev";
  /* The wall is drawn closed only once the host has reported a sandbox. */
  report.chamber.setWalled(report.sandboxSeen && document.body.dataset.runner !== "dev");
}

function renderTarget(target) {
  if (!target) return;
  const kind = byId("target-kind");
  const text = byId("target-text");
  clear(text);
  kind.textContent = target.kind === "fixture" ? "Test charge" : "Target URL";
  text.append(scannedText(target.value || ""));
}

function setState(status, labelOverride) {
  report.status = status;
  const node = byId("scan-state");
  node.dataset.state = status;
  node.textContent = labelOverride || STATE_LABELS[status] || status;
  document.title = `${node.textContent}: Link Detonator report`;
  setPhase();
  syncTicker();
}

function setPhase() {
  const phase = report.status === "running" ? "live" : report.eventCount > 0 ? "done" : "idle";
  byId("chamber").dataset.phase = phase;
}

function syncTicker() {
  if (report.status === "running" && !report.tickTimer) {
    report.tickTimer = window.setInterval(updateReadout, 1000);
  } else if (report.status !== "running" && report.tickTimer) {
    window.clearInterval(report.tickTimer);
    report.tickTimer = null;
  }
}

function formatClock(seconds) {
  const whole = Math.max(0, Math.floor(seconds));
  const minutes = Math.floor(whole / 60);
  return `${String(minutes).padStart(2, "0")}:${String(whole % 60).padStart(2, "0")}`;
}

function updateReadout() {
  byId("scan-count").textContent = String(report.eventCount);
  report.chamber.setCount(report.eventCount);
  if (report.startTs === null) return;
  const end = report.status === "running" ? Date.now() / 1000 : (report.endTs ?? report.startTs);
  byId("scan-elapsed").textContent = formatClock(end - report.startTs);
}

/* ------------------------------------------------------------------ Report: live stream */

function openStream() {
  const stream = new EventSource(`/api/scans/${encodeURIComponent(report.id)}/events`);
  report.stream = stream;
  const note = byId("stream-note");

  stream.onopen = () => {
    note.hidden = true;
  };
  stream.onerror = () => {
    /* Closed for good. That can be a busy server, so it says nothing about the scan itself. */
    if (stream.readyState === EventSource.CLOSED) {
      closeStream();
      pollUntilFinal();
      return;
    }
    note.textContent = "Connection dropped. Reconnecting and resuming from the last event.";
    note.hidden = false;
  };
  stream.onmessage = (message) => {
    const event = parseJson(message.data);
    if (event) applyEvent(event, true);
  };
  stream.addEventListener("blast_radius", (message) => {
    const payload = parseJson(message.data);
    if (payload) renderRows(payload.rows || [], true);
  });
}

function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function closeStream() {
  if (report.stream) {
    report.stream.close();
    report.stream = null;
  }
  byId("stream-note").hidden = true;
}

/* Final sync, so the page ends on exactly what the server stored. */
async function finishLive() {
  closeStream();
  try {
    applySnapshot(await fetchJson(`/api/scans/${encodeURIComponent(report.id)}`));
  } catch {
    /* The stream already delivered the evidence, so a failed sync loses nothing. */
  }
  announce(`Scan finished: ${STATE_LABELS[report.status] || report.status}.`);
}

/* The fallback when no event stream is available. Announces only what the server reports. */
async function pollUntilFinal() {
  const note = byId("stream-note");
  note.textContent = "Live updates are unavailable, so this page is checking for new evidence every few seconds.";
  note.hidden = false;
  try {
    applySnapshot(await fetchJson(`/api/scans/${encodeURIComponent(report.id)}`));
  } catch (error) {
    if (error.status === 404) {
      note.hidden = true;
      renderLoadFailure(error);
      return;
    }
  }
  if (TERMINAL_STATES.has(report.status)) {
    note.hidden = true;
    announce(`Scan finished: ${STATE_LABELS[report.status] || report.status}.`);
    return;
  }
  window.setTimeout(pollUntilFinal, POLL_INTERVAL_MS);
}

function announce(message) {
  byId("live-announcer").textContent = message;
}

/* ------------------------------------------------------------------ Report: events */

function applyEvent(event, live) {
  if (!event || typeof event.seq !== "number" || event.seq <= report.lastSeq) return;
  report.lastSeq = event.seq;
  report.eventCount += 1;
  report.startTs = report.startTs ?? event.ts;
  report.endTs = event.ts;

  if (report.status === "queued" || report.status === "loading") setState("running");

  routeEvent(event, live);
  appendTimeline(event, live);
  if (live) {
    fireWave();
    updateReadout();
  }
  if (event.type === "scan_finished") {
    setState(event.data && event.data.status ? event.data.status : "finished");
    if (live) finishLive();
  }
}

function routeEvent(event, live) {
  const data = event.data || {};
  if (event.type === "screenshot") addFrame(event, live);
  if (event.type === "navigation") addHop(data);
  if (event.type === "text_layers") addTextLayers(event);
  if (event.type === "verdict") renderVerdict(data);
  if (event.type === "sandbox_created" && event.source === "host") {
    report.sandboxSeen = true;
    applyRunner(null);
  }
}

/* ------------------------------------------------------------------ Report: timeline */

function plural(count, word) {
  return `${count} ${word}${count === 1 ? "" : "s"}`;
}

/* `lines` are attacker-controlled strings. `title` is built only from our own wording. */
const EVENT_TEXT = {
  worker_started: (d) => ({ title: "Browser started", lines: [`${d.mode || "unknown"} mode${d.offline ? ", offline" : ""}`, d.url] }),
  navigation: (d) => ({ title: `Navigated${d.status ? ` (${Number(d.status)})` : ""}`, lines: [d.url] }),
  screenshot: (d) => ({ title: "Frame captured", lines: [d.label] }),
  request: (d) => ({ title: "Request", lines: [`${d.method || ""} ${d.resource_type || ""}`.trim(), d.url] }),
  response: (d) => ({
    title: `Answer from a non-public address${d.status ? ` (${Number(d.status)})` : ""}`,
    tone: "bad",
    lines: [d.url, d.peer_ip ? `Connected to ${d.peer_ip}` : null],
  }),
  request_failed: (d) => ({
    title: d.blocked_locally ? "Request aborted locally" : "Request failed",
    tone: "warn",
    lines: [d.url, d.error, d.blocked_locally ? "Aborted by the worker's offline switch. This is not a firewall block." : null],
  }),
  download_attempt: (d) => ({ title: "Download attempted", tone: "warn", lines: [d.suggested_filename, d.url, "The file is never kept or opened."] }),
  dialog: (d) => ({ title: "Dialog auto-dismissed", tone: "warn", lines: [d.dialog_type, d.message] }),
  popup: (d) => ({ title: "Popup recorded and closed", tone: "warn", lines: [d.url] }),
  form: (d) => ({
    title: d.has_password ? "Form with a password field" : "Form found",
    tone: d.has_password ? "warn" : undefined,
    lines: [`${d.method || "GET"} ${d.action || ""}`.trim(), (d.field_names || []).join(", "), "Never filled or submitted."],
  }),
  text_layers: (d) => ({ title: `Text layers: ${plural((d.concealed || []).length, "concealed item")}`, tone: (d.concealed || []).length ? "warn" : undefined, lines: [] }),
  page_unresponsive: (d) => ({ title: "Page stopped responding", tone: "warn", lines: [`${d.operation || "operation"} exceeded ${Number(d.timeout_ms) || 0} ms`] }),
  page_crash: () => ({ title: "Page crashed", tone: "warn", lines: [] }),
  worker_finished: (d) => ({ title: `Worker finished: ${d.status || "unknown"}`, lines: [d.error] }),
  sandbox_created: (d) => ({ title: "Sandbox created", lines: [d.name, d.image, d.runtime ? `runtime: ${d.runtime}` : null] }),
  secret_audit: (d) => ({ title: d.ok ? "Secret audit passed" : "Secret audit failed", tone: d.ok ? "good" : "bad", lines: [`${Number(d.checked_count) || 0} values checked`] }),
  deadline_killed: (d) => ({ title: d.kill_confirmed === false ? "Deadline reached: kill not confirmed" : "Deadline reached: sandbox killed", tone: d.kill_confirmed === false ? "bad" : "warn", lines: [`after ${Number(d.deadline_s) || 0} s`] }),
  output_limit_killed: (d) => ({ title: d.kill_confirmed === false ? "Output limit hit: kill not confirmed" : "Output limit hit: sandbox killed", tone: d.kill_confirmed === false ? "bad" : "warn", lines: [d.reason] }),
  output_dropped: (d) => ({ title: `Dropped ${plural(Number(d.count) || 0, "invalid line")} of worker output`, tone: "warn", lines: [] }),
  sandbox_exit: (d) => ({ title: `Sandbox exited with code ${d.exit_code ?? "unknown"}`, tone: d.oom_killed ? "warn" : undefined, lines: [d.oom_killed ? "Killed by the memory limit." : null] }),
  sandbox_removed: (d) => ({ title: d.verified ? "Sandbox removal verified" : "Sandbox removal NOT verified", tone: d.verified ? "good" : "bad", lines: [] }),
  scan_error: (d) => ({ title: "Scan error", tone: "bad", lines: [d.message] }),
  scan_finished: (d) => ({ title: `Scan finished: ${d.status || "unknown"}`, lines: [] }),
  verdict: (d) => ({ title: `Verdict: ${d.status || "unknown"}`, lines: [] }),
};

function describeEvent(event) {
  const describe = EVENT_TEXT[event.type];
  if (describe) return describe(event.data || {});
  return { title: event.type, lines: [] };
}

function timeLabel(ts) {
  if (report.startTs === null || typeof ts !== "number") return "";
  const offset = Math.max(0, ts - report.startTs);
  const minutes = Math.floor(offset / 60);
  const seconds = (offset - minutes * 60).toFixed(1).padStart(4, "0");
  return `+${String(minutes).padStart(2, "0")}:${seconds}`;
}

function appendTimeline(event, live) {
  const list = byId("timeline");
  if (event.type === "request") {
    appendRequest(list, event, live);
    return;
  }
  report.requestGroup = null;
  const text = describeEvent(event);
  list.append(timelineItem(event, live, text.tone, [
    h("div", { class: "tl-title" }, text.title),
    ...text.lines.filter((line) => line !== null && line !== undefined && line !== "")
      .map((line) => h("div", { class: "tl-line" }, scannedText(line))),
  ]));
  keepPinned(list, live);
}

function timelineItem(event, live, tone, body) {
  return h("li", {
    class: `tl${live ? " is-new" : ""}`,
    id: `ev-${event.seq}`,
    tabindex: "-1",
    "data-source": event.source === "host" ? "host" : "worker",
    "data-tone": tone,
  },
    h("span", { class: "tl-time" }, timeLabel(event.ts)),
    h("span", { class: "tl-mark", title: event.source === "host" ? "Host fact" : "Worker report" }),
    h("div", { class: "tl-body" }, body),
  );
}

/* Consecutive requests fold into one line, or a noisy page would bury everything else. */
function appendRequest(list, event, live) {
  if (!report.requestGroup) {
    const summary = h("summary");
    const items = h("ol", { class: "tl-group-items" });
    const details = h("details", { class: "tl-group" }, summary, items);
    list.append(timelineItem(event, live, undefined, [details]));
    report.requestGroup = { summary, items, count: 0 };
  }
  const group = report.requestGroup;
  group.count += 1;
  group.summary.textContent = plural(group.count, "network request");
  const data = event.data || {};
  group.items.append(h("li", { class: "tl-subitem", id: group.count === 1 ? null : `ev-${event.seq}`, tabindex: "-1" },
    scannedText(`${data.method || ""} ${data.resource_type || ""} ${data.url || ""}`.trim())));
  keepPinned(list, live);
}

function keepPinned(list, live) {
  if (live && list.scrollHeight - list.scrollTop - list.clientHeight < 140) {
    list.scrollTop = list.scrollHeight;
  }
}

function jumpToEvidence(seq) {
  const target = byId(`ev-${seq}`);
  if (!target) return;
  const fold = target.closest("details");
  if (fold) fold.open = true;
  target.scrollIntoView({ behavior: prefersCalm() ? "auto" : "smooth", block: "center" });
  target.focus({ preventScroll: true });
  target.classList.remove("is-target");
  void target.offsetWidth;
  target.classList.add("is-target");
}

/* ------------------------------------------------------------------ Report: filmstrip and lightbox */

function addFrame(event, live) {
  const data = event.data || {};
  const safeUrl = typeof data.image_url === "string" && IMAGE_URL_SHAPE.test(data.image_url) ? data.image_url : null;
  const index = report.frames.length;
  report.frames.push({ url: safeUrl, label: String(data.label || ""), seq: event.seq });

  byId("filmstrip").append(frameItem(index, safeUrl, data.label, event.seq, live));
  byId("film-count").textContent = plural(report.frames.length, "frame");
  if (live) {
    const strip = byId("filmstrip");
    strip.scrollLeft = strip.scrollWidth;
  }
}

function frameItem(index, url, label, seq, live) {
  const caption = h("span", { class: "frame-caption" }, `#${seq} `, scannedText(label));
  if (!url) {
    return h("li", { class: "frame" },
      h("div", { class: "frame-rejected" }, "Frame rejected: not a valid JPEG"),
      caption);
  }
  return h("li", { class: `frame${live ? " is-new" : ""}` },
    h("button", {
      class: "frame-button",
      type: "button",
      "aria-label": `Open frame ${index + 1} full size`,
      on: { click: () => openLightbox(index) },
    }, h("img", { src: url, alt: `Screenshot ${index + 1}`, loading: "lazy", width: "250", height: "156" })),
    caption);
}

function wireLightbox() {
  const dialog = byId("lightbox");
  byId("lightbox-close").addEventListener("click", () => dialog.close());
  byId("lightbox-prev").addEventListener("click", () => stepLightbox(-1));
  byId("lightbox-next").addEventListener("click", () => stepLightbox(1));
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close();
  });
  dialog.addEventListener("keydown", (event) => {
    if (event.key === "ArrowLeft") stepLightbox(-1);
    if (event.key === "ArrowRight") stepLightbox(1);
  });
  dialog.addEventListener("close", restoreFrameFocus);
}

function viewableFrames() {
  return report.frames.map((frame, index) => ({ ...frame, index })).filter((frame) => frame.url);
}

function openLightbox(index) {
  report.lightboxIndex = index;
  showLightboxFrame();
  const dialog = byId("lightbox");
  if (!dialog.open) dialog.showModal();
}

function stepLightbox(direction) {
  const frames = viewableFrames();
  if (frames.length === 0) return;
  const position = frames.findIndex((frame) => frame.index === report.lightboxIndex);
  const next = (position + direction + frames.length) % frames.length;
  report.lightboxIndex = frames[next].index;
  showLightboxFrame();
}

function showLightboxFrame() {
  const frame = report.frames[report.lightboxIndex];
  if (!frame || !frame.url) return;
  const image = byId("lightbox-image");
  image.src = frame.url;
  image.alt = `Screenshot ${report.lightboxIndex + 1}, full size`;
  const caption = byId("lightbox-caption");
  clear(caption);
  caption.append(`Frame ${report.lightboxIndex + 1} of ${report.frames.length}, event #${frame.seq}: `, scannedText(frame.label));
}

function restoreFrameFocus() {
  const buttons = byId("filmstrip").querySelectorAll(".frame");
  const item = buttons[report.lightboxIndex];
  const button = item ? item.querySelector("button") : null;
  if (button) button.focus();
}

function wireCopyLink() {
  const button = byId("copy-link");
  const original = button.textContent;
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(window.location.href);
      button.textContent = "Copied";
    } catch {
      button.textContent = "Copy failed: use the address bar";
    }
    window.setTimeout(() => {
      button.textContent = original;
    }, 2200);
  });
}

/* ------------------------------------------------------------------ Report: redirect chain */

function addHop(data) {
  const hops = report.hops;
  const previous = hops[hops.length - 1];
  if (data.redirected_from && (!previous || previous.url !== data.redirected_from)) {
    hops.push({ url: data.redirected_from, status: null });
  }
  hops.push({ url: data.url, status: data.status });
  renderChain();
}

function renderChain() {
  const hops = report.hops;
  byId("chain-count").textContent = plural(hops.length, "hop");
  byId("redirect-chain").replaceChildren(...hops.map((hop, index) => {
    const landed = index === hops.length - 1;
    return h("li", { class: `hop${landed ? " is-landed" : ""}` },
      h("span", { class: "hop-status" }, `${landed ? "LANDED" : "HOP"} ${hop.status === null || hop.status === undefined ? "" : Number(hop.status)}`.trim()),
      h("span", { class: "hop-url", dir: "ltr" }, scannedText(hop.url)),
    );
  }));
}

/* ------------------------------------------------------------------ Report: text layers */

function addTextLayers(event) {
  const data = event.data || {};
  const concealed = Array.isArray(data.concealed) ? data.concealed : [];
  const capture = byId("text-layers").children.length + 1;
  byId("text-layers").append(h("div", { class: "layer-pair" },
    h("p", { class: "layer-page" }, `Capture ${capture}, event #${event.seq}`),
    h("div", { class: "layer-column" },
      h("h3", { class: "layer-heading" }, "What a person sees"),
      h("div", { class: "layer-visible", tabindex: "0", "aria-label": "Visible page text" },
        data.visible_text ? scannedText(data.visible_text) : "No visible text recorded."),
    ),
    h("div", { class: "layer-column" },
      h("h3", { class: "layer-heading layer-heading-hidden" }, `What the page hid (${concealed.length})`),
      concealed.length
        ? h("ol", { class: "concealed-list", tabindex: "0", "aria-label": "Concealed page text" }, concealed.map(concealedItem))
        : h("p", { class: "empty-note" }, "Nothing concealed was found in the places checked."),
    ),
  ));
}

function concealedItem(item) {
  const source = CONCEALED_SOURCES[item.source] || "Other";
  return h("li", { class: "concealed-item" },
    h("span", { class: "concealed-source" }, source),
    item.selector ? h("span", { class: "concealed-selector" }, scannedText(item.selector)) : null,
    h("div", { class: "concealed-text" }, scannedText(item.text)),
  );
}

/* ------------------------------------------------------------------ Report: Blast Radius rows */

function renderRows(rows, live) {
  if (!rows.length) return;
  report.chamber.layout(rows);
  const list = byId("blast-rows");
  const firstPaint = !report.hasRenderedRows;
  report.hasRenderedRows = true;
  const changes = [];

  rows.forEach((row, index) => {
    const known = report.rows.get(row.id);
    if (!known) {
      const element = createRow(row, index);
      report.rows.set(row.id, { element, status: null, evidence: "" });
      list.append(element);
      if (firstPaint && !prefersCalm()) {
        element.classList.add("is-entering");
        element.style.setProperty("--enter-delay", `${index * 55}ms`);
      }
    }
    if (updateRow(row, live)) changes.push(row);
    report.chamber.setSpoke(row);
  });

  summariseRows(rows);
  if (live && changes.length) {
    announce(changes.map((row) => `${row.label}: ${STATUS_LABELS[row.status] || row.status}`).join(". "));
  }
}

function createRow(row, index) {
  const number = String(index + 1).padStart(2, "0");
  const element = h("li", {
    class: "row",
    "data-row": row.id,
    on: {
      mouseenter: () => setHot(row.id, true),
      mouseleave: () => setHot(row.id, false),
      focusin: () => setHot(row.id, true),
      focusout: () => setHot(row.id, false),
    },
  },
    h("span", { class: "row-number", "aria-hidden": "true" }, number),
    h("div", { class: "row-main" },
      h("h3", { class: "row-label" }, row.label),
      h("p", { class: "row-detail" }),
      h("div", { class: "row-evidence" }),
    ),
    h("span", { class: "stamp" }),
  );
  return element;
}

function updateRow(row, live) {
  const known = report.rows.get(row.id);
  const element = known.element;
  const evidence = (row.evidence_seqs || []).join(",");
  const statusChanged = known.status !== row.status;

  element.dataset.status = row.status;
  const stamp = element.querySelector(".stamp");
  stamp.dataset.status = row.status;
  stamp.textContent = STATUS_LABELS[row.status] || row.status;

  const detail = element.querySelector(".row-detail");
  clear(detail);
  detail.append(scannedText(row.detail || ""));

  if (evidence !== known.evidence) renderEvidenceLinks(element, row.evidence_seqs || [], row.source);

  known.status = row.status;
  known.evidence = evidence;

  if (live && statusChanged && !prefersCalm()) replayStamp(element);
  return statusChanged;
}

function replayStamp(element) {
  element.classList.remove("is-new", "is-entering");
  void element.offsetWidth;
  element.classList.add("is-new");
}

function renderEvidenceLinks(element, seqs, source) {
  const holder = element.querySelector(".row-evidence");
  clear(holder);
  if (!seqs.length) return;
  holder.append(source ? `Evidence (${source}) ` : "Evidence ");
  for (const seq of seqs.slice(0, MAX_SEQ_LINKS)) {
    holder.append(h("button", {
      class: "seq-link",
      type: "button",
      "aria-label": `Jump to event ${seq} in the timeline`,
      on: { click: () => jumpToEvidence(seq) },
    }, `#${seq}`));
  }
  if (seqs.length > MAX_SEQ_LINKS) holder.append(` +${seqs.length - MAX_SEQ_LINKS} more`);
}

function setHot(rowId, isHot) {
  const known = report.rows.get(rowId);
  if (known) known.element.classList.toggle("is-hot", isHot);
  report.chamber.setHot(rowId, isHot);
}

function summariseRows(rows) {
  const counts = new Map();
  for (const row of rows) {
    const label = STATUS_LABELS[row.status] || row.status;
    counts.set(label, (counts.get(label) || 0) + 1);
  }
  const parts = [...counts].map(([label, count]) => `${count} ${label.toLowerCase()}`);
  byId("chamber-summary").textContent = `Blast Radius plan with ${rows.length} checks: ${parts.join(", ")}. The list that follows has the same information.`;
}

/* ------------------------------------------------------------------ Report: the chamber plan */

const PLAN = { cx: 360, cy: 360, core: 42, wall: 232, inner: 96, middle: 164, breach: 252, label: 256 };

function polar(radius, angle) {
  return [PLAN.cx + radius * Math.cos(angle), PLAN.cy + radius * Math.sin(angle)];
}

function linePath(fromRadius, toRadius, angle) {
  const [x1, y1] = polar(fromRadius, angle);
  const [x2, y2] = polar(toRadius, angle);
  return `M${x1.toFixed(1)} ${y1.toFixed(1)}L${x2.toFixed(1)} ${y2.toFixed(1)}`;
}

function arcPath(radius, from, to) {
  const [x1, y1] = polar(radius, from);
  const [x2, y2] = polar(radius, to);
  return `M${x1.toFixed(1)} ${y1.toFixed(1)}A${radius} ${radius} 0 0 1 ${x2.toFixed(1)} ${y2.toFixed(1)}`;
}

/* How far a spoke reaches is a drawing of its status, not a measurement. */
function spokeReach(status) {
  if (status === "contained") return PLAN.wall - 8;
  if (status === "failed") return PLAN.breach;
  if (status === "observed") return PLAN.middle;
  if (status === "clear") return PLAN.wall - 8;
  if (status === "not_applicable") return PLAN.middle;
  return PLAN.wall - 20;
}

function createChamber(root) {
  const spokes = new Map();
  const wavesLayer = svg("g", { "aria-hidden": "true" });
  const wallGroup = svg("g", { class: "wall-group" });
  const spokesLayer = svg("g");
  const coreCount = svg("text", { class: "core-count", x: PLAN.cx, y: PLAN.cy + 1 }, "0");

  root.append(
    svg("circle", { class: "plan-ring", cx: PLAN.cx, cy: PLAN.cy, r: PLAN.inner }),
    svg("circle", { class: "plan-ring", cx: PLAN.cx, cy: PLAN.cy, r: PLAN.middle }),
    wallGroup,
    spokesLayer,
    wavesLayer,
    svg("circle", { class: "core-disc", cx: PLAN.cx, cy: PLAN.cy, r: PLAN.core }),
    coreCount,
  );

  function layout(rows) {
    if (spokes.size === rows.length && rows.every((row) => spokes.has(row.id))) return;
    spokes.clear();
    clear(wallGroup);
    clear(spokesLayer);
    rows.forEach((row, index) => {
      const spoke = createSpoke(row, index, rows.length);
      spokes.set(row.id, spoke);
      spokesLayer.append(spoke.group);
      wallGroup.append(spoke.wallHolder);
    });
  }

  function setSpoke(row) {
    const spoke = spokes.get(row.id);
    if (spoke) drawSpoke(spoke, row);
  }

  function setHot(rowId, isHot) {
    const spoke = spokes.get(rowId);
    if (spoke) spoke.group.classList.toggle("is-hot", isHot);
  }

  return {
    layout,
    setSpoke,
    setHot,
    setCount: (count) => {
      coreCount.textContent = String(count);
    },
    setWalled: (isWalled) => {
      root.dataset.walled = isWalled ? "yes" : "no";
    },
    wavesLayer,
    wallGroup,
  };
}

function createSpoke(row, index, total) {
  const step = (2 * Math.PI) / total;
  const angle = -Math.PI / 2 + step * (index + 0.5);
  const from = angle - step / 2 + 0.035;
  const to = angle + step / 2 - 0.035;

  const line = svg("path", { class: "spoke-line" });
  const arrest = svg("path", { class: "spoke-arrest" });
  const dots = svg("g");
  const wall = svg("path", { class: "wall-segment", d: arcPath(PLAN.wall, from, to) });
  const wallHolder = svg("g", { class: "spoke" }, wall);
  const label = createSpokeLabel(row, index, angle);
  const hit = svg("path", { class: "spoke-hit", d: sectorPath(from, to) });
  const group = svg("g", { class: "spoke", "data-row": row.id }, line, arrest, dots, label, hit);

  hit.addEventListener("click", () => {
    const known = report.rows.get(row.id);
    if (!known) return;
    known.element.scrollIntoView({ behavior: prefersCalm() ? "auto" : "smooth", block: "nearest" });
    replayStamp(known.element);
  });
  hit.addEventListener("mouseenter", () => setHot(row.id, true));
  hit.addEventListener("mouseleave", () => setHot(row.id, false));

  return { group, line, arrest, dots, wall, wallHolder, angle, from, to };
}

function sectorPath(from, to) {
  const [x1, y1] = polar(PLAN.core, from);
  const [x2, y2] = polar(PLAN.label + 40, from);
  const [x3, y3] = polar(PLAN.label + 40, to);
  const [x4, y4] = polar(PLAN.core, to);
  const radius = PLAN.label + 40;
  return `M${x1.toFixed(1)} ${y1.toFixed(1)}L${x2.toFixed(1)} ${y2.toFixed(1)}A${radius} ${radius} 0 0 1 ${x3.toFixed(1)} ${y3.toFixed(1)}L${x4.toFixed(1)} ${y4.toFixed(1)}Z`;
}

function createSpokeLabel(row, index, angle) {
  const [x, y] = polar(PLAN.label, angle);
  const anchor = Math.cos(angle) >= 0 ? "start" : "end";
  const name = SPOKE_NAMES[row.id] || String(row.label || row.id).toUpperCase();
  return svg("g", { "aria-hidden": "true" },
    svg("text", { class: "spoke-number", x: x.toFixed(1), y: (y + 2).toFixed(1), "text-anchor": anchor }, String(index + 1).padStart(2, "0")),
    svg("text", { class: "spoke-name", x: x.toFixed(1), y: (y + 24).toFixed(1), "text-anchor": anchor }, name),
  );
}

function drawSpoke(spoke, row) {
  const status = row.status;
  spoke.group.dataset.status = status;
  spoke.wallHolder.dataset.status = status;

  const reach = spokeReach(status);
  spoke.line.setAttribute("d", linePath(PLAN.core + 4, reach, spoke.angle));

  /* A breach is a real gap in the drawn wall, centred on the spoke. */
  if (status === "failed") {
    const gap = 0.09;
    spoke.wall.setAttribute("d", `${arcPath(PLAN.wall, spoke.from, spoke.angle - gap)}${arcPath(PLAN.wall, spoke.angle + gap, spoke.to)}`);
  } else {
    spoke.wall.setAttribute("d", arcPath(PLAN.wall, spoke.from, spoke.to));
  }

  const showArrest = status === "contained" || status === "observed";
  const span = status === "contained" ? 0.11 : 0.07;
  spoke.arrest.setAttribute("d", showArrest ? arcPath(reach + 2, spoke.angle - span, spoke.angle + span) : "");

  drawDots(spoke, row, reach);
}

/* One dot per piece of evidence, capped. Positions are deterministic so a reload draws the same plan. */
function drawDots(spoke, row, reach) {
  clear(spoke.dots);
  const count = Math.min((row.evidence_seqs || []).length, MAX_DOTS);
  for (let i = 0; i < count; i += 1) {
    const along = PLAN.core + 18 + ((reach - PLAN.core - 24) * (i + 1)) / (count + 1);
    const swing = (i % 2 === 0 ? 1 : -1) * (0.035 + ((i * 7) % 5) * 0.012);
    const [x, y] = polar(along, spoke.angle + swing);
    spoke.dots.append(svg("rect", {
      class: "spoke-dot",
      x: (x - 4).toFixed(1),
      y: (y - 4).toFixed(1),
      width: 8,
      height: 8,
      transform: `rotate(${(i * 37) % 90} ${x.toFixed(1)} ${y.toFixed(1)})`,
    }));
  }
}

/* A shockwave for each live event. Throttled, because a hostile page can send thousands. */
function fireWave() {
  if (prefersCalm() || !report.chamber) return;
  const now = performance.now();
  if (report.activeWaves >= MAX_WAVES || now - report.lastWaveAt < WAVE_GAP_MS) return;
  report.lastWaveAt = now;
  report.activeWaves += 1;

  const wave = svg("circle", { class: "wave", cx: PLAN.cx, cy: PLAN.cy, r: PLAN.wall });
  wave.addEventListener("animationend", () => {
    wave.remove();
    report.activeWaves -= 1;
    jolt(report.chamber.wallGroup);
  }, { once: true });
  report.chamber.wavesLayer.append(wave);
}

function jolt(wallGroup) {
  if (byId("chamber").dataset.walled === "no") return;
  wallGroup.classList.remove("hit");
  void wallGroup.getBoundingClientRect();
  wallGroup.classList.add("hit");
}

/* ------------------------------------------------------------------ Report: verdict */

function renderVerdict(verdict) {
  const card = byId("verdict-card");
  const title = byId("verdict-title");
  const body = byId("verdict-body");
  if (!verdict || verdict.status === "pending" || !verdict.status) {
    card.dataset.status = "pending";
    title.textContent = "Verdict engine not connected";
    body.textContent = "No verdict has been issued, and none is implied. Everything on this page is raw evidence, not a judgement.";
    return;
  }
  card.dataset.status = String(verdict.status);
  title.textContent = String(verdict.status);
  clear(body);
  body.append(scannedText(verdict.summary || ""));
}

/* ------------------------------------------------------------------ Boot */

document.addEventListener("DOMContentLoaded", () => {
  const page = document.body.dataset.page;
  if (page === "home") initHome();
  if (page === "report") initReport();
});
