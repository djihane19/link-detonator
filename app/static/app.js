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
/* ---- Investigation progress: every stage comes from a recorded event, never a timer. */

const pipeline = { sandbox: false, worker: false, evidence: false, removed: null, error: false };

function notePipeline(event) {
  const host = event.source === "host";
  if (event.type === "verdict" && host) report.verdictSeq = event.seq;
  if (event.type === "sandbox_created" && host) pipeline.sandbox = true;
  if (event.type === "worker_started") pipeline.worker = true;
  if (["worker_finished", "sandbox_exit", "deadline_killed", "output_limit_killed"].includes(event.type)) pipeline.evidence = true;
  if (event.type === "sandbox_removed" && host) pipeline.removed = event.data?.verified === true;
  if (event.type === "scan_error" && host) pipeline.error = true;
  renderPipeline();
}

function stageStates() {
  const finished = FINAL_STATES.has(report.status);
  const dev = document.body.dataset.runner === "dev";
  const verdict = report.verdict;
  const states = {};
  if (pipeline.sandbox) states.sandbox = ["done", "Container started"];
  else if (dev && (pipeline.worker || finished)) states.sandbox = ["skipped", "Dev run: no sandbox"];
  else if (finished) states.sandbox = ["failed", "No sandbox was recorded"];
  else states.sandbox = [report.status === "running" ? "active" : "waiting", report.status === "running" ? "Starting" : "Queued"];

  if (pipeline.evidence) states.evidence = ["done", "Page recorded"];
  else if (finished) states.evidence = [pipeline.error ? "failed" : "skipped", "Recording incomplete"];
  else if (pipeline.sandbox || pipeline.worker) states.evidence = ["active", "Recording the page"];
  else states.evidence = ["waiting", "Waiting"];

  if (pipeline.removed === true) states.containment = ["done", "Container destroyed and checked"];
  else if (pipeline.removed === false) states.containment = ["failed", "Removal not verified"];
  else if (dev && (pipeline.evidence || finished)) states.containment = ["skipped", "Dev run: nothing to verify"];
  else if (finished) states.containment = ["failed", "No removal was recorded"];
  else if (pipeline.evidence) states.containment = ["active", "Checking"];
  else states.containment = ["waiting", "Waiting"];

  const complete = verdict && verdict.status === "complete";
  if (complete) states.ai = ["done", "Verdict ready"];
  else if (verdict && verdict.status === "unavailable") states.ai = ["failed", "Model unavailable"];
  else if (finished) states.ai = ["skipped", "No AI verdict"];
  else if (pipeline.removed !== null || (dev && pipeline.evidence)) states.ai = ["active", "Analysing evidence"];
  else states.ai = ["waiting", "Waiting"];
  return states;
}

function renderPipeline() {
  const list = byId("pipeline");
  if (!list) return;
  const states = stageStates();
  for (const item of list.children) {
    const [state, detail] = states[item.dataset.stage] || ["waiting", "Waiting"];
    item.dataset.state = state;
    item.querySelector(".stage-detail").textContent = detail;
  }
}

const PLAIN_VERDICT = {
  malicious: "Malicious indicators observed. Do not open this link.",
  suspicious: "Suspicious indicators observed. Treat this link with caution.",
  benign: "No malicious indicators observed in this scan. That is not a guarantee.",
  inconclusive: "Inconclusive. The evidence was not enough for a judgement.",
};

const FINAL_STATES = new Set(["ok", "partial", "error", "interrupted", "finished"]);

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
      ...fixtures.filter((fixture) => fixture.name !== "hostile-gauntlet" && !fixture.name.startsWith("lab-")).map(fixtureCard),
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
  for (const box of [byId("arm-error"), byId("rack-error"), byId("qr-error"), byId("email-error")]) if (box) box.hidden = true;
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
  if (response.status === 413) return "The image is too large to upload. Try a smaller photo or a screenshot.";
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
  report.target = target;
  const kind = byId("target-kind");
  const text = byId("target-text");
  clear(text);
  kind.textContent = target.kind === "fixture" ? "Test charge" : "Target URL";
  text.append(scannedText(target.value || ""));
}

let receiptLoaded = false;

/* The receipt exists once a scan is final. Its digest is shown here so a downloaded copy
   can be compared with it; the chain is tamper-evident, not a signature. */
async function offerReceipt() {
  if (receiptLoaded || !report.id || !byId("receipt-link")) return;
  receiptLoaded = true;
  const url = `/api/scans/${encodeURIComponent(report.id)}/receipt.json`;
  try {
    const response = await fetch(url, { headers: { Accept: "application/json" } });
    if (!response.ok) {
      receiptLoaded = false;
      return;
    }
    const receipt = await response.json();
    if (!/^[0-9a-f]{64}$/.test(receipt.final_digest || "")) return;
    const link = byId("receipt-link");
    link.href = url;
    link.hidden = false;
    const digest = byId("receipt-digest");
    digest.textContent = `Evidence receipt digest (SHA-256): ${receipt.final_digest}. This server computes it from its own records, so it is not an independent copy. Save it outside this site now: a saved copy exposes any later change to this record. Not a signature.`;
    digest.hidden = false;
  } catch {
    receiptLoaded = false;
  }
}

function setState(status, labelOverride) {
  report.status = status;
  if (FINAL_STATES.has(status)) offerReceipt();
  if (FINAL_STATES.has(status) && byId("verdict-card")) renderVerdict(report.verdict);
  renderPipeline();
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
  notePipeline(event);
  if (event.type === "screenshot") addFrame(event, live);
  if (event.type === "navigation") addHop(data);
  if (event.type === "text_layers") addTextLayers(event);
  if (event.type === "verdict") renderVerdict(data);
  if (event.type === "qr_source" && event.source === "host") renderQrSource(data);
  if (event.type === "email_source" && event.source === "host") renderEmailSource(data);
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
  qr_source: (d) => ({ title: "Target decoded from a QR image", lines: [String(d.payload_display || "")] }),
  email_source: (d) => ({ title: d.found_in === "qr" ? "Target from a QR code in an email" : "Target from a link in an email", lines: [String(d.link_display || "")] }),
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
  // Stays highlighted until the next jump, so it is clear which event was meant.
  for (const previous of document.querySelectorAll(".tl.is-current, .tl-subitem.is-current")) previous.classList.remove("is-current");
  target.classList.add("is-current");
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

/* Only after a benign verdict, only for a real http(s) link, and only on a deliberate click. */
function safeHttpUrl(value) {
  try {
    const url = new URL(String(value));
    return url.protocol === "https:" || url.protocol === "http:" ? url.href : null;
  } catch {
    return null;
  }
}

function offerOpenLink(verdict) {
  const box = byId("open-link");
  if (!box) return;
  const url = report.target?.kind === "url" ? safeHttpUrl(report.target.value) : null;
  const sandboxed = verdict.verification?.environment === "docker_sandbox";
  box.hidden = !(url && sandboxed && verdict.status === "complete" && verdict.classification === "benign");
  const button = byId("open-link-button");
  button.onclick = () => {
    if (!url || box.hidden) return;
    if (window.confirm(`Open this link in a new tab?\n\n${url}\n\nThe scan found no threats, but that is not a guarantee.`)) {
      window.open(url, "_blank", "noopener,noreferrer");
    }
  };
}

/* ---- AI manipulation analysis: recorded checks only, attempts kept apart from successes. */

const PATTERN_LABELS = {
  override_instructions: "Tried to override the AI's instructions",
  reveal_prompt: "Asked the AI to reveal its instructions",
  steer_verdict: "Tried to steer the verdict (\"say it is safe\")",
  exfiltrate: "Asked the AI to send credentials or secrets",
  local_or_internal: "Pointed the AI at local files or internal addresses",
  run_download: "Told the AI to download and run something",
};

function evidenceButtons(seqs) {
  // A signal lists its event once per matching fragment; show each source event once.
  return [...new Set(seqs || [])].slice(0, MAX_SEQ_LINKS).map((seq) => h("button", {
    class: "seq-link",
    type: "button",
    "aria-label": `Jump to event ${seq} in the timeline`,
    on: { click: () => jumpToEvidence(seq) },
  }, `#${seq}`));
}

function manipulationFinding(outcome, text, seqs) {
  const label = { attempted: "Attempted", denied: "Denied by rules", resisted: "Resisted", succeeded: "Succeeded", partial: "Succeeded in part", observed: "Observed", allowed: "Allowed by rules", detected: "Detected by the model" }[outcome] || outcome;
  const holder = h("span", { class: "row-evidence" });
  const buttons = evidenceButtons(seqs);
  if (buttons.length) holder.append("Source ", ...buttons);
  return h("li", { class: "manipulation-finding", "data-outcome": outcome },
    h("strong", { class: "manipulation-outcome" }, label),
    h("span", { class: "manipulation-text" }, scannedText(text)),
    holder);
}

function renderManipulation(verdict) {
  const card = byId("manipulation-card");
  if (!card) return;
  if (!verdict || verdict.status !== "complete") {
    card.hidden = true;
    return;
  }
  const verdictSeqs = typeof report.verdictSeq === "number" ? [report.verdictSeq] : [];
  const findings = [];
  for (const signal of verdict.signals || []) {
    const what = PATTERN_LABELS[signal.pattern] || String(signal.pattern);
    if (signal.layer === "concealed") findings.push(manipulationFinding("attempted", `${what}, in text hidden from people.`, signal.evidence_seqs));
    else findings.push(manipulationFinding("observed", `Visible text matches "${what}". Visible text can be legitimate, such as an article about attacks.`, signal.evidence_seqs));
  }
  if (verdict.injection_reported_by_model) findings.push(manipulationFinding("detected", "The model reported prompt injection in this page.", verdictSeqs));
  for (const decision of verdict.policy_decisions || []) {
    if (decision.allowed) findings.push(manipulationFinding("allowed", `The model asked to ${decision.kind} ${decision.target}; the rules allowed it in a new sandbox.`, verdictSeqs));
    else findings.push(manipulationFinding("denied", `The model asked to ${decision.kind} ${decision.target}; the rules denied it (${decision.rule}).`, verdictSeqs));
  }
  const manipulation = verdict.manipulation || {};
  const comparedHidden = (verdict.model?.calls ?? 0) >= 2 && (verdict.signals || []).some((s) => s.layer === "concealed") || manipulation.verdict_flipped;
  if (manipulation.verdict_flipped) findings.push(manipulationFinding("partial", "Shown its hidden text, the model judged the page safer. The final verdict was raised by the rules, so it did not lower the result.", verdictSeqs));
  else if (comparedHidden) findings.push(manipulationFinding("resisted", "The hidden text did not make the model judge the page safer.", verdictSeqs));
  if (manipulation.canary_leaked) findings.push(manipulationFinding("succeeded", "The model's output repeated a secret planted in its instructions. It stayed inside Link Detonator and was redacted from this report.", verdictSeqs));
  else findings.push(manipulationFinding("resisted", "A secret planted in the model's instructions never appeared in its output.", verdictSeqs));

  const executed = (verdict.policy_decisions || []).some((d) => d.allowed && d.kind !== "open_link");
  const compromised = manipulation.canary_leaked || manipulation.verdict_flipped || executed;
  const attempted = findings.some((f) => ["attempted", "denied", "detected"].includes(f.dataset.outcome));
  byId("manipulation-summary").textContent = compromised
    ? "Partial compromise recorded: see the findings marked Succeeded. No action outside the rules was executed."
    : attempted
      ? "Manipulation was attempted. No successful compromise was recorded by these checks."
      : "No manipulation attempt was recorded by these checks.";
  card.dataset.compromised = String(Boolean(compromised));
  const list = byId("manipulation-findings");
  clear(list);
  list.append(...findings);
  card.hidden = false;
}

function renderTally(verdict) {
  const tally = byId("verdict-tally");
  if (!tally) return;
  const records = verdict.verification?.records || [];
  const count = (outcome) => records.filter((r) => r.outcome === outcome).length;
  const sandboxed = verdict.verification?.environment === "docker_sandbox";
  const items = [
    ["Attempts detected", count("attempt_detected"), "attempt_detected"],
    ["Denied by rules", count("denied_by_policy"), "denied_by_policy"],
    ["Contained by sandbox", sandboxed ? count("blocked_by_enforcement") : "not tested", "blocked_by_enforcement"],
    ["Model calls", verdict.model?.calls ?? 0, "neutral"],
  ];
  clear(tally);
  for (const [label, value, outcome] of items) {
    const li = document.createElement("li");
    li.dataset.outcome = outcome;
    const number = document.createElement("span");
    number.className = "tally-number";
    number.textContent = String(value);
    const name = document.createElement("span");
    name.className = "tally-label";
    name.textContent = label;
    li.append(number, name);
    tally.append(li);
  }
  tally.hidden = false;
}

const OUTCOME_LABELS = {
  attempt_detected: "Attempt detected",
  denied_by_policy: "Denied by policy",
  blocked_by_enforcement: "Blocked by enforcement",
  completed: "Completed",
  unknown: "Outcome unknown",
  not_tested: "Not tested",
  not_attempted: "Not attempted",
};

function verdictSection(heading, nodes) {
  const section = document.createElement("div");
  section.className = "verdict-section";
  const title = document.createElement("h3");
  title.textContent = heading;
  section.append(title, ...nodes);
  return section;
}

function verdictLine(label, text, outcome) {
  const line = document.createElement("p");
  line.className = "verdict-line";
  if (outcome) line.dataset.outcome = outcome;
  const tag = document.createElement("strong");
  tag.textContent = label;
  line.append(tag, " ", scannedText(text || ""));
  return line;
}

function renderVerdict(verdict) {
  report.verdict = verdict;
  renderPipeline();
  const card = byId("verdict-card");
  const title = byId("verdict-title");
  const body = byId("verdict-body");
  clear(body);
  const tally = byId("verdict-tally");
  if (tally) tally.hidden = true;
  const plain = byId("verdict-plain");
  if (plain) plain.hidden = true;
  const manipulationCard = byId("manipulation-card");
  if (manipulationCard) manipulationCard.hidden = true;
  if (!verdict || !verdict.status || verdict.status === "pending") {
    // The AI runs after the sandbox has finished and been removed, so a running scan
    // has no verdict yet. A finished scan with none had no model, or its analysis failed.
    card.dataset.status = "pending";
    const finished = FINAL_STATES.has(report.status);
    title.textContent = finished ? "No AI verdict for this scan" : "AI analysis pending";
    body.textContent = finished
      ? "No AI model is configured on this deployment, or the analysis did not complete. Everything on this page is raw evidence, not a judgement."
      : "The AI analyses the evidence after the sandbox run finishes and the container is removed.";
    return;
  }
  if (verdict.status === "unavailable") {
    card.dataset.status = "unavailable";
    title.textContent = "AI verdict unavailable";
    body.append(scannedText(verdict.reason || ""));
    return;
  }
  card.dataset.status = String(verdict.classification);
  title.textContent = String(verdict.classification);
  if (plain) {
    plain.textContent = PLAIN_VERDICT[verdict.classification] || "";
    plain.hidden = !plain.textContent;
  }
  renderTally(verdict);
  offerOpenLink(verdict);
  renderManipulation(verdict);
  const environment = verdict.verification?.environment;
  const parts = [scannedText(verdict.summary || "")];
  const opinion = [verdictLine("Model confidence", `${Math.round((verdict.model_confidence || 0) * 100)}% (the model's opinion, not a verified fact)`)];
  if (verdict.raised_by_rules) opinion.push(verdictLine("Raised by rules", `The model said ${verdict.model_classification}. ${(verdict.manipulation?.reasons || []).join(" ")}`));
  (verdict.indicators || []).forEach((item) => opinion.push(verdictLine("Indicator", item.claim)));
  parts.push(verdictSection("AI assessment", opinion));
  const decisions = (verdict.policy_decisions || []).map((d) => verdictLine(d.allowed ? "Allowed" : "Denied", `${d.kind} ${d.target} (${d.rule})`, d.allowed ? "completed" : "denied_by_policy"));
  if (decisions.length) parts.push(verdictSection("What the agent asked to do", decisions));
  const notice = environment === "docker_sandbox" ? "Facts recorded by the host." : "DEV MODE: not sandboxed, so no containment is claimed.";
  const records = (verdict.verification?.records || [])
    .filter((r) => r.outcome !== "not_attempted")
    .map((r) => verdictLine(OUTCOME_LABELS[r.outcome] || r.outcome, `${r.control}: ${r.detail}`, r.outcome));
  parts.push(verdictSection(`Independent verification. ${notice}`, records));
  body.append(...parts);
}

/* ------------------------------------------------------------------ QR input */

const QR_PREVIEW_SHAPE = /^\/api\/qr\/[A-Za-z0-9_-]{22}\/preview\.png$/;
const QR_KIND_LABELS = {
  web_url: "Web link",
  test_page: "Built-in test page",
  dangerous_uri: "Dangerous link type",
  payment_request: "Payment request",
  wifi_config: "Wi-Fi details",
  other_uri: "Other link type",
  text: "Plain text",
};

function initQr() {
  const button = byId("qr-decode");
  if (!button) return;
  button.addEventListener("click", () => decodeQr(byId("qr-file").files[0]));
  const camera = byId("qr-camera");
  byId("qr-camera-button").addEventListener("click", () => camera.click());
  camera.addEventListener("change", () => {
    if (camera.files[0]) decodeQr(camera.files[0]);
    camera.value = "";
  });
}

const QR_MAX_SIDE = 2048;
const QR_SEND_AS_IS = new Set(["image/png", "image/jpeg", "image/webp"]);

/* Phone photos are large, and may be HEIC. The browser decodes them here, on the user's
   own device, and sends a JPEG of at most 2048 pixels a side. The server still treats
   whatever arrives as hostile. */
async function prepareImage(file) {
  if (QR_SEND_AS_IS.has(file.type) && file.size <= 1.5 * 1024 * 1024) {
    try {
      const probe = await createImageBitmap(file);
      const small = Math.max(probe.width, probe.height) <= QR_MAX_SIDE;
      probe.close?.();
      if (small) return file;
    } catch {
      return file;
    }
  }
  let bitmap;
  try {
    bitmap = await createImageBitmap(file, { imageOrientation: "from-image" });
  } catch {
    throw new Error("This photo could not be read on this device. Try a PNG or JPEG screenshot.");
  }
  const scale = Math.min(1, QR_MAX_SIDE / Math.max(bitmap.width, bitmap.height));
  const canvas = document.createElement("canvas");
  canvas.width = Math.max(1, Math.round(bitmap.width * scale));
  canvas.height = Math.max(1, Math.round(bitmap.height * scale));
  canvas.getContext("2d").drawImage(bitmap, 0, 0, canvas.width, canvas.height);
  bitmap.close?.();
  const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/jpeg", 0.9));
  if (!blob) throw new Error("This photo could not be prepared for upload.");
  return blob;
}

async function decodeQr(file) {
  const errorBox = byId("qr-error");
  errorBox.hidden = true;
  byId("qr-result").hidden = true;
  if (!file) {
    showError(errorBox, "Choose a QR image first.");
    return;
  }
  const buttons = [byId("qr-decode"), byId("qr-camera-button")];
  for (const b of buttons) b.disabled = true;
  byId("qr-decode").textContent = "Decoding";
  try {
    let upload;
    try {
      upload = await prepareImage(file);
    } catch (error) {
      showError(errorBox, error.message);
      return;
    }
    if (upload.size > 5 * 1024 * 1024) {
      showError(errorBox, "The image is larger than 5 MB.");
      return;
    }
    const response = await fetch("/api/qr", { method: "POST", headers: { "Content-Type": upload.type || "application/octet-stream" }, body: upload });
    if (!response.ok) {
      showError(errorBox, await refusalMessage(response));
      return;
    }
    renderQrResult(await response.json());
    byId("qr-result").scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch {
    showError(errorBox, "Could not reach the server. Check your connection and try again.");
  } finally {
    for (const b of buttons) b.disabled = false;
    byId("qr-decode").textContent = "Decode";
  }
}

function renderQrResult(result) {
  if (QR_PREVIEW_SHAPE.test(result.preview_url || "")) byId("qr-preview").src = result.preview_url;
  const payloads = result.payloads || [];
  const sandbox = result.decoder === "sandbox" ? "Decoded in a network-disabled sandbox." : "DEV: decoded without a sandbox.";
  byId("qr-summary").textContent = payloads.length
    ? `${sandbox} Found ${result.codes_found} code${result.codes_found === 1 ? "" : "s"}${result.truncated ? ", showing the first 5" : ""}. Nothing has been opened.`
    : `${sandbox} No QR code was found in this image.`;
  const list = byId("qr-payloads");
  clear(list);
  for (const payload of payloads) {
    const item = document.createElement("li");
    item.className = "qr-payload";
    item.dataset.kind = payload.kind;
    const kind = document.createElement("strong");
    kind.textContent = QR_KIND_LABELS[payload.kind] || payload.kind;
    const text = document.createElement("code");
    text.textContent = payload.display;
    const note = document.createElement("p");
    note.className = "hint";
    note.textContent = payload.note || "";
    item.append(kind, text, note);
    if (payload.investigable && payload.target) {
      const go = document.createElement("button");
      go.type = "button";
      go.className = "detonate";
      go.textContent = "Investigate this link";
      go.addEventListener("click", () => investigateQr(result.id, payload.target));
      item.append(go);
    }
    list.append(item);
  }
  byId("qr-result").hidden = false;
}

function investigateQr(qrId, target) {
  const payload = target.kind === "fixture" ? { fixture: target.value, qr_id: qrId } : { url: target.value, qr_id: qrId };
  const code = byId("access-code")?.value.trim();
  if (code && target.kind === "url") payload.access_code = code;
  startScan(payload, byId("qr-error"));
}

function renderQrSource(data) {
  const card = byId("qr-card");
  if (!card) return;
  if (QR_PREVIEW_SHAPE.test(data.preview_url || "")) byId("qr-card-image").src = data.preview_url;
  const facts = byId("qr-card-facts");
  clear(facts);
  const rows = [
    ["Decoded link", data.payload_display],
    ["Type", QR_KIND_LABELS[data.payload_kind] || data.payload_kind],
    ["Codes in image", String(data.codes_found)],
    ["Image SHA-256", data.sha256],
    ["Decoder", data.decoder === "sandbox" ? "Network-disabled sandbox" : "DEV: no sandbox"],
  ];
  for (const [label, value] of rows) {
    const term = document.createElement("dt");
    term.textContent = label;
    const detail = document.createElement("dd");
    detail.append(scannedText(String(value ?? "")));
    facts.append(term, detail);
  }
  card.hidden = false;
}

/* ------------------------------------------------------------------ Email input */

/* Everything in an email upload is attacker-controlled except the labels below. It is
   shown with textContent (via scannedText) and never as a link or a download. */
const EMAIL_MAX_BYTES = 5 * 1024 * 1024;
const AUTH_LABELS = { spf: "SPF", dkim: "DKIM", dmarc: "DMARC" };
const AUTH_TONE = { pass: "good", fail: "bad", softfail: "bad", permerror: "warn", temperror: "warn", neutral: "warn", none: "warn", unknown: "warn" };

function initEmail() {
  const button = byId("email-check");
  if (!button) return;
  const input = byId("email-file");
  button.addEventListener("click", () => checkEmail(input.files[0]));
  const drop = byId("email-drop");
  drop.addEventListener("click", () => input.click());
  drop.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      input.click();
    }
  });
  drop.addEventListener("dragover", (event) => {
    event.preventDefault();
    drop.classList.add("is-over");
  });
  drop.addEventListener("dragleave", () => drop.classList.remove("is-over"));
  drop.addEventListener("drop", (event) => {
    event.preventDefault();
    drop.classList.remove("is-over");
    const file = event.dataTransfer && event.dataTransfer.files[0];
    if (file) checkEmail(file);
  });
}

async function checkEmail(file) {
  const errorBox = byId("email-error");
  errorBox.hidden = true;
  byId("email-result").hidden = true;
  if (!file) {
    showError(errorBox, "Choose a .eml file first.");
    return;
  }
  if (file.size > EMAIL_MAX_BYTES) {
    showError(errorBox, "The email is larger than 5 MB.");
    return;
  }
  const button = byId("email-check");
  button.disabled = true;
  button.textContent = "Checking";
  try {
    const type = file.type === "message/rfc822" ? "message/rfc822" : "application/octet-stream";
    const response = await fetch("/api/email", { method: "POST", headers: { "Content-Type": type }, body: file });
    if (!response.ok) {
      showError(errorBox, await refusalMessage(response));
      return;
    }
    renderEmailResult(await response.json());
    byId("email-result").scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch {
    showError(errorBox, "Could not reach the server. Check your connection and try again.");
  } finally {
    button.disabled = false;
    button.textContent = "Check email";
  }
}

function factRows(list, rows) {
  clear(list);
  for (const [label, value] of rows) {
    if (value === null || value === undefined || value === "") continue;
    const term = document.createElement("dt");
    term.textContent = label;
    const detail = document.createElement("dd");
    detail.append(scannedText(String(value)));
    list.append(term, detail);
  }
}

function textElement(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.append(scannedText(value));
  return node;
}

function formatBytes(size) {
  const n = Number(size) || 0;
  if (n < 1024) return `${n} bytes`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function emailItem(emailId, item, isLink) {
  const li = document.createElement("li");
  li.className = "qr-payload email-link";
  li.dataset.kind = item.kind;
  if (isLink && item.text_mismatch) li.dataset.mismatch = "yes";
  li.append(textElement("strong", "", QR_KIND_LABELS[item.kind] || item.kind));
  if (isLink && item.anchor_text && item.anchor_text !== item.display) {
    li.append(textElement("span", "email-label", "Text shown in the email"));
    li.append(textElement("code", "email-anchor", item.anchor_text));
    li.append(textElement("span", "email-label", item.text_mismatch ? "Really goes to (a different address)" : "Really goes to"));
  }
  li.append(textElement("code", "", item.display));
  const notes = [];
  if (isLink && item.hidden) notes.push("This link is hidden from the reader in the email.");
  if (!isLink && item.part) notes.push(`Found in: ${item.part}.`);
  notes.push(item.note || "");
  li.append(textElement("p", "hint", notes.filter(Boolean).join(" ")));
  if (item.investigable && item.target) {
    const go = document.createElement("button");
    go.type = "button";
    go.className = "detonate";
    go.textContent = "Investigate this link";
    go.addEventListener("click", () => investigateEmail(emailId, item.target));
    li.append(go);
  }
  return li;
}

function emptyItem(text) {
  const li = document.createElement("li");
  li.className = "hint";
  li.textContent = text;
  return li;
}

function renderEmailResult(result) {
  const headers = result.headers || {};
  const sandbox = result.extractor === "sandbox" ? "Read in a network-disabled sandbox." : "DEV: read without a sandbox.";
  const links = result.links || [];
  const codes = result.qr_payloads || [];
  const files = result.attachments || [];
  byId("email-summary").textContent = `${sandbox} Found ${plural(links.length, "link")}, ${plural(codes.length, "QR code")} and ${plural(files.length, "attachment")}.${result.truncated ? " Only part of this email was examined: it hit a size or count limit." : ""} Nothing has been opened.`;
  const to = (headers.to || []).join(", ") + (headers.to_count > (headers.to || []).length ? ` and ${headers.to_count - headers.to.length} more` : "");
  factRows(byId("email-facts"), [
    ["From", headers.from],
    ["Reply-To", headers.reply_to],
    ["Return-Path", headers.return_path],
    ["To", to],
    ["Subject", headers.subject],
    ["Date", headers.date],
    ["Relays", headers.received_count ? String(headers.received_count) : ""],
    ["File SHA-256", result.sha256],
  ]);

  const auth = byId("email-auth");
  clear(auth);
  for (const key of ["spf", "dkim", "dmarc"]) {
    const value = (result.auth || {})[key] || "unknown";
    const chip = document.createElement("li");
    chip.className = "email-chip";
    chip.dataset.tone = AUTH_TONE[value] || "warn";
    chip.textContent = `${AUTH_LABELS[key]}: ${value}`;
    auth.append(chip);
  }

  const warnings = byId("email-indicators");
  clear(warnings);
  for (const indicator of result.indicators || []) {
    const li = document.createElement("li");
    li.dataset.indicator = indicator.id;
    li.textContent = indicator.count > 1 ? `${indicator.text} (${indicator.count})` : indicator.text;
    warnings.append(li);
  }
  if (!warnings.children.length) warnings.append(emptyItem("None of the checks found anything. That does not make the email safe."));

  const linkList = byId("email-links");
  clear(linkList);
  for (const link of links) linkList.append(emailItem(result.id, link, true));
  if (!links.length) linkList.append(emptyItem("No links found."));

  const qrList = byId("email-qr");
  clear(qrList);
  for (const code of codes) qrList.append(emailItem(result.id, code, false));
  if (!codes.length) qrList.append(emptyItem("No QR codes found."));

  const fileList = byId("email-attachments");
  clear(fileList);
  for (const file of files) {
    const li = document.createElement("li");
    li.className = "email-attachment";
    if (file.risky) li.dataset.risky = "yes";
    li.append(textElement("strong", "", file.filename || "(no file name)"));
    li.append(textElement("span", "hint", `${file.content_type}, ${formatBytes(file.size)}${file.inline ? ", inline" : ""}${file.risky ? ". A file type that can run code." : ""}`));
    li.append(textElement("code", "email-hash", `SHA-256 ${file.sha256}`));
    fileList.append(li);
  }
  if (!files.length) fileList.append(emptyItem("No attachments."));
  else fileList.append(emptyItem("Attachments are never opened, run or offered for download."));

  byId("email-result").hidden = false;
}

function investigateEmail(emailId, target) {
  const payload = target.kind === "fixture" ? { fixture: target.value, email_id: emailId } : { url: target.value, email_id: emailId };
  const code = byId("access-code")?.value.trim();
  if (code && target.kind === "url") payload.access_code = code;
  startScan(payload, byId("email-error"));
}

function renderEmailSource(data) {
  const card = byId("email-card");
  if (!card) return;
  factRows(byId("email-card-facts"), [
    ["Subject", data.subject],
    ["From", data.from],
    [data.found_in === "qr" ? "QR code" : "Link", data.link_display],
    ["Link text", data.anchor_text && data.anchor_text !== data.link_display ? data.anchor_text : ""],
    ["Found in", data.found_in === "qr" ? data.qr_part || "a QR code" : ""],
    ["Email SHA-256", data.sha256],
    ["Reader", data.extractor === "sandbox" ? "Network-disabled sandbox" : "DEV: no sandbox"],
  ]);
  card.hidden = false;
}

/* ------------------------------------------------------------------ Benchmark */

const METRIC_LABELS = [
  ["attack_detection_rate", "Attacks detected", "higher is better"],
  ["false_positive_rate", "False alarms on safe pages", "lower is better"],
  ["unauthorized_action_prevention_rate", "Unauthorized agent actions blocked", "higher is better"],
  ["secret_exfiltration_prevention_rate", "Scans with no planted-secret leak", "higher is better"],
  ["incomplete_investigations", "Incomplete investigations", "lower is better"],
];

function metricTile(label, value, note, definition) {
  const tile = document.createElement("div");
  tile.className = "bench-metric";
  const number = document.createElement("p");
  number.className = "bench-number";
  number.textContent = value;
  const name = document.createElement("p");
  name.className = "bench-name";
  name.textContent = label;
  const small = document.createElement("p");
  small.className = "hint";
  small.textContent = definition ? `${note}. ${definition}` : note;
  tile.append(number, name, small);
  return tile;
}

function ratio(metric) {
  if (!metric || metric.denominator === undefined) return "n/a";
  return `${metric.numerator} / ${metric.denominator}`;
}

function cell(text) {
  const td = document.createElement("td");
  td.textContent = text;
  return td;
}

function renderComparison(data) {
  const runs = data.baselines || [];
  if (!runs.length) return;
  const ours = data.metrics || {};
  const oursCalledSafe = (data.cases || []).filter((c) => c.is_attack && c.classification === "benign").length;
  const attacks = (data.cases || []).filter((c) => c.is_attack).length;
  const rows = runs.map((run, index) => [
    `Without protections, run ${index + 1}`,
    `${run.summary?.attacks_called_safe?.numerator ?? "n/a"} / ${run.summary?.attacks_called_safe?.denominator ?? "n/a"}`,
    ratio(run.summary?.attacks_detected),
    ratio(run.summary?.false_alarms),
    ratio(run.summary?.secret_leaks),
    "naive",
  ]);
  rows.push(["Link Detonator, published run", `${oursCalledSafe} / ${attacks}`, ratio(ours.attack_detection_rate), ratio(ours.false_positive_rate),
    `${(ours.secret_exfiltration_prevention_rate?.denominator ?? 0) - (ours.secret_exfiltration_prevention_rate?.numerator ?? 0)} / ${ours.secret_exfiltration_prevention_rate?.denominator ?? 0}`, "ours"]);
  const body = byId("bench-compare-rows");
  clear(body);
  for (const values of rows) {
    const tr = document.createElement("tr");
    tr.dataset.kind = values.pop();
    tr.append(...values.map((value) => cell(value)));
    body.append(tr);
  }
  byId("bench-compare").hidden = false;
}

async function initBenchmark() {
  let data;
  try {
    data = await fetchJson("/api/benchmark");
  } catch (error) {
    byId("bench-meta").textContent = "No benchmark has been published on this server yet.";
    return;
  }
  const environment = (data.environment || []).join(", ") === "docker_sandbox" ? "the Docker sandbox on a Vultr VM" : (data.environment || []).join(", ");
  byId("bench-meta").textContent = `Run ${data.generated_at || "unknown"}, model ${data.model}, in ${environment}.`;

  const metrics = data.metrics || {};
  const tiles = METRIC_LABELS.map(([key, label, note]) => metricTile(label, ratio(metrics[key]), note, metrics[key]?.definition));
  const latency = metrics.latency_s || {};
  tiles.push(metricTile("Seconds per scan", `${latency.median ?? "n/a"}`, `median, max ${latency.max ?? "n/a"}`, "From submitting the page to the final verdict, model calls included."));
  const enforcement = metrics.sandbox_enforcement_events || {};
  tiles.push(metricTile("Enforcement events", `${enforcement.count ?? 0}`, "blocked by the sandbox or firewall", enforcement.definition));
  clear(byId("bench-metrics"));
  byId("bench-metrics").append(...tiles);

  const rows = (data.cases || []).map((item) => {
    const tr = document.createElement("tr");
    tr.dataset.result = item.passed ? "pass" : "fail";
    const caseCell = document.createElement("td");
    const id = document.createElement("strong");
    id.className = "bench-id";
    id.textContent = item.id || "";
    const category = document.createElement("span");
    category.className = "bench-category";
    category.textContent = String(item.category || "").replaceAll("_", " ");
    caseCell.append(id, category);
    const verdict = cell(item.classification || "none");
    verdict.className = "bench-verdict";
    verdict.dataset.verdict = item.classification || "none";
    const resultCell = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = "bench-badge";
    badge.textContent = item.passed ? "Pass" : "Fail";
    resultCell.append(badge);
    if (!item.passed && item.failure_explanation) {
      const why = document.createElement("span");
      why.className = "bench-why";
      why.textContent = item.failure_explanation;
      resultCell.append(why);
    }
    const actions = item.denied ? `${item.denied} denied` + (item.allowed ? `, ${item.allowed} allowed` : "") : item.allowed ? `${item.allowed} allowed` : "none proposed";
    const attack = cell(item.attack || "");
    attack.className = "bench-small";
    const expected = cell(item.expected_safe_behavior || "");
    expected.className = "bench-small";
    const naive = document.createElement("td");
    const chips = document.createElement("div");
    chips.className = "bench-naive";
    naive.append(chips);
    for (const run of data.baselines || []) {
      const label = run.classifications?.[item.id] || "none";
      const chip = document.createElement("span");
      chip.className = "naive-chip";
      chip.dataset.verdict = label;
      chip.dataset.fooled = String(Boolean(item.is_attack && label === "benign"));
      chip.textContent = label;
      chips.append(chip);
    }
    tr.append(caseCell, attack, expected, verdict, naive, cell(actions), resultCell);
    return tr;
  });
  clear(byId("bench-cases"));
  byId("bench-cases").append(...rows);
  renderComparison(data);

  const limits = [
    data.conditions || "",
    "These are controlled test pages, not the open web. A small suite cannot predict real-world detection rates.",
    "The verdict is a model opinion. Containment is enforced and verified separately, by the sandbox, firewall and policy gate.",
    "Prompt injection cannot be fully prevented in a model. The agent's only permitted action is opening an observed link in a new sandbox.",
  ].filter(Boolean);
  clear(byId("bench-limits"));
  byId("bench-limits").append(...limits.map((text) => { const li = document.createElement("li"); li.textContent = text; return li; }));
}

/* ------------------------------------------------------------------ Boot */

document.addEventListener("DOMContentLoaded", () => {
  const page = document.body.dataset.page;
  if (page === "home") { initHome(); initQr(); initEmail(); }
  if (page === "report") initReport();
  if (page === "benchmark") initBenchmark();
});
