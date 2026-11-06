# Link Detonator: engineering contract

Link Detonator opens a suspicious link in a throwaway browser container on Vultr and returns evidence. This file is the shared source of truth for the code. Code must conform to it; change it only if it is wrong, and note why.

## Scope boundary (rule compliance)

lablab's guide says core AI functionality should be built during the event window, while prior non-AI scaffolding is generally allowed. Until kickoff (2026-11-03 17:00 CET) this repo contains **non-AI scaffolding only**.

- Allowed now: sandbox, firewall, evidence capture, API, UI, fixtures, deploy tooling, tests.
- Not allowed before kickoff: any LLM client or call, prompts, agent planning loop, AI verdict logic, prompt-injection classification by a model.
- `app/verdict.py` holds the seam: a `VerdictEngine` protocol and `PendingVerdictEngine`, which always returns `status: "pending"`. Never fabricate or hard-code a verdict. *(After kickoff, `app/agent/` implements this seam. `PendingVerdictEngine` remains the behaviour when no inference key is set.)*

## Layout

```
app/          FastAPI orchestrator (runs on the Vultr VM, NOT in the sandbox)
  config.py        env-driven settings (LD_ prefix)
  models.py        pydantic models for the event envelope and API
  urlpolicy.py     submitted-URL validation
  sandbox.py       SandboxRunner protocol, DockerRunner, LocalFixtureRunner
  scans.py         job manager, queue, concurrency, persistence, SSE pub/sub
  blast_radius.py  pure function: events -> Blast Radius rows
  verdict.py       VerdictEngine seam
  ratelimit.py     per-client limits
  main.py          routes, security headers, static pages
  static/          index.html, report.html, app.js, styles.css (no build step, no CDN)
worker/       Code that runs INSIDE the sandbox
  worker.py, Dockerfile, requirements.txt, fixtures/*
deploy/       provision.sh, firewall.sh, verify_sandbox.sh, systemd units, Caddyfile
tests/        pytest, offline only
docs/         CONTRACT.md, ARCHITECTURE.md, PRE_KICKOFF.md, DEMO.md
```

Python 3.12-compatible (VM is Ubuntu 24.04). Local venv at `.venv`. Dependencies pinned in `requirements*.txt`. Worker image: `mcr.microsoft.com/playwright/python:v1.64.1-noble`, with `playwright==1.64.1`.

## Event envelope

Every event is one JSON object: `{"v":1,"seq":int,"ts":float,"source":"worker"|"host","type":str,"data":{}}`.

The worker writes single-line JSON to stdout with `type`, `data` and optional `ts`. **The host assigns `seq`, `source` and its own receive `ts`** and ignores any such claims from the worker. Worker output is hostile input: enforce a per-line cap (8 MiB), a total cap (64 MiB), an event-count cap (5000), schema validation per type, and truncation of strings. Drop unknown types and count them in `host: output_dropped`. Exceeding a hard cap kills the sandbox (`output_limit_killed`).

### Worker event types

| type | data |
|---|---|
| `worker_started` | `url, mode` (`live`/`fixture`), `offline` (bool) |
| `navigation` | `url, status` (int or null), `redirected_from` (or null) |
| `response` | `url, status, peer_ip` (or null): an answer to any request, sent only when the URL or the connected address is non-public (cap 200) |
| `screenshot` | `label, mime` (`image/jpeg`), `b64` |
| `request` | `url, method, resource_type` (cap 500, then count) |
| `request_failed` | `url, error, resource_type, blocked_locally` (bool: true only when worker `--offline` aborted it) |
| `download_attempt` | `url, suggested_filename` (file is never kept or opened) |
| `dialog` | `dialog_type, message` (auto-dismissed) |
| `popup` | `url` (closed after recording) |
| `form` | `action, method, has_password, field_names[]` (never filled or submitted) |
| `text_layers` | `visible_text` (cap 20k chars), `concealed[]` of `{source, text, selector}`, `source` in `hidden_css, offscreen, tiny_text, same_color, comment, meta, aria_label, alt` |
| `page_unresponsive` | `operation, timeout_ms` |
| `page_crash` | `{}` |
| `worker_finished` | `status` (`ok`/`error`/`partial`), `error` (or null), optional `omitted` (`{type: count}` for events the worker's own caps held back; shown in the `limits` row), optional `tracking_shed` (true: request recording stopped during a flood), optional `deadline_reached` (true: the worker's own time limit ended the scan) |

`redirected_from` also covers page-driven navigations (meta refresh, script), since the worker never interacts with the page. A password field outside any form is a `form` with empty `action` and `method`. The worker also accepts `--deadline`, `--dwell` and `--work-root`, and refuses `--offline` with `--url`.

In live mode the worker lets only GET, HEAD and OPTIONS through, and aborts anything else a page sends, recording it as `request_failed`. A scan reads a page; it does not post to third parties from this VM's address. The worker turns off Chromium's local-network checks so that requests to private addresses reach the firewall.

The worker never clicks, types or submits. Each browser operation has its own timeout shorter than the host deadline, and events flush immediately so evidence survives a kill. Screenshots: viewport JPEG, quality 60, cap 25 per scan.

### Host event types (trusted facts)

`sandbox_created {name, image, runtime, policy{}}`, `secret_audit {ok, checked_count, canary}`, `deadline_killed {deadline_s, kill_confirmed}`, `output_limit_killed {reason, kill_confirmed}`, `output_dropped {count}`, `sandbox_exit {exit_code, oom_killed}`, `sandbox_removed {verified}`, `scan_error {message}`, `scan_finished {status}`, `verdict {status, ...}`.

`sandbox_removed.verified` is true only if a post-cleanup `docker inspect` reports the container does not exist. `secret_audit.ok` compares values of configured secrets against the running container's `Config.Env` from `docker inspect`, and never logs or emits the values. Those are the named secrets, any variable whose name looks like a secret, and a random canary (`canary: true`) planted in the orchestrator's environment, so the audit does real work on a VM with nothing else configured.

`kill_confirmed` is true only if `docker kill` returned 0 and the container is then gone or not running. Runner events from `LocalFixtureRunner` omit it.

## Docker policy (exact argv)

Built as a pure function `build_docker_argv(name, image, target_args, settings) -> list[str]` and unit-tested:

```
docker run --rm --init --name ld-<id> --label link-detonator=1 --network ld-sandbox
  --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m
  --cap-drop ALL --security-opt no-new-privileges
  --pids-limit 256 --memory 1g --memory-swap 1g --cpus 1 --shm-size 128m
  --ulimit nofile=1024:1024 --log-driver none --user pwuser
  [--runtime <LD_RUNTIME> if set]
  <image> python /worker/worker.py <args>
```

`<args>` is the target (`--url X` or `--fixture X`) plus `--deadline`, set to 75% of `LD_DEADLINE_S` (bounded to 5-300 s) so `worker_finished` arrives before the host's kill.

No `-e`, `--env-file`, `-v`, `--mount`, `--privileged`, `--pid`, `--ipc=host` or `--network host`, ever. Evidence leaves only through stdout. Use `asyncio.create_subprocess_exec` with an argv list, never a shell. Chromium runs with `--no-sandbox` because the container is the boundary; say so in the docs. Its profile lives in `/tmp`.

Lifecycle: the host enforces the deadline (default 60 s) with `docker kill`, always runs `docker rm -f` in `finally`, then verifies removal. On startup a reaper removes containers labelled `link-detonator=1`.

## Network policy (deploy/firewall.sh)

Bridge `ld-sandbox`, device `ld-br0`, subnet `172.30.0.0/24`, `enable_icc=false`, IPv6 off.

- `DOCKER-USER`, for traffic from `ld-br0`: allow established; reject `169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 127.0.0.0/8, 0.0.0.0/8, 224.0.0.0/4, 240.0.0.0/4`; allow port 53 to the two resolvers pinned in `daemon.json` (`1.1.1.1`, `8.8.8.8`); allow TCP 80/443; reject everything else.
- Changed from the first version of this file, which said "drop" and allowed no DNS. Allowing only TCP 80/443 contradicted the "DNS works" check, because Docker's resolver dials upstream servers from the container's namespace. A silent drop leaves Chromium retrying past the deadline, so `request_failed` would never fire and `private_network` could never be `contained`. Neither has been tested on a VM; see ARCHITECTURE.md.
- `INPUT`: traffic from `ld-br0` is rejected. **DOCKER-USER only covers forwarded traffic, so container-to-host needs this rule**, including the VM's own public IP.
- Rules must be idempotent and restored after reboot and after Docker restarts (systemd oneshot after docker.service).
- `deploy/verify_sandbox.sh` runs on the VM with the exact sandbox flags and prints PASS/FAIL for: metadata blocked, RFC1918 blocked, host and public-IP blocked, public HTTPS allowed, DNS works, rootfs read-only, `/tmp` noexec, no capabilities, non-root, no env secrets, pid limit, memory limit. It exits non-zero on any FAIL.

## Submitted-URL policy (urlpolicy.py)

Accept only `http`/`https`, ports 80/443 or none, no userinfo, length up to 2048. The host must be a public DNS name or public IP. Reject single-label names, and private, loopback, link-local, reserved, multicast and unspecified addresses (IPv4, IPv6, IPv4-mapped, and integer/octal/hex forms). Resolve the name and reject if any answer is non-public, with the resolver injectable for tests. This check is UX and defence in depth; **the firewall is the real boundary** because of DNS rebinding and redirects.

## Fixtures

Served inside the sandbox only, via Playwright `context.route` on `http://fixtures.invalid/<name>`; no public hostile page is ever hosted. In `--fixture` mode other requests go to the real network so the firewall does the real blocking on the VM. `--offline` (local tests) aborts all non-fixture requests and marks them `blocked_locally: true`. A local abort must never be presented as a firewall block.

All fixtures use a fictional brand ("Larkspur Bank"), collect nothing, and show a visible "Link Detonator test fixture" footer. Download payloads are harmless text. No real brand names or logos.

Required: `benign`, `phish-login` (redirect then fake login), `hostile-injection` (concealed instructions in every `concealed` source), `hostile-download`, `hostile-ssrf` (fetch/img to metadata, RFC1918, loopback), `hostile-freeze` (`while(true){}` after a short delay), `hostile-memory` (bounded allocation loop), `hostile-gauntlet` (composite, for the demo video).

## API

- `POST /api/scans` with exactly one of `{"url"}` or `{"fixture"}`, and optional `access_code` -> 202 `{id, report_url}`; 400 invalid; 403 access code wrong, or live scans off; 429 rate limited or budget spent; 503 queue full or too many lookups.
- Live URLs need `LD_LIVE_ACCESS_CODE` to be set and supplied. Unset means live scans are off. `LD_LIVE_SCANS_ENABLED=0` is the operator's kill switch. Fixtures stay public. Changed from the first version of this file, which let anyone submit a URL: an anonymous service that runs arbitrary pages from the owner's IP is an abuse relay.
- `GET /api/scans/{id}` -> snapshot: status, target, events (screenshot `b64` replaced by `image_url`), `blast_radius`, `verdict`.
- `GET /api/scans/{id}/events` -> SSE, replay honouring `Last-Event-ID`, ends after `scan_finished`.
- `GET /api/scans/{id}/screenshots/{seq}.jpg` -> JPEG only after magic-byte validation, `X-Content-Type-Options: nosniff`.
- `GET /api/fixtures`, `GET /healthz`. Pages: `/`, `/r/{id}`.
- SSE also sends a named `blast_radius` event with the current rows, plus keepalive comments, and answers 204 when a finished scan has nothing left to replay.

IDs are `secrets.token_urlsafe(16)`. Persist to `data/scans/<id>/` (`meta.json`, `events.ndjson`, decoded screenshots). Screenshot `b64` is not kept in `events.ndjson`. Reload on start; a scan interrupted by restart becomes `interrupted`. Enforce retention days and a disk cap. Defaults: concurrency 2, queue 10 plus 2 places only code holders can take, 5 scans/min and 30/hour per client, 2 queued-or-running scans per client, 120 scans/hour globally (code holders exempt), 50 live scans/day globally, 240 reads/min and 4 open streams per client. Finished snapshots are cached, and at most 4 finished logs are read at once; beyond that a snapshot answers 503. Honour `X-Forwarded-For` only when `LD_TRUST_PROXY=1`.

Headers on all responses: `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`, plus `X-Content-Type-Options`, `Referrer-Policy: no-referrer`. All scanned-page strings are attacker-controlled: the UI renders them with `textContent` only, never `innerHTML`, and never makes them clickable.

## Blast Radius (blast_radius.py)

A pure function of events returning rows `{id, label, status, detail, evidence_seqs, source}`, with `status` in `contained, observed, not_observed, clear, failed, not_applicable`.

Rows: `downloads`, `private_network`, `freeze`, `memory`, `concealed_text`, `secrets`, `limits`, `destroyed`.

**Honesty rules:** a row may say `contained` only when events prove it. `private_network` is `contained` only in a Docker scan where every request to a non-public destination that could reach the firewall failed with the firewall's own error (`net::ERR_ADDRESS_UNREACHABLE`, measured on the VM by `verify_sandbox.sh`), and the request log is complete. Any other error, or a truncated log, is `observed`. An answer from a non-public address, judged by connected address as well as URL, or `ERR_CONNECTION_REFUSED` from a non-loopback private address, is `failed`. Loopback and names that never resolved do not reach the firewall, so alone they are `not_applicable`. The firewall's error on a public-looking name is `observed`. `blocked_locally` yields `not_applicable` with a clear note. `freeze` and `limits` are `contained` only with verified removal, and any host kill must also be confirmed. `destroyed` is `contained` only if `sandbox_removed.verified` is true, otherwise `failed`. `concealed_text` is `observed` (the AI classifier arrives after kickoff). A row with no evidence is `not_observed`.

## Local dev runner

`LocalFixtureRunner` runs `worker.py --fixture X --offline` as a subprocess so the UI works on a Mac without Docker. It requires `LD_DEV_LOCAL_RUNNER=1`, refuses live URLs, refuses to start unless `LD_BIND_HOST` is loopback, refuses scans on any connection that did not arrive on a loopback address, emits no sandbox host events that imply isolation, and makes the UI show a permanent "DEV: NOT SANDBOXED" banner.
