# Engineering log

Newest last. Decisions and evidence, for review by another engineer.

## 2026-11-03

**First commit missed kickoff.** Scaffolding finished about 01:05 CET but was not committed before 17:00 CET. Disclosed in `PRE_KICKOFF.md`. No backdating. The baseline was staged before any AI code was written, so the first commit contains no AI.

**The model proposes, it never decides.** Alternative considered: give the model browser tools directly, as in most browser agents. Rejected, because a page can steer the model and tool access then equals attacker access. Instead one action kind exists, and a rule engine with no model input gates it.

**A fresh sandbox per link, no interactive browser session.** Alternative: a long-lived controllable browser over stdin. Rejected for now: it adds a control channel from host into a hostile container, and shared state between steps. Cost: the agent cannot click or type, so it cannot go through multi-step flows. The worker's "never click" rule also means it cannot trigger a harmful submission.

**Hidden-text comparison.** The model judges the page with and without hidden text. If hidden text makes the verdict safer, that is treated as manipulation. Costs one extra call only when hidden text exists.

**Final class only goes up.** Rules can raise it, the model cannot lower it through follow-ups. Cost: more false positives are possible. Measured by benign cases.

**Containment claims come from one place.** `verify.py` reuses `compute_blast_radius` and reports `not_tested` in dev mode, even if a page produces firewall-like errors. A worker cannot claim to be a sandbox, because only host-sourced events count.

**Model choice: `glm-5.3-flash`, provisional.** On the live list with image input and tool support, at $0.10 per million input tokens and $0.35 per million output tokens. Not yet called. Configurable with `LD_LLM_MODEL`. To be compared with `qwen3.8-flash-next` on the benchmark.

**No OpenAI SDK.** `httpx` is enough for one endpoint.

**Evidence so far.** `make harness` with an obeying model: 70/70 prohibited proposals denied, and 0/14 cases passed, as expected, since that model leaks and over-flags. This shows the judge is not hardcoded. It is not a detection result.

## 2026-11-05

**VM deployed.** Vultr `vhp-4c-8gb` in Amsterdam, Ubuntu 24.04.5, Docker 29.1.3. Live at `https://185.92.220.83.sslip.io` with a Let's Encrypt certificate from Caddy.

**`verify_sandbox.sh`: 40 of 40 checks pass on the VM.** First real run. It confirmed the assumption that a firewall REJECT reaches Chromium as `net::ERR_ADDRESS_UNREACHABLE`, with firewall packet counters rising for every blocked destination. The memory limit killed an allocator after 992 MiB, and the pid limit refused forks after 254.

**Bug found on the VM: kill confirmation.** `docker kill` returns once the signal is sent. Docker 29 also prints an empty line before its "no such object" error, so the check's fallback never matched. Measured: a killed sandbox is gone within about 250 ms. Fixes: the check judges by exit status and polls for up to 3 s, and the app polls the same way (`KILL_CONFIRM_POLLS`) before claiming a confirmed kill.

**Live Gauntlet scan on the VM:** downloads, private_network, freeze and destroyed all read `contained` from real evidence. Secrets: clear. Verdict pending, because no inference key is set yet.

## 2026-11-06 and 07

**Real model connected.** First call returned no answer: `glm-5.3-flash` spent all 1500 output tokens reasoning (`finish_reason: length`). Fix: `reasoning_effort: low` and a 4000-token cap, both configurable, plus a named error for an exhausted budget.

**Benchmark runs 1 to 3 (real model, Docker sandbox):** 13/14, 13/14, 14/14. Details in `reports/README.md`.
- Run 1 missed a page-initiated popup and navigation. Fix: the evidence now lists page-initiated actions as facts, and the prompt says a page's claims about itself are not evidence. A rule that flags popups or redirects was rejected, because ordinary sites do both.
- Run 2's miss was infrastructure: an app restart's cleanup removed the benchmark's sandbox. Fix: sandboxes carry an owner label, and cleanup removes only its own. The fake Docker ignored all but the first `--filter`, which hid this in tests; it now applies all of them, like Docker.

**Benchmark page** at `/benchmark` shows the published real run. It refuses harness reports, so a test-double result can never appear as model performance.

## 2026-11-07: QR input adapter

**Decision: decode in a sandbox, not in the app.** Parsing an uploaded image in the trusted process would put an image parser in front of the attacker. The decoder runs in the worker image with `--network none`, read-only, 256 MB and 64 pids, and gets the image on stdin. The host checks only size and signature, and validates every field of the decoder's reply as hostile input. The preview the app serves is redrawn by the sandbox, so uploaded bytes are never served back.

**Decision: no new security logic.** Payloads go through `check_url_syntax`, with no DNS at decode time. Investigation then goes through the unchanged `/api/scans` path. `qr_id` only links evidence, and only when the target matches a payload decoded from that image.

**Measured:** OpenCV's default detector missed a 46-character version 4 code that its Aruco detector read. The decoder now combines both: 15 of 15 exact decodes across sizes and payload types. On the VM: decoder container network unreachable (errno 101), and `verify_sandbox.sh` still 40/40 after the image rebuild.
