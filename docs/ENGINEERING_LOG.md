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

## 2026-11-07: naive baseline

**Why:** a competing entry compares against baselines, and "11/11 detected" alone does not show what our layers add. `benchmarks/baseline.py` sends the same sandbox-captured pages to the same model with a plain prompt over raw text: no untrusted boundary, no structured evidence, no rule engine, no planted secret. Proposals are counted, never run.

**Result, 3 runs:** the naive agent called 2, 2 and 1 of 11 attacks safe, each time on the prompt-injection pages or the self-navigating page. Link Detonator, run 4: 0 of 11.

**A scoring correction before publishing:** the first rule counted opening `http://elsewhere.invalid/...` as dangerous, because the URL policy refuses that name. That overstated it, since the name cannot resolve. The rule now counts only non-browsing tools, non-http schemes and private, loopback or metadata addresses. With it the naive agent made no dangerous proposals, and we make no claim about that.

## 2026-11-07: QR uploads blocked by the proxy

A tablet's camera upload was refused with a generic message. Caddy's `request_body` limit was 64 KB for every route, set before QR uploads existed, so photos never reached the app. The app tests call the app directly and could not see it. Fix: 6 MB on `/api/qr` only, with the app still enforcing exactly 5 MB, and 64 KB elsewhere. Checked through the public address with a 1 MB phone-style photo (decoded), and a 100 KB JSON body to `/api/scans` (still refused). A 413 now shows "image too large" instead of "request was refused".

## 2026-11-07: email intake

**Decision: the same boundary as QR codes.** An email is hostile input with three parsers in it (MIME, HTML, images), so none of them runs in the app. `worker/email_extract.py` runs in the worker image with `--network none`, read-only, 256 MB and 64 pids, reads the `.eml` on stdin and prints one JSON line. The app checks size and that the first 1 KB looks like headers, then validates every field of the reply (types, lengths, counts, exact key sets) and rejects it whole on any mismatch.

**Decision: reuse, not new rules.** Links and QR payloads go through `app.qr.classify()`, so the email path refuses exactly what the QR path refuses. `qr_decode.py` now exposes `decode_image()`, which the email reader imports, and its command-line output is unchanged. Investigation is the unchanged `/api/scans` path with an `email_id` that only links evidence, and only for a target found in that email. The scan manager's origin event now names its type, defaulting to `qr_source`, so `email_source` is host-only like `qr_source`.

**Decision: indicators, no verdict.** Seven deterministic facts (mismatched link text, Reply-To domain, failed header checks, dangerous links, internal links, risky attachment names, QR codes). They are shown as facts. No model reads the email in this change.

**Caps, measured locally:** 2000 levels of nesting are refused in 0.3 s; 3000 parts are cut at 200 in 0.4 s; a 4.4 MB text body is cut at 500 KB in 0.1 s. A 10 s alarm in the sandbox and a 20 s host timeout bound anything else. The Docker path is not yet checked on the VM; that needs an image rebuild, since `email_extract.py` is copied in by name.

**Proxy:** Caddy's 6 MB body limit now covers `/api/email` as well as `/api/qr`, so the QR upload refusal logged above does not repeat for email. 64 KB elsewhere.

## 2026-11-07: gVisor for the decoders

Installed `runsc` (release-20261102.0) from Google's signed apt repository and registered it with Docker. `provision.sh` now does both, and keeps the runtime when it rewrites `daemon.json`.

**Browser sandbox under gVisor, measured:** 33 of 43 checks passed. Every network block held, but DNS failed, because gVisor's netstack bypasses Docker's embedded-DNS NAT, and `--reproduce-nat` and `--reproduce-nftables` did not fix it. The pid and memory probes could not report: a fork flood or reaching 1 GB ends the whole gVisor sandbox (exit 2 or 137), which is containment but a different signal. Decision: do not move the browser yet. A DNS redesign this close to the deadline is a larger risk than the gain.

**Decoders under gVisor:** they have no network, so DNS does not matter. `LD_DECODER_RUNTIME=runsc` applies to the QR decoder and the email extractor. A QR decode took 1.04 s versus 0.83 s on runc, with the same result. `verify_sandbox.sh` adds "decoder has no network" and "decoder runs under gVisor": 42 of 42 pass.

## 2026-11-08: production truth, progress, receipts

**Truth fixes.** An external review read our page source and found two dev-mode sentences. Findings: the "None of the four applies in this dev run" note was hidden on the live site (`display: none`, `runner=sandbox`) but present in the source. The footer "no AI verdict is connected in this build" was visible and false, left over from before kickoff. A third problem: while a scan ran, the verdict card said "the model is not connected". Fixes: the server now removes dev-only blocks from the HTML unless it is in dev mode, the footer is accurate, and the verdict wording follows the real scan state. The snapshot's default `{"status": "pending"}` is the same value the no-model engine produces, so the UI decides by whether the scan has finished. Regression tests cover both modes.

**Progress strip.** It is driven only by recorded events. It shows the real order (Sandbox, Evidence, Containment verified, AI analysis) rather than the requested Sandbox, Evidence, AI, Containment, because removal is verified before the model is called; the requested order would show step 4 finishing before step 3.

**Receipts.** Canonical JSON plus a SHA-256 chain and a final digest, with an offline verifier written against the standard library only and tested against the app's implementation. No signing, by design at this stage. The trust model is written into every receipt.

**Benchmark page.** Method, raw report links (all checked: HTTP 200) and reproduction commands. The local commands were run from a fresh clone of the public repository. `make harness` produced the expected 14 failures from the obeying test model. Unit tests passed in 3 of 4 runs; the one failing run overlapped a parallel full-suite run and did not recur, cause unconfirmed. The VM commands are the ones used for runs 4 and baselines 1 to 3.

**Trust model correction.** The first receipt wording called the report page an independent source of the digest. It is not: the server recomputes the digest from its own event log on every request (stable across requests and restarts, and changed by any edit to the log; both tested). Independence exists only for a copy saved outside the server. The receipt, the verifier, the README and the report page now say so.

**Manipulation card and evidence navigation.** The card uses only fields already in the verdict, plus the verdict event's own sequence number as the source of model-side findings. Evidence-number jumps already existed but only flashed for 1.6 s; the target now stays marked until the next jump. Browser tests cover attempt-only, partial-compromise and clean cases, and that each number lands on its exact event.

## 2026-11-08: the browser under gVisor

Branch `feat/browser-gvisor`. Built and tested beside production (separate directory, image tag and app port) so the live version stayed untouched until the candidate was proven.

**DNS root cause.** Docker's embedded DNS is a NAT rule in the container's network namespace (`127.0.0.11:53` to a high port on that namespace's loopback), served in the host kernel. gVisor's netstack has its own loopback, so the redirected packets never arrive. Reproduced independently: under runsc, `getaddrinfo` failed while a raw query to `1.1.1.1:53` was answered, and `9.9.9.9:53` was blocked under both runtimes. **Fix:** a root-owned resolver file, written by `provision.sh` from `LD_SANDBOX_DNS`, bind-mounted read-only at `/etc/resolv.conf` (`LD_SANDBOX_RESOLV_CONF`). It names only the two resolvers the firewall allows. DNS-over-HTTPS was rejected because it would take DNS outside the port-53 rules. The contract's "no `--mount`, ever" becomes "this one read-only file, path validated".

**Chromium's own sandbox.** Under runsc it starts and every page renderer shows seccomp mode 2 and a single-uid user namespace. Under runc it cannot start ("Target page, context or browser has been closed"), so `--no-sandbox` is added only when `LD_CHROMIUM_SANDBOX` is off. `chrome://sandbox` does not exist in the headless shell, so `sandbox_probe.py chromium-sandbox` reads `/proc` for each new renderer instead. Two probe bugs found on the way: zygote children rewrite their command line into one string (exact matching found nothing), and the probe matched its own process.

**Limits behave differently.** gVisor stops the whole sandbox at the PID limit (exit 2, after about 111 guest processes) and OOM-kills it at the memory limit (`OOMKilled`, about 992 MiB). Both fail closed, but the in-container reporting is impossible, so the checks now judge host-side facts. The read-only-rootfs probe now writes to the user's own home, so only a read-only filesystem can refuse it (under gVisor the old target returned EACCES, which proved nothing).

**Measured.** `verify_sandbox.sh` 44 of 44 (the 42 earlier checks plus "browser runs under gVisor" and "chromium sandbox active"). A real-model benchmark run was also made under gVisor. It is kept out of the repository until it is reviewed; the published benchmark remains run 4, on the standard runtime.

**Network boundary.** A canary HTTP listener on the sandbox gateway, docker0 and the public IP, and a second sandbox serving a canary, all answered from their own side and none was reached from the gVisor sandbox: raw sockets got "No route to host", Chromium got `ERR_ADDRESS_UNREACHABLE`, the listener logged 0 hits and the `LD-SANDBOX-INPUT` counter rose. Metadata, 10/8, 172.16/12, 192.168/16 and 100.64/10, unauthorized resolvers (9.9.9.9, 8.8.4.4, 208.67.222.222, the gateway, 127.0.0.11), DNS over TCP to 9.9.9.9 and DNS-over-TLS were all blocked, as were DNS rebinding names and public 302 redirects to each private target. Public sites loaded (HTTP 200). The firewall rules were identical before and after. Raw output: `docs/evidence/browser-gvisor/`.

**Found while testing:** if the `docker` client process dies, its container keeps running until the worker's own deadline (20 s in the test) and is then removed by `--rm`. The app is not exposed to this: it kills by name at the host deadline and always runs `docker rm -f`.
