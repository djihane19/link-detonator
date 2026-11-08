# Technical audit

Status as of 2026-11-03, after the first agent build. "Verified" means run here and observed. Anything needing Docker, the VM or the real model is not verified.

## Genuinely works (verified locally)
- Worker with real Chromium extracts evidence from all 19 test pages, offline, including when a page tampers with DOM APIs or freezes.
- API, queue, persistence, SSE replay, rate limits, abuse limits and security headers.
- Policy gate, verifier and benchmark judge. With a test model that obeys every attack, 70 of 70 prohibited proposals were denied on real page evidence.
- Full test suite passes (see the engineering log for the latest count).

## Partially implemented
- **Agent autonomy:** it analyses, opens approved links in new sandboxes and re-analyses. It never clicks or types, by design, and it sees URLs from navigations, requests, forms and page text but not every link's href.
- **Benchmark:** the harness runs; no real model result exists yet.
- **Product surface:** the report shows the verdict and verification. There is no benchmark page yet.

## Only simulated (and labelled so)
- `CompromisedModel` in `benchmarks/run.py`, a test double reachable only through the `compromised` option.
- `tests/fake_docker.py`, which proves how the app reacts to Docker, not what Docker does.
- Dev mode runs with no sandbox. The UI says so and claims no containment.

## Missing
- ~~Any run of the real model~~ Done 2026-11-06: three real benchmark runs on the VM; see `reports/README.md`.
- ~~Any run on a VM~~ Done 2026-11-05: all 40 sandbox checks pass on the VM, and the app is live behind Caddy. See the engineering log.
- ~~gVisor evaluation~~ Done 2026-11-08: the browser runs under gVisor with Chromium's own sandbox on; see VERIFICATION.md and `docs/evidence/browser-gvisor/`. Rollback is documented in VERIFICATION.md. Final video still to do.

## Insecure or questionable by design
- **Docker access:** the app user is in the `docker` group, which is root-equivalent on the VM. Mitigation: the VM holds nothing else. A compromised app means a compromised VM.
- **Browser isolation:** under gVisor with Chromium's own sandbox on, an escape needs a Chromium sandbox escape, then a gVisor escape (or a Docker or runsc bug), then whatever the VM allows. Each is possible in principle; the design makes the chain longer, not impossible. If `LD_RUNTIME` is unset, Chromium falls back to `--no-sandbox` on the shared host kernel.
- **One mount:** the browser sandbox gets one read-only bind mount, the resolver file. It is root-owned, holds only two resolver addresses and is validated before use.
- **Hidden-text patterns:** they catch known wording only. A paraphrase can pass, and the model is the only other layer.
- **Model output in the planted-secret test:** a leak means the model repeated it. The value is random and useless, and real keys never enter the prompt or sandbox.
- **Follow-up sandboxes** run outside the scan concurrency limit, bounded at two per scan.

## Could fail in a live demo
- The model service: rate limits, latency, or `response_format` being rejected. Failure shows "unavailable" honestly, not a fake verdict.
- ~~The firewall error assumption~~ Confirmed on the VM: Chromium reports `net::ERR_ADDRESS_UNREACHABLE` for every blocked private target (see VERIFICATION.md).
- Latency: two to four model calls after a 15-second scan.

## Must happen before deployment
1. Commit the staged baseline, then the agent work separately.
2. Inference key on the VM only, in `/etc/link-detonator/app.env`.
3. Run `deploy/verify_sandbox.sh` and fix what fails.
4. Run the real benchmark.

## Preserve
Worker extraction, Blast Radius honesty rules, URL policy, hostile-output caps, the firewall design, and the report UI.
