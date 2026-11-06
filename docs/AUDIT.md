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
- Any run of the real model. Prompts, `response_format` handling and the vision input are unproven on the service.
- ~~Any run on a VM~~ Done 2026-11-05: all 40 sandbox checks pass on the VM, and the app is live behind Caddy. See the engineering log.
- gVisor evaluation, slides, final video, and rollback documentation.

## Insecure or questionable by design
- **Docker access:** the app user is in the `docker` group, which is root-equivalent on the VM. Mitigation: the VM holds nothing else. A compromised app means a compromised VM.
- **Chromium `--no-sandbox`:** the container is the only boundary unless gVisor is added. A Chromium exploit plus a kernel exploit is out of scope for this design.
- **Hidden-text patterns:** they catch known wording only. A paraphrase can pass, and the model is the only other layer.
- **Model output in the planted-secret test:** a leak means the model repeated it. The value is random and useless, and real keys never enter the prompt or sandbox.
- **Follow-up sandboxes** run outside the scan concurrency limit, bounded at two per scan.

## Could fail in a live demo
- The model service: rate limits, latency, or `response_format` being rejected. Failure shows "unavailable" honestly, not a fake verdict.
- The firewall error assumption: `ERR_ADDRESS_UNREACHABLE` is reasoned, not observed. If wrong, `private_network` reads `observed`, not `contained`, until fixed. `verify_sandbox.sh` checks this.
- Latency: two to four model calls after a 15-second scan.

## Must happen before deployment
1. Commit the staged baseline, then the agent work separately.
2. Inference key on the VM only, in `/etc/link-detonator/app.env`.
3. Run `deploy/verify_sandbox.sh` and fix what fails.
4. Run the real benchmark.

## Preserve
Worker extraction, Blast Radius honesty rules, URL policy, hostile-output caps, the firewall design, and the report UI.
