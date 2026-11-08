# Evidence: the browser sandbox under gVisor

Raw output from the live VM (Ubuntu 24.04, kernel 6.8.0-147, Docker 29.1.3, runsc release-20261102.0), 2026-11-08. Summaries are in [../../VERIFICATION.md](../../VERIFICATION.md).

**Post-deployment** results, from production after the switch-over, are in [post-deploy/](post-deploy/): the deploy log, `verify_sandbox.sh` 44 of 44, the container seen during a live Gauntlet, its receipt and screenshots with the independent verification, teardown, and the backup, deploy and rollback scripts. Everything else in this folder is **pre-deployment**.

| Pre-deployment file | What it is |
|---|---|
| `verify-sandbox-bfff013.txt` | `deploy/verify_sandbox.sh`, 44 of 44, release image and settings |
| `network-boundary.txt` | Live canary listener on the host and a neighbour sandbox, raw sockets and Chromium from the gVisor sandbox, DNS rebinding, redirects, firewall unchanged |
| `e2e-bfff013.txt` | Scans through the app's API: successes, failures, teardown and the standalone receipt verifier |
| `images.txt` | Image IDs: production `prod-6a3fcec` and release `gvisor-bfff013`; the worker file in each matches its commit |
| `scripts/` | The test scripts, as run |

Local test suite at commit `fa95556`: 1033 passed.

**Commit identifiers.** This branch's history was rewritten on 2026-11-08, before it was first pushed, to keep an unreviewed benchmark run out of the repository. Raw logs, file names and image tags keep the original hashes: `bfff013` is now `fa95556` and `cd875a3` is now `3b52bef`. The code trees are identical; only documentation changed.

These show the layers are in place on this VM at this time. They do not show the layers are unbreakable: a Chromium sandbox escape followed by a gVisor escape, or a Docker or runsc bug, would still reach the VM.
