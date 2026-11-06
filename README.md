# Link Detonator

Link Detonator opens a suspicious link in a throwaway browser container and returns the evidence: screenshots, redirects, requests, downloads, forms and hidden text. It also shows what the page tried to do and whether the sandbox stopped it. The container is then destroyed, and that destruction is checked.

It is a defensive triage tool, and an entry for the lablab.ai "Vultr: Agent Rush" hackathon (Blast Radius Zero challenge, browser pattern).

## AI verdict agent: not built yet

**There is no AI in this repository yet.** No LLM client, prompts, agent loop or verdict logic exist. The hackathon's guidance is that core AI work happens during the event, so all of it will be written after kickoff (2026-11-03 17:00 CET).

Today, `app/verdict.py` only holds the seam: a `VerdictEngine` protocol and a `PendingVerdictEngine` that always returns `status: "pending"`. Reports show raw evidence and no verdict. [docs/PRE_KICKOFF.md](docs/PRE_KICKOFF.md) lists what was written when.

## Verification status

| Part | Status |
|---|---|
| Deploy scripts | `bash -n` only, plus the generated rule text and the event checker (`tests/test_hardening.py`). They have never been executed against `iptables` or Docker |
| Firewall and sandbox behaviour | **Never run for real.** Nothing here has been tested on a VM or with real Docker |
| `deploy/verify_sandbox.sh` | Written to prove this on the VM. Until it passes there, treat the guarantees below as design intent |

## Architecture

```
            Internet
               |  443 (80 for certificates)
      +--------v----------------------------------------------+
      |  Vultr VM, Ubuntu 24.04 (holds nothing else)          |
      |                                                       |
      |   Caddy: automatic HTTPS                              |
      |      |  127.0.0.1:8000                                |
      |   FastAPI orchestrator (user: detonator)              |
      |      |  docker run, one per scan                      |
      |      |  stdout only: hostile JSON lines, capped       |
      |      |  and validated                                 |
      |   +--v----------------------------------------+       |
      |   | Sandbox container on bridge ld-br0        |       |
      |   |  Playwright + Chromium, read-only rootfs, |       |
      |   |  no capabilities, no mounts, no env,      |       |
      |   |  CPU/memory/PID limits, 60 s deadline     |       |
      |   +--+----------------------------------------+       |
      |      |                                                |
      |   iptables, the real boundary:                        |
      |      INPUT        -> blocked (the VM itself)          |
      |      DOCKER-USER  -> private and metadata blocked     |
      |                      TCP 80/443 allowed               |
      |                      DNS to 2 pinned resolvers only   |
      |                      everything else blocked          |
      +------+------------------------------------------------+
             |
         Public web only
```

More detail is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). The engineering rules are in [docs/CONTRACT.md](docs/CONTRACT.md).

## Security model

**What it is designed to do**

- Keep a scanned page away from cloud metadata, private networks and the VM's own services, using host firewall rules rather than URL checks.
- Keep secrets out of the container. There are no `-e`, `--env-file` or mounts, and evidence leaves only through stdout.
- Treat everything the worker prints, and every string from a page, as hostile.
- Claim containment only when events prove it. A row with no evidence says `not_observed`.

**Honest limits**

- **It is not malware-proof.** A container shares the VM's kernel, so a kernel or Docker escape would defeat it. A browser exploit is contained only as far as these layers hold.
- **Chromium runs with `--no-sandbox`** inside the container. Its own sandbox needs privileges the container deliberately lacks, so the container is the boundary and there is no second layer within it.
- **gVisor is optional and not installed.** It would reduce kernel exposure. Install it yourself and set `LD_RUNTIME=runsc`; this path is untested, and some checks in `verify_sandbox.sh` may need adjusting.
- **The docker group is root-equivalent.** The `detonator` user needs it to start containers, so compromising the app means root on the VM. **This VM must hold nothing else**: no other services, data or credentials you would mind losing. Rebuild it rather than cleaning it.
- **The sandbox can reach the public web.** Pages run for real, so a target learns the VM's IP and can receive anything the page sends. Detonating a link can tip off whoever sent it.
- **DNS can leak data.** Lookups for attacker-chosen names reach the attacker's name server through the resolver.
- **Evasion works.** A page can detect a headless browser, or wait out the 60-second deadline, and show nothing. A clean report does not mean a safe link.
- **There are no user accounts.** Anyone can run the built-in test charges, within per-client and global limits. Report URLs are unguessable rather than private.
- **Live URL scans are off until you turn them on.** A live scan runs a stranger's JavaScript from this VM's address, and stores what it finds for 7 days, so abuse complaints would name you. Set a long random `LD_LIVE_ACCESS_CODE` in `/etc/link-detonator/app.env` and give it only to people you trust. `LD_LIVE_SCANS_ENABLED=0` is the kill switch. There is a daily budget, non-GET requests are stopped in live mode and egress is throttled, but none of this makes it safe to publish the code.
- **Secret audit coverage.** Each scan compares the sandbox's environment against the named secrets, anything in the orchestrator's environment whose name looks like a secret, and a random canary. Add a new key's name to `LD_SECRET_ENV_NAMES` as well when you add the key, in case its name does not look like one.

## Local development

No Docker is needed. Fixtures run in a plain subprocess with **no sandbox**, and the UI shows a permanent "DEV: NOT SANDBOXED" banner. Live URLs are refused, and requests outside the fixture are aborted by the worker. These aborts are marked `blocked_locally`, and are never reported as a firewall block.

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/playwright install chromium --only-shell
make test     # offline tests
make dev      # http://127.0.0.1:8000
```

`make worker-image` builds the sandbox image, and needs Docker.

## Deploying to a VM

These steps have not been run yet. Follow them expecting to debug, and leave time for it.

1. Create a new Ubuntu 24.04 VM dedicated to this. If you use a Vultr firewall group, allow 22, 80 and 443.
2. Copy the repo to the VM:
   ```sh
   ssh root@<public-ip> mkdir -p /opt/link-detonator
   rsync -a --exclude .venv --exclude data --exclude .git ./ root@<public-ip>:/opt/link-detonator/
   ```
3. Provision it:
   ```sh
   ssh root@<public-ip> /opt/link-detonator/deploy/provision.sh
   ```
   This installs Docker, Caddy and ufw (allowing 22, 80 and 443), creates the `detonator` user, applies the firewall, and builds the worker image. It then runs `verify_sandbox.sh`. **The app starts only if every check passes.**
4. Open `https://<public-ip>.sslip.io/`. To use your own domain, pass `LD_SITE_ADDRESS=your.domain` to `provision.sh` on every run.

Useful afterwards:

```sh
deploy/firewall.sh --check        # is the policy in place?
deploy/verify_sandbox.sh          # full proof; run it with no scans in progress
journalctl -u link-detonator -f   # app logs
```

Restarting Docker also restarts the firewall unit and the app, so any running scan is marked `interrupted`.

## License

MIT. See [LICENSE](LICENSE).
