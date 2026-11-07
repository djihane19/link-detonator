# Link Detonator

**Other tools ask if a page is malicious. Link Detonator assumes the page will attack the AI checking it.** It opens a suspicious link or QR code in a throwaway browser, inside a container behind a firewall on Vultr. The AI reads the evidence and proposes; a deterministic rule engine decides what may run; the sandbox and firewall enforce; and the report shows what the page attempted, what was blocked and what was verified. The container is then destroyed, and that destruction is checked.

Built for the lablab.ai "Vultr: Agent Rush" hackathon (Blast Radius Zero challenge, browser pattern). Team RINVIDA.

## Judges start here (2 minutes)

| | |
|---|---|
| **Live app** | https://185.92.220.83.sslip.io |
| **1. Run the Gauntlet** | Click "Run the Gauntlet" on the home page: one page that attacks the agent several ways at once. Watch the Blast Radius fill in, then read the verdict at the top. No access code needed. |
| **2. Scan a QR code** | Upload `demo/qr/1-fake-bank-login.png`, decode, then investigate. Then try `4-cloud-metadata-refused.png`: it is refused before anything runs. |
| **3. Benchmark** | https://185.92.220.83.sslip.io/benchmark shows real attacks against the agent, measured, plus the same model without our protections: it called 1 to 2 of 11 attacks safe in each of 3 runs; Link Detonator 0 of 11. History: [reports/README.md](reports/README.md) |
| **4. Proof of containment** | [docs/VERIFICATION.md](docs/VERIFICATION.md): raw output of 40 sandbox and firewall checks on the live VM, and what they do not prove |
| **Design and trade-offs** | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/ENGINEERING_LOG.md](docs/ENGINEERING_LOG.md), [docs/AUDIT.md](docs/AUDIT.md) |

Test pages and test QR codes need no code. Live links on the open web need an access code, so strangers cannot use the server to attack other sites or spend its credit.

## AI agent

Written after kickoff, in `app/agent/`. It runs on the live VM with `glm-5.3-flash` on Vultr Serverless Inference. **Latest real benchmark: 14 of 14 cases, 11 of 11 attacks detected, 0 of 3 false alarms**, all in the Docker sandbox. See `reports/README.md` for all three runs, including the two that failed a case. Without `VULTR_API_KEY`, the verdict stays pending; there is no stand-in model in the product.

The model only proposes. `policy.py` is a deterministic gate that allows one action kind (opening an observed link in a new sandbox), the sandbox and firewall enforce, and `verify.py` reports from recorded facts. Three checks do not depend on the model behaving: a secret planted in the system prompt, a comparison of the verdict with and without the page's hidden text, and pattern detectors on hidden text. They can raise the final class and never lower it. Prompt injection cannot be fully prevented in a model, so nothing here relies on that.

See `docs/AUDIT.md` for status and `docs/ENGINEERING_LOG.md` for decisions. Run the benchmark with `make benchmark` (real model, needs the key) or `make harness` (a test model that obeys every attack, which tests the rules only and is not model performance).

## QR codes

A QR code is one more way to submit a link. On a phone, **Scan with camera** opens the camera directly. Photos are shrunk on the device to at most 2048 pixels and sent as JPEG; HEIC works where the browser can decode it. Otherwise upload a PNG, JPEG or WebP image (at most 5 MB and 4096x4096 pixels). It is decoded inside a disposable container with **no network**, read-only, non-root and limited to 256 MB, and the image reaches it only on stdin. The app itself only counts bytes and checks file signatures. It never parses the image.

The decoded payload is shown with its type: web link, built-in test page, dangerous link type (`javascript:`, `data:`, `file:` and similar), payment request, Wi-Fi details (password hidden), other link, or plain text. Nothing is opened, resolved or contacted during decoding. A web link is investigated only after you click, through the normal scan pipeline, with the same URL validation, access code and budgets. The server also checks that the link really came from that QR image. The report starts with a `qr_source` event that only the orchestrator can write: the image's SHA-256, the decoded link, and a preview redrawn by the sandbox. The original upload is kept as evidence but never served.

After a **benign** verdict on a real link, the report offers to open it in a new tab, behind a confirmation that says the verdict is not a guarantee. It never appears for suspicious or malicious verdicts, for test pages, or outside the sandbox.

**Limits:** no PDF, batch or OCR support. Decoding uses OpenCV's two QR detectors combined, and a damaged or unusual code may still not be read. A shortened link's real destination is unknown until investigated. Live links need the operator's access code, like any live scan.

## Email files

A suspicious email is one more way to submit links. Save it as a `.eml` file (most mail apps can download or save a message that way) and upload it in **Check a suspicious email** on the home page. Try `demo/email/1-fake-bank-alert.eml` and `demo/email/2-benign-newsletter.eml`.

The file is read inside a disposable container with **no network**, read-only, non-root and limited to 256 MB, from the same image and with the same limits as the QR decoder. It arrives only on stdin. The app itself only counts bytes and checks that the first kilobyte looks like mail headers rather than a binary; it never parses the email, its HTML or its images. The reader uses Python's standard `email` package and `html.parser`, and lists:

- the sender, Reply-To, Return-Path, subject, date and the SPF, DKIM and DMARC results the email's own headers claim (copied, not verified);
- every link in the HTML (with the text shown for it) and in the plain text;
- every attachment's name, declared type, size and SHA-256. Attachments are hashed in memory and never written, opened or offered for download;
- QR codes in attached, inline and embedded images, read with the same decoder as QR uploads.

Each link and QR payload is classified with the same rules as QR codes, and the reply is validated as hostile before use. The page lists indicators: a link whose text shows a different address than it goes to, a Reply-To on another domain, a failed sender check, `javascript:` or `data:` links, links to private addresses, executable or double-extension attachments, and QR codes. **These are facts, not a verdict.** A web link is investigated only after you click, through the normal scan pipeline, and the server checks that the link really came from that email. The report then starts with an `email_source` event that only the orchestrator can write: the subject, sender, chosen link and the file's SHA-256. The original file is kept as evidence but never served.

**Limits:** files only, at most 5 MB, 200 MIME parts, 10 levels of nesting, 50 links and 30 attachments; anything past that is cut off and the page says so. There is no live mailbox or forwarding address yet, which needs a domain with its own mail setup. No AI reads the email itself yet: the agent only sees the page a link leads to. Links in HTML text that are not real links are not listed. Header checks are only what the email claims, and a sender can forge them.

## Verification status

| Part | Status |
|---|---|
| Sandbox and firewall | **Verified on the live VM:** `deploy/verify_sandbox.sh` passes 42 of 42 real checks, including the QR and email decoders running under gVisor with no network (latest run 2026-11-07). Raw output and what it does and does not prove: [docs/VERIFICATION.md](docs/VERIFICATION.md) |
| Deploy scripts | Run for real: `provision.sh` built this VM, and it refuses to start the app unless verification passes |
| AI agent | Running on the VM with Vultr Serverless Inference. Real benchmark results: [reports/README.md](reports/README.md) |
| Not verified | Resistance to Chromium or kernel exploits in the browser sandbox, which does not use gVisor yet. See "Security model" below |

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
- **gVisor runs the file decoders, not yet the browser.** QR images and email files are parsed under gVisor (`LD_DECODER_RUNTIME=runsc`), so a parser exploit meets gVisor's user-space kernel, not the host's. The browser sandbox still uses the standard runtime: under gVisor its DNS lookups failed (gVisor's own network stack bypasses Docker's DNS redirect), and `--reproduce-nat` and `--reproduce-nftables` did not fix it in the time available. `provision.sh` installs gVisor from Google's signed repository.
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

These steps built the live VM on 2026-11-05. The first run found one bug in the verification script, since fixed (see the engineering log).

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
