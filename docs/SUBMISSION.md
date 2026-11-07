# lablab submission text

Copy each field into the form. Check the form's character limits and trim if needed.

## Project title

Link Detonator: an AI agent that investigates hostile links without trusting them

## Short description (under 255 characters)

Other tools ask if a page is malicious. Link Detonator assumes it will attack the AI checking it: links and QR codes are investigated in a firewalled Vultr sandbox, the model only proposes, and every claim is backed by evidence.

## Long description

Link Detonator is an AI security agent for a problem most link scanners ignore: the page being investigated can attack the agent doing the investigating. Hidden instructions, fake logins, forced downloads and requests to internal servers all target the AI itself.

**How it works.** A suspicious link, or a QR code, opens in a throwaway Chromium browser inside a Docker container behind an iptables egress firewall on a Vultr VM. The browser never clicks, types or submits. The orchestrator records everything the page does. A model on Vultr Serverless Inference (glm-5.3-flash) reads that evidence, passed only as untrusted data, and proposes a verdict and follow-up actions. A deterministic rule engine allows exactly one action, opening a link seen in the evidence, and only in a fresh sandbox. Everything else is denied and logged. The container is destroyed after each scan, and the destruction is verified.

**The model cannot grant itself anything.** No security control depends on the model behaving. Network, filesystem, resource limits and secret isolation are enforced by the runtime and firewall. Three checks run without trusting the model: a secret planted in its instructions, a comparison of its verdict with and without the page's hidden text, and hidden-text attack patterns. They can raise a verdict but never lower it.

**Evidence over claims.** The report separates what the page attempted, what the rules denied and what the sandbox contained. A row says "contained" only when host-recorded events prove it, and never in an unsandboxed development mode. On the live VM, 40 of 40 sandbox and firewall checks pass. Blocked checks require the firewall rule's packet counter to rise, and the raw output is published.

**Measured.** An adversarial benchmark of 14 controlled pages (11 attacks, 3 safe lookalikes), run with the real model in the real sandbox: 11/11 attacks detected, 0/3 false alarms, every unauthorized agent action blocked, no planted-secret leaks. We publish all four runs, including the two that each missed one case, and what we changed.

**Why it matters.** We ran the same 14 pages through the same model without our layers: raw page text, a plain prompt, no rule engine. In each of three runs it called 1 to 2 of the 11 attacks safe, including a page that simply instructed it to. With Link Detonator: 0 of 11.

**QR codes.** QR images are decoded inside a container with no network. Nothing opens until the user clicks. Then the link goes through the same validation and pipeline, so metadata and private addresses are refused and `javascript:` links are never opened.

**Honest limits.** The container shares the host kernel, Chromium runs without its own sandbox inside the container, and 14 cases are a small suite. These are documented in the repository with the threat model.

**For:** IT and security teams triaging reported links and QR codes, and managed security providers.

## Technologies and tags

Vultr, Vultr Serverless Inference, Vultr Cloud Compute, Docker, Playwright, Chromium, FastAPI, Python, iptables, OpenCV, AI agents, AI security, prompt injection, sandboxing, phishing, QR codes

## Links

- Demo application platform: Vultr Cloud Compute (VM) with Vultr Serverless Inference
- Application URL: https://185.92.220.83.sslip.io
- GitHub repository: https://github.com/djihane19/link-detonator
- Slides: `docs/slides/link-detonator-slides.pdf`
- Cover image: `docs/slides/cover.png`
- Video: upload your recording (MP4)

## Notes for judges (optional field)

Start with "Run the Gauntlet" on the home page, then upload a QR image from `demo/qr/` in the repository. The README's "Judges start here" section has a 2-minute path. Test pages and test QR codes need no access code. Live links on the open web need one, so strangers cannot use the server to attack other sites.
