# Demo video runbook

> **DRAFT.** The AI parts do not exist yet, and nothing here has been rehearsed or run on a VM. Sections marked **[AFTER KICKOFF]** are placeholders. Rewrite this once the agent works, and keep narration to what the screen actually shows.

Target length: **3:40**, under the 4-minute limit. Everything is built on the `hostile-gauntlet` fixture, so no real hostile site or brand appears.

## Before recording

- [ ] Run `deploy/verify_sandbox.sh` on the VM with no scans running. All PASS, or do not record.
- [ ] Use the **VM**, never `make dev`. Local mode has no sandbox or firewall, so it cannot show containment.
- [ ] Run the Gauntlet once as a rehearsal and check each row below against the real output.
- [ ] Run `hostile-memory` once and keep its report open for the memory section.
- [ ] Do not narrate `private_network` as firewall proof unless `verify_sandbox.sh` passed "browser sees the firewall error" on this VM.
- [ ] Open a terminal with SSH to the VM, large font, no secrets visible in history or the environment.
- [ ] Close anything showing personal details. Hide the public IP if you prefer.

## Script

| Time | On screen | Say |
|---|---|---|
| 0:00 to 0:20 | Home page | "Someone sends you a suspicious link. Clicking it is the risk. Link Detonator opens it for you, in a container built to be destroyed." |
| 0:20 to 0:45 | Terminal: `verify_sandbox.sh` output, already captured | "This is not a claim. On this VM, these checks ran with the exact flags each scan uses. Metadata, private networks and the host are blocked, and the rule counters prove the firewall did it." |
| 0:45 to 1:05 | Click The Gauntlet | "This test page is hostile on purpose, with a fictional bank. It is served only inside the sandbox, and tries most of its tricks at once." |
| 1:05 to 1:45 | Report filling in live: Filmstrip, Redirect chain, Timeline | Narrate events as they arrive: the redirect, the fake login form, the download attempt, the requests to internal addresses, the frozen tab. "Nothing here is clicked or typed. We only watch." Do not mention memory here: the Gauntlet allocates only 128 MiB, and its `memory` row reads `not_observed`. |
| 1:45 to 2:15 | Blast Radius rows, one at a time | Say only what the rehearsal showed. If `private_network` reads `contained`: "The worker reported these requests failing with the firewall's rejection, and the verification run showed that error comes from this firewall." The download was recorded and never kept. Each row links to its evidence. Finish on `destroyed`: "We checked afterwards that the container no longer exists." |
| 2:15 to 2:30 | Report from a separate `hostile-memory` scan, already run: `memory` row | Show the row as the rehearsal produced it. Say the memory limit stopped it only if the row reads `contained`. If it reads `observed`, say a page crash was recorded and the cause is not established. |
| 2:30 to 2:50 | "What you see, what it hid" | "The page's visible text is on one side. On the other are instructions hidden from people but readable by machines. That is an attack on any AI reading this page." |
| 2:50 to 3:20 | **[AFTER KICKOFF]** The agent's verdict | Show the real agent working from this evidence, including how it handles those hidden instructions. Do not script this until it exists. |
| 3:20 to 3:40 | README, security limits | "This is not malware-proof: a container shares a kernel, and pages can evade it. We say so, because triage tools should be honest. Link Detonator." |

## Rules for the recording

- Never show a verdict the system did not produce. If the agent is not ready, show the `pending` state and say so.
- Use only rows the rehearsal really produced. If a row reads `not_observed` or `failed`, fix the cause or show it as it is.
- Do not edit the footage in a way that hides a failure or implies a speed the system does not have. Say so if you cut waiting time.
- Do not call a `blocked_locally` result a firewall block.

## If something breaks

| Problem | Fallback |
|---|---|
| A live scan fails during recording | Open the report from the rehearsal and say it is a recorded run |
| `private_network` is not `contained` | Check the firewall first: `deploy/firewall.sh --check`. Then read the row's errors against `verify_sandbox.sh`. Do not record until the cause is known |
| HTTPS or the certificate fails | Check that ports 80 and 443 are open, including any Vultr firewall group. `journalctl -u caddy` shows the reason |
