# Demo video script

Target length **3:45**, under the 4-minute limit. Everything on screen is live at https://185.92.220.83.sslip.io and uses only built-in test pages, so no real brand or hostile site appears.

**Rule:** narrate only what the screen shows. AI wording varies a little between runs, so read the verdict that is actually on screen; never script its exact words.

## Before recording (10 minutes)

1. Run these once, about 10 minutes before recording, and keep each report open in its own tab. They are the fallback if anything is slow live.
   - Home page, then **Run the Gauntlet**. Keep that report tab.
   - Home page, **Decode a QR image** with `demo/qr/1-fake-bank-login.png`, then **Investigate this link**. Keep that report tab; it usually shows a denied agent action.
2. Open https://185.92.220.83.sslip.io/benchmark in a tab.
3. Browser zoom 110 to 125 percent, a window about 1280 by 800, notifications off.
4. Have `demo/qr/4-cloud-metadata-refused.png` ready to upload.

## Script

| Time | Screen | Say (roughly) |
|---|---|---|
| 0:00 to 0:20 | Home page, top | "AI agents are starting to browse the web for us. But a web page can attack the agent itself: hidden instructions, fake logins, requests to internal servers. Link Detonator is an AI agent built to investigate hostile links without trusting them." |
| 0:20 to 0:40 | Scroll to the three steps | "It works in three steps. The link opens in a throwaway browser in a container behind a firewall, on Vultr. The AI reads the evidence and proposes, but a rule engine decides what may run. The model cannot grant itself anything. And every claim in the report is tied to recorded evidence." |
| 0:40 to 1:30 | Click **Run the Gauntlet**. Let the Blast Radius fill | "This test page attacks the agent several ways at once. Watch: it tried to reach private networks and the cloud metadata service, and the firewall blocked it; you can see the real browser error. It started a download, which was never kept. It froze the browser, and the sandbox survived. And it hid instructions aimed at the AI, which we extracted." |
| 1:30 to 2:05 | Scroll to the top: the red verdict and the tally | "The verdict comes from Vultr Serverless Inference. Read the summary and confidence on screen. Note it calls the hidden instructions an attack instead of obeying them. The tally shows what was detected, what the rules denied and what the sandbox contained." |
| 2:05 to 2:25 | Scroll to Sandbox destroyed and Secrets | "Two facts the AI does not get to claim: the host verified the container no longer exists, and checked that none of our secrets, including the AI key, were inside it." |
| 2:25 to 2:55 | QR: decode `1-fake-bank-login.png`, then switch to its prepared report | "Phishing increasingly arrives as QR codes. The image is decoded in a container with no network, and nothing opens until I click. Here is the result: a malicious credential-harvesting page. And here the agent asked to follow the attacker's link, and the rule engine denied it. That is the containment moment: the page tries to steer the AI, but the AI does not control its own boundaries." |
| 2:55 to 3:10 | Upload `4-cloud-metadata-refused.png` | "This QR points at the cloud metadata address, a classic way to steal cloud credentials. It is refused before anything runs, and the firewall would block it anyway." |
| 3:10 to 3:35 | `/benchmark` page, the comparison table first | "Does this matter? Same model, same pages, without our layers: in every run it called one or two attacks safe, including a page that simply told it to. With Link Detonator: none. Eleven of eleven attacks detected, no false alarms. We publish every run, including the failures." |
| 3:35 to 3:45 | Home page or README | "Link Detonator: built for security teams who triage suspicious links and QR codes. Evidence over claims. Code, live demo and verification evidence are linked in the submission." |

## Optional phone shot (15 seconds, recorded separately)

On a phone, open the live app, tap **Scan with camera** and photograph `demo/qr/1-fake-bank-login.png` on your laptop screen. Show the decoded link, then tap **Investigate this link**. Say: "Same flow on a phone: point, decode in a sandbox, investigate." Real-world QR codes contain live links, which need the access code.

## If something goes wrong live

- **Scan slow or the AI unavailable:** switch to the prepared report tab and say "here is the same scan from a few minutes ago".
- **Rate limit message:** wait one minute, or use the prepared tab.
- **Verdict different from expected:** read what is on screen. Variation between runs is real, and the benchmark page shows it honestly.

## Numbers to quote

Use the figures on the `/benchmark` page at recording time. Do not quote numbers from memory.
