# Devpost submission materials — CyberSafe Alexa+

> ⚠️ Before submitting: confirm the hackathon's current submission status and eligible tracks on the official rules page. This project is an independent prototype, not an official Amazon Alexa+ integration.

## Inspiration
Smart-home adoption keeps growing, but security literacy hasn't kept pace. People receive suspicious emails and links every day and have no quick, private way to sanity-check them — and most smart-home devices ship insecure by default. We asked: *what if an Alexa-style assistant could coach anyone through digital safety, right on their own machine, with nothing sent to the cloud?*

## What it does
CyberSafe Alexa+ is an interactive cybersecurity assistant with a **simulated agentic workflow**: the user asks in plain language; the agent interprets the intent, selects the right tool from its toolbox, executes transparent local analysis, and explains the result conversationally. Tools include a URL safety analyzer (11 heuristics), a phishing detector for emails/messages (9 indicators), a local password strength estimator, and a smart-home security checklist that scores your posture and returns prioritized fixes. Every run is recorded in a local activity log, and a dashboard visualizes risk trends.

## How we built it
- **Python + Streamlit** for the app; developed in **VS Code on Windows**.
- `agent.py` implements the agentic loop: intent routing → planning → tool selection → execution → explanation, with a visible workflow trace in every reply.
- Each tool in `tools/` is a **transparent, locally implemented heuristic engine** — no black boxes, no external calls, fully auditable.
- Polished dark UI with custom CSS, risk badges, animated score rings, and charts.

## Challenges we ran into
- Intent routing ambiguity (e.g., a pasted phishing email *containing* a link). We resolved it by weighting message-context cues over raw URL matches and validating against real attack samples.
- Keeping heuristics explainable: every flag includes a human-readable reason so the app teaches, not just judges.

## Accomplishments that we're proud of
- A fully local, private security assistant anyone can run with one command.
- An agentic workflow a judge can inspect step-by-step in the UI.
- 30+ transparent checks across four tools, all with actionable advice.

## What we learned
Smart-home security is weakest at the router (default passwords, UPnP, no segmentation) — so recommendations prioritize the network layer first. We also learned how much users trust tools they can *inspect*.

## What's next
- Real AI integration (LLM intent understanding + Alexa Skills Kit) if eligibility allows
- VirusTotal/urlscan API enrichment behind an opt-in toggle
- Browser extension + mobile companion
- Family/voice-persona mode for coaching kids and seniors

## Required feedback / contact
- If Amazon judges review this: we would love feedback on whether a local-first "Alexa-coach" concept could become a real Alexa skill — especially voice UX patterns for delivering security advice conversationally.
