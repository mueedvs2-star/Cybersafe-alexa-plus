# 🛡️ CyberSafe Alexa+

**An interactive cybersecurity assistant with a simulated agentic workflow** — built with Python + Streamlit for the **Amazon Developer Hackathon 2026**.

> ⚠️ Independent prototype. Not an official Amazon Alexa+ integration, not affiliated with or endorsed by Amazon.

---

## ✨ Features

| Feature | What it does |
|---|---|
| 💬 **Conversational Assistant** | Plain-language requests → intent interpretation → tool selection → analysis → explanation (visible agentic workflow trace in every answer) |
| 🔗 **URL Checker** | 11 transparent heuristics: HTTPS, IP literals, punycode/homoglyphs, abused TLDs, `@` tricks, subdomain depth, brand hyphen-spoofing, length, urgency keywords, non-standard ports, link shorteners |
| 📧 **Email/Message Analyzer** | 9 phishing indicators: urgency pressure, credential requests, generic greetings, prize bait, risky attachments, brand impersonation, link-domain mismatch, sender anomalies, scam-typo patterns |
| 🔑 **Password Estimator** | Local entropy/strength estimate — nothing is sent anywhere |
| 🏠 **Smart-Home Security Advisor** | 10-question checklist → posture score + prioritized, actionable fixes (router, Wi-Fi, IoT VLAN, 2FA, UPnP, cameras, skills…) |
| 📋 **Activity Log** | Every analysis persisted locally to `data/activity_log.json` |
| 📊 **Dashboard** | Risk trend, activity by page, risk distribution |

**Privacy-first:** every check is implemented locally and transparently — no external API calls, no data leaves the app.

## 🚀 Run locally (Windows / VS Code)

```bash
# 1. Clone
git clone https://github.com/<you>/cybersafe-alexa-plus.git
cd cybersafe-alexa-plus

# 2. Create a virtual environment
py -m venv .venv
.venv\Scripts\activate

# 3. Install & run
pip install -r requirements.txt
streamlit run app.py
```

The app opens at `http://localhost:8501`.

## 🧠 The agentic workflow (simulated, transparent)

```
user text
   │
   ▼
Intent Interpreter  (regex routing: url_check / email_check / password_check / smarthome / help)
   │
   ▼
Planner             (builds a visible step plan, selects the registered tool)
   │
   ▼
Tool Executor       (runs the local heuristic engine for that tool)
   │
   ▼
Explainer           (plain-language verdict, risk badge, score ring, prioritized advice)
```

Each assistant reply includes an expandable **workflow trace** so users (and judges) can see exactly how the agent interpreted → planned → executed.

## 🗂️ Project structure

```
cybersafe-alexa-plus/
├── app.py                  # Streamlit UI (6 pages)
├── agent.py                # Simulated agent: intent → plan → tool → explain
├── utils.py                # Activity log + risk formatting
├── tools/
│   ├── url_checker.py      # 11-check URL heuristics
│   ├── email_checker.py    # 9-indicator phishing analysis
│   └── smarthome.py        # Smart-home questionnaire + recommendations
├── assets/style.css        # Dark, polished theme
├── data/                   # activity_log.json (created at runtime, gitignored)
├── requirements.txt
└── README.md
```

## 🏆 Devpost

See `DEVPOST.md` for the ready-to-paste project description.

## 📜 License

MIT — see `LICENSE`. All security checks are transparent heuristics for education; they are **advisory, not guarantees**.
