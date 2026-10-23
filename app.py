import streamlit as st
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent import run_agent
from tools.url_checker import analyze_url
from tools.email_checker import analyze_message
from tools.smarthome import QUESTIONS, assess
from utils import add_log, get_logs, risk_badge, risk_score_html

st.set_page_config(page_title="CyberSafe Alexa+", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

# ---------------- CSS ----------------
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "style.css")) as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# ---------------- Session state ----------------
for k, v in [("chat", []), ("sm_answers", {}), ("last_assessment", None)]:
    if k not in st.session_state:
        st.session_state[k] = v

# ---------------- Sidebar ----------------
with st.sidebar:
    st.markdown("## 🛡️ CyberSafe Alexa+")
    st.caption("Interactive cybersecurity assistant — Amazon Developer Hackathon 2026")
    st.divider()
    page = st.radio("Navigate", ["💬 Assistant", "🔗 URL Checker", "📧 Email / Message Analyzer",
                                 "🏠 Smart-Home Security", "📋 Activity Log", "📊 Dashboard"])
    st.divider()
    st.markdown("**Agentic workflow status**")
    st.success("● Local engine online\n● 4 tools registered\n● 0 external calls")
    st.caption("Independent prototype — not an official Amazon Alexa+ integration.")

st.title("🛡️ CyberSafe Alexa+")

# =========================================================== ASSISTANT
if page == "💬 Assistant":
    st.caption("Ask in plain language — I'll interpret your request, select the right security tool, run it, and explain the results.")
    c1, c2, c3 = st.columns(3)
    if c1.button("🔍 Example: check a URL"):
        st.session_state["prompt"] = "check this url: http://paypal-secure.login-verify.tk/update/password"
    if c2.button("📧 Example: suspicious email"):
        st.session_state["prompt"] = ("Dear Customer, your Amazon account has been suspended. "
                                      "Verify your account within 24 hours at http://amazon-login-secure.top "
                                      "or your account will be closed permanently.")
    if c3.button("🏠 Example: smart home audit"):
        st.session_state["prompt"] = "can you check my smart home security and give me recommendations?"

    for msg in st.session_state.chat:
        with st.chat_message(msg["role"], avatar="🧑" if msg["role"] == "user" else "🛡️"):
            st.markdown(msg["content"], unsafe_allow_html=True)
            if msg["role"] == "assistant" and msg.get("steps"):
                with st.expander("🧠 View agentic workflow trace"):
                    for s in msg["steps"]:
                        st.markdown(f"- {s}")
            if msg["role"] == "assistant" and msg.get("checks"):
                with st.expander("🔬 Detailed check results"):
                    for c in msg["checks"]:
                        icon = "✅" if c["ok"] else "⚠️"
                        st.markdown(f"{icon} **{c['name']}** — {c['detail']}")
            if msg["role"] == "assistant" and msg.get("risk"):
                st.markdown(risk_badge(msg["risk"]), unsafe_allow_html=True)

    prompt = st.chat_input("e.g. 'is this link safe: http://bit.ly/3xK9sT2' or paste a suspicious email…")
    if "prompt" in st.session_state:
        prompt = st.session_state.pop("prompt")

    if prompt:
        st.session_state.chat.append({"role": "user", "content": prompt})
        with st.chat_message("user", avatar="🧑"):
            st.markdown(prompt)
        with st.chat_message("assistant", avatar="🛡️"):
            with st.spinner("Interpreting → planning → selecting tool → executing…"):
                r = run_agent(prompt, st.session_state.sm_answers)
            st.markdown(r["explanation"], unsafe_allow_html=True)
            checks = (r.get("result") or {}).get("checks") if r.get("result") else None
            if r.get("risk"):
                colA, colB = st.columns([1, 4])
                colA.markdown(risk_score_html(r.get("score") or 0, r["risk"]), unsafe_allow_html=True)
                colB.markdown(risk_badge(r["risk"]), unsafe_allow_html=True)
            if r.get("steps"):
                with st.expander("🧠 View agentic workflow trace"):
                    for s in r["steps"]:
                        st.markdown(f"- {s}")
            if checks:
                with st.expander("🔬 Detailed check results"):
                    for c in checks:
                        st.markdown(f"{'✅' if c['ok'] else '⚠️'} **{c['name']}** — {c['detail']}")
            if r.get("advice"):
                st.markdown("**📌 Recommended actions:**")
                for a in r["advice"]:
                    st.markdown(f"- {a}")
            st.session_state.chat.append({"role": "assistant", "content": r["explanation"],
                                          "risk": r.get("risk"), "steps": r.get("steps"), "checks": checks})
            add_log({"page": "assistant", "intent": r["intent"], "input": prompt[:200],
                     "risk": r.get("risk"), "score": r.get("score")})

# =========================================================== URL CHECKER
elif page == "🔗 URL Checker":
    st.subheader("URL Safety Analyzer")
    st.caption("11 transparent heuristics — HTTPS, IP literals, punycode, TLD reputation, '@' tricks, link shorteners, and more.")
    url = st.text_input("Paste a URL:", placeholder="https://example.com/login")
    if st.button("Analyze", type="primary") and url:
        r = analyze_url(url)
        add_log({"page": "url", "input": url[:200], "risk": r["risk"], "score": r["score"]})
        c1, c2 = st.columns([1, 3])
        c1.markdown(risk_score_html(r["score"], r["risk"]), unsafe_allow_html=True)
        c2.markdown(f"### {r['verdict']}\n**Host:** `{r['host']}`  \n" + risk_badge(r["risk"]), unsafe_allow_html=True)
        st.markdown("#### Checks")
        for c in r["checks"]:
            st.markdown(f"{'✅' if c['ok'] else '⚠️'} **{c['name']}** — {c['detail']}")
        st.markdown("#### Advice")
        for a in r["advice"]:
            st.markdown(f"- {a}")

# =========================================================== EMAIL
elif page == "📧 Email / Message Analyzer":
    st.subheader("Phishing & Suspicious Message Detector")
    st.caption("9 indicators: urgency pressure, credential requests, generic greetings, prize bait, risky attachments, brand impersonation, link-domain mismatch, sender anomalies, and scam-typo patterns.")
    sender = st.text_input("Sender address (optional):", placeholder="support@amaz0n-secure.net")
    msg = st.text_area("Paste the full email or message:", height=200,
                       placeholder="Dear Customer, your account has been suspended…")
    if st.button("Analyze", type="primary") and msg:
        r = analyze_message(msg, sender)
        add_log({"page": "email", "input": msg[:200], "risk": r["risk"], "score": r["score"]})
        c1, c2 = st.columns([1, 3])
        c1.markdown(risk_score_html(r["score"], r["risk"]), unsafe_allow_html=True)
        c2.markdown(f"### {r['verdict']}\nLinks found: **{r['link_count']}**  \n" + risk_badge(r["risk"]), unsafe_allow_html=True)
        st.markdown("#### Indicator results")
        for c in r["checks"]:
            st.markdown(f"{'✅' if c['ok'] else '⚠️'} **{c['name']}** — {c['detail']}")
        st.markdown("#### What to do")
        for a in r["advice"]:
            st.markdown(f"- {a}")

# =========================================================== SMART HOME
elif page == "🏠 Smart-Home Security":
    st.subheader("Smart-Home Security Checklist")
    st.caption("Answer honestly — I'll score your posture and produce tailored recommendations. Answers stay local.")
    with st.form("sm_form"):
        answers = {}
        for q in QUESTIONS:
            answers[q["id"]] = st.checkbox(q["q"], help=q["tip"])
        submitted = st.form_submit_button("Assess my home", type="primary")
    if submitted:
        st.session_state.sm_answers = answers
        r = assess(answers)
        st.session_state.last_assessment = r
        add_log({"page": "smarthome", "input": f"{r['answered']}/{r['total']} yes", "risk": r["risk"], "score": r["score"]})
    if st.session_state.last_assessment:
        r = st.session_state.last_assessment
        c1, c2 = st.columns([1, 3])
        c1.markdown(risk_score_html(100 - r["score"], r["risk"]), unsafe_allow_html=True)
        c2.markdown(f"### {r['verdict']}\nYou answered **{r['answered']}/{r['total']}** practices in place.  \n"
                    + risk_badge(r["risk"]), unsafe_allow_html=True)
        if r["gaps"]:
            st.markdown("#### Priority fixes")
            for g in r["gaps"]:
                with st.expander(f"🔧 {g['fix'].split('—')[0].split('.')[0]}"):
                    st.markdown(f"**Why it matters:** {g['why']}\n\n**What to do:** {g['fix']}")
        else:
            st.success("Outstanding — every recommended practice is in place. Re-audit quarterly.")
        st.info("💡 Now ask the assistant: *'check my smart home security and give me recommendations'* to see the agentic workflow summarize this.")

# =========================================================== ACTIVITY LOG
elif page == "📋 Activity Log":
    st.subheader("Activity Log")
    st.caption("Every analysis is recorded locally (data/activity_log.json) — audit what was checked and when.")
    logs = list(reversed(get_logs()))
    c1, c2, c3 = st.columns(3)
    c1.metric("Total analyses", len(logs))
    c2.metric("High-risk findings", sum(1 for l in logs if l.get("risk") in ("HIGH", "CRITICAL")))
    c3.metric("Top risk", logs[0]["risk"] if logs else "—")
    if st.button("Clear log"):
        import json
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "activity_log.json"), "w") as f:
            json.dump([], f)
        st.rerun()
    for l in logs:
        with st.container(border=True):
            st.markdown(f"**{l['ts']}** · `{l.get('page', '?')}` · intent `{l.get('intent', '-')}` "
                        + risk_badge(l.get("risk", "MINIMAL")) + (f" · score {l['score']}" if l.get("score") is not None else ""),
                        unsafe_allow_html=True)
            st.caption(str(l.get("input", ""))[:180])

# =========================================================== DASHBOARD
else:
    st.subheader("Security Activity Dashboard")
    logs = get_logs()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Analyses run", len(logs))
    c2.metric("High-risk", sum(1 for l in logs if l.get("risk") in ("HIGH", "CRITICAL")))
    c3.metric("Medium-risk", sum(1 for l in logs if l.get("risk") == "MEDIUM"))
    c4.metric("Clean / minimal", sum(1 for l in logs if l.get("risk") in ("MINIMAL", "LOW")))
    if logs:
        import pandas as pd
        df = pd.DataFrame(logs)
        df["ts"] = pd.to_datetime(df["ts"])
        st.markdown("#### Risk trend over time")
        trend = df.set_index("ts").resample("D")["score"].mean().dropna()
        st.line_chart(trend if len(trend) > 1 else df["score"])
        st.markdown("#### Activity by page")
        st.bar_chart(df["page"].value_counts())
        st.markdown("#### Risk distribution")
        st.bar_chart(df["risk"].value_counts())
    else:
        st.info("Run some analyses and the dashboard will light up.")
