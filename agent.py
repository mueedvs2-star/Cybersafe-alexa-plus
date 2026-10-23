"""Simulated agentic workflow: interpret -> plan -> select tool -> execute -> explain."""
import re
from tools.url_checker import analyze_url
from tools.email_checker import analyze_message
from tools.smarthome import assess, QUESTIONS

GREETINGS = {"hello", "hi", "hey", "good morning", "good afternoon", "good evening", "howdy"}

INTENT_PATTERNS = [
    ("url_check", [
        r"\bcheck\b.*\b(url|link|website|site)\b", r"\bis\b.*\b(link|url|site)\b.*\bsafe",
        r"\bphishing link\b", r"\bscan\b.*\blink", r"\bverify\b.*\burl", r"\bthis\b.*\b(link|url)\b",
    ]),
    ("email_check", [
        r"\b(email|e-mail|message|text|sms|dm)\b.*\b(suspicious|scam|phish|check|analyze|weird|real|fake)\b",
        r"\bis\b.*\b(email|message)\b.*\b(scam|phishing|real|legit)",
        r"\bphishing email\b", r"\banalyze\b.*\b(email|message)",
        r"\bdear (user|customer|valued|account holder|sir/madam)\b",
        r"\byou'?ve (won|been selected)\b", r"\bclaim your\b",
        r"\byour account (has been|will be) (suspended|closed)\b",
        r"\bverify your account\b",
    ]),
    ("smarthome", [
        r"\bsmart.?home\b", r"\balexa\b.*\b(secur|safe|protect)\b", r"\brouter\b", r"\bwifi\b",
        r"\bcamera\b.*\b(secur|safe)\b", r"\biot\b", r"\bdevice\b.*\b(secur|safe)\b", r"\bprotect\b.*\bhome\b",
        r"\bchecklist\b", r"\brecommend\b.*\b(secur|device|home)\b",
    ]),
    ("password_check", [
        r"\bpassword\b.*\b(strong|check|test|safe)\b", r"\bis\b.*\bpassword\b.*\b(strong|safe|good)\b",
    ]),
    ("help", [r"\bhelp\b", r"\bwhat can you do\b", r"\bhow do you work\b", r"\bcommands?\b", r"\babilities\b"]),
]

TOOL_FOR_INTENT = {
    "url_check": "URL Safety Analyzer (heuristic engine)",
    "email_check": "Message Phishing Detector (heuristic engine)",
    "smarthome": "Smart-Home Security Advisor (questionnaire engine)",
    "password_check": "Password Strength Estimator (local estimator)",
}


def extract_url(text: str):
    m = re.search(r"(?:https?://)?[\w.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?", text)
    return m.group(0) if m else None


def classify_intent(text: str) -> str:
    t = text.strip().lower()
    if t in GREETINGS:
        return "greeting"
    for intent, patterns in INTENT_PATTERNS:
        if any(re.search(p, t) for p in patterns):
            return intent
    if re.search(r"https?://\S+", text):
        # Long paste with a link = likely a message being shared, unless the user
        # explicitly frames it as a URL/link question.
        if len(text.split()) > 25 and not re.search(r"\b(check|is|scan|verify).{0,20}\b(url|link|website|site)\b", t):
            return "email_check"
        return "url_check"
    if len(text.split()) > 25:
        return "email_check"
    return "general"


def plan(intent: str, text: str) -> list:
    steps = [f"🔎 Interpreted intent as **{intent.replace('_', ' ')}**"]
    if intent in TOOL_FOR_INTENT:
        steps.append(f"🧰 Selected tool: **{TOOL_FOR_INTENT[intent]}**")
    if intent == "url_check" and extract_url(text):
        steps.append(f"🎯 Extracted target: `{extract_url(text)}`")
    steps.append("⚙️ Executing transparent local analysis (no data leaves this app)")
    steps.append("🗣️ Composing plain-language explanation with advice")
    return steps


# --- local password estimator (transparent zxcvbn-lite) ---
COMMON_PASSWORDS = {"password", "123456", "12345678", "qwerty", "abc123", "letmein", "iloveyou",
                    "dragon", "monkey", "football", "sunshine", "admin", "welcome", "master"}
def estimate_password(pw: str) -> dict:
    import math
    score = 0
    notes = []
    if pw.lower() in COMMON_PASSWORDS:
        return {"score": 0, "risk": "HIGH", "verdict": "This is one of the most common passwords in the world — change it now.",
                "checks": [], "advice": ["Use a unique passphrase of 4+ random words, or a password manager."]}
    if len(pw) >= 12: score += 2
    elif len(pw) >= 8: score += 1
    else: notes.append("Too short — aim for at least 12 characters.")
    if re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw): score += 1
    else: notes.append("Mix upper and lower case letters.")
    if re.search(r"\d", pw): score += 1
    else: notes.append("Add numbers.")
    if re.search(r"[^A-Za-z0-9]", pw): score += 1
    else: notes.append("Add symbols (!, #, $...).")
    if re.search(r"(.)\1\1", pw): score -= 1; notes.append("Avoid repeated characters.")
    if re.search(r"^(19|20)\d{2}$", pw[-4:] or ""): score -= 1; notes.append("Avoid years at the end.")
    score = max(0, min(score, 5))
    strength = score / 5
    guesses = 26 ** len(pw) if pw.isalpha() else (94 ** len(pw))
    entropy = round(len(pw) * math.log2(94 if re.search(r"[^A-Za-z0-9]", pw) else (62 if re.search(r"\d", pw) else 52)), 1)
    if score <= 1:
        risk, verdict = "HIGH", "Weak password — easily cracked"
    elif score <= 3:
        risk, verdict = "MEDIUM", "Moderate password — could be stronger"
    else:
        risk, verdict = "MINIMAL", "Strong password"
    return {"score": round((1 - strength) * 100), "risk": risk, "verdict": verdict,
            "checks": [{"name": n, "ok": False, "detail": n} for n in notes],
            "advice": ["Never reuse this password across sites.", "Turn on 2FA wherever it is offered."],
            "entropy_bits": entropy}


def run_agent(text: str, smarthome_answers: dict | None = None) -> dict:
    """Full simulated agentic loop. Returns conversation payload."""
    intent = classify_intent(text)
    steps = plan(intent, text)
    result = {"intent": intent, "steps": steps, "tool": TOOL_FOR_INTENT.get(intent), "result": None,
              "explanation": "", "advice": [], "risk": None, "score": None}

    if intent == "url_check":
        url = extract_url(text)
        if not url:
            result["explanation"] = "I'd be happy to check a link — please paste the URL you want analyzed."
            return result
        r = analyze_url(url)
        result.update(result=r, risk=r["risk"], score=r["score"], advice=r["advice"])
        flags = [c for c in r["checks"] if not c["ok"]]
        result["explanation"] = (
            f"I ran 11 transparent checks on **{r['host']}**. "
            f"**Verdict: {r['verdict']}** — risk score {r['score']}/100."
            + (f" {len(flags)} check(s) raised flags." if flags else " No flags were raised.")
        )
    elif intent == "email_check":
        r = analyze_message(text)
        result.update(result=r, risk=r["risk"], score=r["score"], advice=r["advice"])
        flags = [c for c in r["checks"] if not c["ok"]]
        result["explanation"] = (
            f"I analyzed the message against 9 phishing indicators. "
            f"**Verdict: {r['verdict']}** — risk score {r['score']}/100."
            + (f" {len(flags)} indicator(s) triggered." if flags else " Nothing suspicious detected.")
        )
    elif intent == "password_check":
        m = re.search(r"password(?:\s+(?:is|:|=))?\s*[\"'`]?([A-Za-z0-9!@#$%^&*()\-+=]{3,})", text, re.I)
        pw = m.group(1) if m else text.split()[-1]
        r = estimate_password(pw)
        result.update(result=r, risk=r["risk"], score=r["score"], advice=r["advice"])
        result["explanation"] = (
            f"I estimated the strength of that password locally (~{r.get('entropy_bits', 0)} bits of entropy). "
            f"**Verdict: {r['verdict']}**."
        )
    elif intent == "smarthome":
        if smarthome_answers:
            r = assess(smarthome_answers)
            result.update(result=r, risk=r["risk"], score=100 - r["score"], advice=[g["fix"] for g in r["gaps"]])
            result["explanation"] = (
                f"Based on your answers, your smart-home security scores **{r['score']}/100**. "
                f"**{r['verdict']}** — {len(r['gaps'])} area(s) need attention."
            )
        else:
            result["explanation"] = (
                "I can give you tailored smart-home security recommendations. "
                "Open the **🏠 Smart Home** tab and answer the 10-question checklist — "
                "then ask me to 'check my smart home security' here."
            )
    elif intent == "greeting":
        result["explanation"] = (
            "👋 Hello! I'm **CyberSafe Alexa+**, your interactive cybersecurity assistant. "
            "I can: 🔗 check URLs for warning signs, 📧 analyze suspicious emails/messages, "
            "🔑 estimate password strength, and 🏠 audit your smart-home security. What would you like to do?"
        )
    elif intent == "help":
        result["explanation"] = (
            "**What I can do:**\n"
            "- `check this url: http://...` — URL safety analysis (11 transparent checks)\n"
            "- Paste any suspicious email/message — phishing indicator analysis\n"
            "- `is my password Str0ng!Pass good?` — local strength estimate\n"
            "- `smart home security` — opens recommendations, then assess your checklist answers\n\n"
            "Everything runs locally in this app — no data is sent anywhere."
        )
    else:
        result["explanation"] = (
            "I'm specialized in cybersecurity tasks. Try asking me to **check a URL**, "
            "**analyze a suspicious email**, **rate a password**, or **audit your smart-home security**. "
            "Type `help` for examples."
        )
    return result
