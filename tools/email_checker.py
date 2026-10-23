"""Locally-implemented phishing/suspicion heuristics for emails and messages."""
import re

URGENCY = ["urgent", "immediately", "within 24 hours", "act now", "expires", "final notice",
           "account will be closed", "suspended", "last warning", "verify now"]
CREDENTIAL = ["verify your account", "confirm your password", "update payment", "log in to",
              "sign in to", "validate your", "enter your", "ssn", "social security"]
GREETING_GENERIC = ["dear customer", "dear user", "dear valued", "dear account holder", "hello dear", "dear sir/madam"]
PRIZE = ["you have won", "congratulations", "claim your prize", "lottery", "winner", "free gift",
         "you've been selected", "no purchase necessary"]
ATTACHMENT_RISK = [".exe", ".scr", ".bat", ".msi", ".jar", ".zip", ".iso", ".hta", ".ps1"]
IMPERSONATION = ["amazon", "paypal", "apple", "microsoft", "netflix", "irs", "bank", "fedex", "usps", "dhl"]


def _find(text, keywords):
    t = text.lower()
    return [k for k in keywords if k in t]


def analyze_message(text: str, sender: str = "") -> dict:
    checks = []

    def add(name, ok, detail):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    urg = _find(text, URGENCY)
    add("No urgency/pressure language", not urg,
        "Pressure phrases found: " + ", ".join(urg[:4]) if urg else "No pressure tactics detected.")

    cred = _find(text, CREDENTIAL)
    add("No credential requests", not cred,
        "Asks for credentials/payment info: " + ", ".join(cred[:4]) if cred
        else "No explicit credential requests.")

    greet = _find(text, GREETING_GENERIC)
    add("Personalized greeting", not greet,
        "Generic greeting: '" + greet[0] + "'" if greet else "Appears personally addressed.")

    prize = _find(text, PRIZE)
    add("No prize/lottery bait", not prize,
        "Prize bait detected: " + ", ".join(prize[:3]) if prize else "No prize/lottery bait.")

    att = re.findall(r"\b[\w.-]+\.(?:exe|scr|bat|msi|jar|zip|iso|hta|ps1)\b", text, re.I)
    add("No risky attachments", not att,
        "Risky attachment referenced: " + ", ".join(set(a.lower() for a in att)) if att
        else "No risky attachment types referenced.")

    imp = _find(text, IMPERSONATION) or _find(sender, IMPERSONATION)
    add("No brand impersonation", not imp,
        "Impersonates: " + ", ".join(sorted(set(imp))[:4]) if imp else "No brand-impersonation keywords.")

    links = re.findall(r"https?://[^\s)>'\"]+", text)
    mismatched = []
    for ln in links:
        m = re.search(r"https?://([^/\s]+)", ln)
        if m and imp and not any(b in m.group(1).lower() for b in imp):
            mismatched.append(ln)
    add("Links match claimed sender", not mismatched,
        "Links point to domains unrelated to the claimed sender: " + "; ".join(mismatched[:3]) if mismatched
        else ("No links, or links are consistent." if not links else f"{len(links)} link(s) found; domains look consistent."))

    sender_flags = []
    s = sender.lower()
    if re.search(r"\d{4,}", s):
        sender_flags.append("many digits in address")
    if re.search(r"(no-?reply|donotreply)", s) and any(k in text.lower() for k in ["verify", "update", "suspended"]):
        sender_flags.append("'no-reply' sender demanding action")
    if s and not s.endswith((".com", ".org", ".net", ".gov", ".edu", ".io")):
        sender_flags.append("uncommon sender TLD")
    add("Sender address looks normal", not sender_flags, "; ".join(sender_flags) if sender_flags
        else (f"Sender '{sender}'." if sender else "No sender provided."))

    grammar = len(re.findall(r"\b(teh|recieve|seperate|occured|definately|accomodate)\b", text.lower()))
    add("No obvious typos", grammar == 0,
        f"{grammar} common scam-typo pattern(s)." if grammar else "No common scam-typo patterns.")

    weights = [15, 20, 8, 12, 15, 10, 12, 10, 8]
    score = min(sum(w for c, w in zip(checks, weights) if not c["ok"]), 100)
    if score >= 60:
        risk, verdict = "HIGH", "Very likely phishing — do not interact"
    elif score >= 30:
        risk, verdict = "MEDIUM", "Suspicious — verify before acting"
    elif score >= 10:
        risk, verdict = "LOW", "Minor warning signs"
    else:
        risk, verdict = "MINIMAL", "Looks normal, stay alert"

    advice = []
    if risk in ("HIGH", "MEDIUM"):
        advice += [
            "Do not click links or open attachments in this message.",
            "Verify via a known channel: call the company using the number on their official site.",
            "Report as phishing (Gmail: three-dot menu → Report phishing; Outlook: Report button).",
        ]
    if cred:
        advice.append("Legitimate companies never ask for passwords or full card numbers by email.")
    if not advice:
        advice.append("When in doubt, contact the sender through a known, separate channel.")

    return {"score": score, "risk": risk, "verdict": verdict, "checks": checks,
            "advice": advice, "link_count": len(links)}
