"""Transparent, locally-implemented URL safety analysis for CyberSafe Alexa+."""
from urllib.parse import urlparse
import ipaddress
import re

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".link", ".zip", ".mov"}
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "banking", "signin", "confirm",
    "password", "wallet", "claim", "free", "winner", "suspended", "unlock", "invoice",
]
BRAND_KEYWORDS = ["amazon", "paypal", "apple", "netflix", "microsoft", "google", "facebook", "chase", "wellsfargo"]


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def analyze_url(url: str) -> dict:
    """Run a battery of transparent heuristic checks against a URL."""
    checks = []
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url  # parse leniently; we report missing scheme separately
        checks.append({"name": "Scheme present", "ok": False,
                       "detail": "No http:// or https:// prefix supplied. Assume untrusted until verified."})
    try:
        parsed = urlparse(url)
    except Exception:
        return {"score": 100, "risk": "CRITICAL", "verdict": "Unparseable URL",
                "checks": [], "advice": ["Do not visit this URL — it cannot be safely analyzed."]}

    host = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    full = url.lower()

    def add(name, ok, detail):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    # 1. HTTPS
    add("Uses HTTPS", parsed.scheme == "https",
        f"Scheme is '{parsed.scheme}'. HTTPS encrypts traffic; HTTP sends it in plaintext.")

    # 2. IP literal
    add("Not an IP address", not _is_ip(host),
        "Host is a raw IP address" if _is_ip(host) else f"Host '{host}' is a domain name.")

    # 3. Domain reputation signals: TLD
    tld = "." + host.rsplit(".", 1)[-1] if "." in host else ""
    add("Common/reputable TLD", tld not in SUSPICIOUS_TLDS,
        f"TLD '{tld}' is frequently abused by phishers." if tld in SUSPICIOUS_TLDS
        else f"TLD '{tld or 'unknown'}'.")

    # 4. Punycode / homoglyph
    add("No punycode/homoglyphs", "xn--" not in host,
        "Domain uses punycode (xn--), which can hide look-alike characters." if "xn--" in host
        else "Domain appears to use standard characters.")

    # 5. '@' trick
    add("No '@' redirect trick", "@" not in full.split("//", 1)[-1].split("/", 1)[0],
        "URL contains '@' — everything before it may be a decoy username." if "@" in full else "No '@' in authority section.")

    # 6. Excessive subdomains
    subdomains = host.split(".")[:-2]
    add("Reasonable subdomain depth", len(subdomains) <= 2,
        f"{len(subdomains)} subdomain level(s): {' > '.join(subdomains) if subdomains else 'none'}."
        if len(subdomains) <= 2 else
        f"{len(subdomains)} subdomain levels (e.g. {' > '.join(subdomains[:3])}...) — a classic credential-phish pattern.")

    # 7. Hyphens imitating brands
    brand_in_host = [b for b in BRAND_KEYWORDS if b in host.replace("-", "")]
    hyphen_brand = any(b in host for b in BRAND_KEYWORDS) and "-" in host
    add("No brand-name hyphen spoofing", not hyphen_brand,
        f"Hyphenated brand look-alike detected ({', '.join(brand_in_host)})." if hyphen_brand
        else ("Brand keyword present — verify it is the real domain." if brand_in_host else "No brand spoofing pattern."))

    # 8. URL length
    add("Not abnormally long", len(url) < 75,
        f"URL is {len(url)} characters." + (" Long URLs hide the true destination in messages." if len(url) >= 75 else ""))

    # 9. Suspicious keywords
    hits = [k for k in SUSPICIOUS_KEYWORDS if k in full]
    add("No urgency/credential keywords", not hits,
        ("Contains pressure keywords: " + ", ".join(hits)) if hits else "No urgency or credential keywords found.")

    # 10. Port
    add("Standard port", parsed.port in (None, 80, 443),
        f"Non-standard port {parsed.port} in use." if parsed.port not in (None, 80, 443) else "Standard port.")

    # 11. URL shortener
    SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"]
    add("Not a link shortener", host not in SHORTENERS,
        f"Shortener '{host}' hides the final destination." if host in SHORTENERS else "Destination is visible.")

    # --- scoring ---
    weights = [15, 20, 10, 15, 20, 10, 15, 5, 10, 10, 10]
    score = sum(w for (c, w) in zip(checks, weights) if not c["ok"])
    score = min(score, 100)
    if score >= 60:
        risk, verdict = "HIGH", "Likely dangerous — do not visit"
    elif score >= 30:
        risk, verdict = "MEDIUM", "Suspicious — proceed with caution"
    elif score >= 10:
        risk, verdict = "LOW", "Some warning signs"
    else:
        risk, verdict = "MINIMAL", "No major warning signs detected"

    advice = []
    if risk in ("HIGH", "MEDIUM"):
        advice += [
            "Do not enter credentials or personal data on this page.",
            "If it claims to be a brand you use, navigate to the official site yourself instead of clicking.",
            "Report the message/link to the platform it arrived on.",
        ]
    if any("@" in c["name"] for c in checks if not c["ok"]):
        advice.append("Watch for '@' tricks: 'paypal.com@evil.tk' goes to evil.tk, not PayPal.")
    if not any(c["name"] == "Uses HTTPS" and c["ok"] for c in checks):
        advice.append("Never submit sensitive info over plain HTTP.")
    if risk == "MINIMAL":
        advice.append("Still verify the sender/context — heuristics can't catch everything.")

    return {"url": url, "host": host, "score": score, "risk": risk,
            "verdict": verdict, "checks": checks, "advice": advice}
