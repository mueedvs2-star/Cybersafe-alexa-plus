"""Smart-home security posture questionnaire and recommendations."""
QUESTIONS = [
    {
        "id": "router_password",
        "q": "Have you changed the default admin password on your router?",
        "tip": "Default router passwords are published online and are the #1 entry point to smart homes.",
    },
    {
        "id": "wifi_wpa3",
        "q": "Is your Wi-Fi secured with WPA2 or WPA3 (not WEP or open)?",
        "tip": "WEP can be cracked in minutes; WPA3 is the current standard.",
    },
    {
        "id": "firmware",
        "q": "Do your smart devices receive automatic firmware/security updates?",
        "tip": "Unpatched devices are exploited within weeks of vulnerabilities being disclosed.",
    },
    {
        "id": "iot_vlan",
        "q": "Are smart-home devices on a separate guest/IoT network from your computers?",
        "tip": "Network segmentation stops a hacked camera from reaching your laptop and files.",
    },
    {
        "id": "2fa",
        "q": "Do your smart-home accounts (Alexa, Google, vendor apps) have two-factor authentication enabled?",
        "tip": "2FA blocks attackers even if your password leaks in a breach.",
    },
    {
        "id": "unused_devices",
        "q": "Have you removed or powered off smart devices you no longer use?",
        "tip": "Every forgotten gadget is an unmonitored door into your network.",
    },
    {
        "id": "upnp",
        "q": "Is UPnP (Universal Plug and Play) disabled on your router?",
        "tip": "UPnP lets devices punch open firewall holes — malware abuses this constantly.",
    },
    {
        "id": "cameras",
        "q": "Do your cameras use strong unique passwords and current firmware?",
        "tip": "Compromised cameras are live-streamed publicly; unique passwords prevent this.",
    },
    {
        "id": "skills_apps",
        "q": "Do you review third-party Alexa skills / device permissions before enabling them?",
        "tip": "Malicious skills can phish voice commands or leak account data.",
    },
    {
        "id": "backup",
        "q": "Do you have a backup of your phone/computer that manages the smart home?",
        "tip": "Ransomware-proof backups are your last line of defense.",
    },
]

RECOMMENDATIONS = {
    "router_password": "Change your router admin password today, and disable remote admin access (WAN management).",
    "wifi_wpa3": "Log into your router and set security to WPA3 (or WPA2 if devices are older); use a long, unique passphrase.",
    "firmware": "Enable automatic updates on every device; set a monthly reminder to manually check the rest.",
    "iot_vlan": "Create a guest or IoT network in your router settings and move all smart devices to it.",
    "2fa": "Turn on 2FA for Amazon/Alexa, Google, and every device-vendor account; prefer an authenticator app.",
    "unused_devices": "Factory-reset and unplug unused smart devices; delete their apps and cloud accounts.",
    "upnp": "Disable UPnP in your router's advanced settings; forward ports manually only if truly needed.",
    "cameras": "Give every camera a unique password, enable auto-firmware updates, and cover indoor cameras when home.",
    "skills_apps": "Audit installed Alexa skills: remove ones you don't recognize, and check each skill's permissions.",
    "backup": "Set up automatic encrypted backups (e.g., cloud + external drive) for phones and computers.",
}


def assess(answers: dict) -> dict:
    """answers: {question_id: bool}. Returns score, risk, and tailored advice."""
    total = len(QUESTIONS)
    yes = sum(1 for q in QUESTIONS if answers.get(q["id"]))
    gaps = [q for q in QUESTIONS if not answers.get(q["id"])]
    score = round(100 * yes / total)
    if score >= 80:
        risk, verdict = "MINIMAL", "Strong smart-home security posture"
    elif score >= 60:
        risk, verdict = "LOW", "Good posture — a few gaps to close"
    elif score >= 40:
        risk, verdict = "MEDIUM", "Several important gaps — prioritize below"
    else:
        risk, verdict = "HIGH", "Significant exposure — act on these recommendations soon"
    return {
        "score": score, "risk": risk, "verdict": verdict,
        "answered": yes, "total": total,
        "gaps": [{"id": q["id"], "why": q["tip"], "fix": RECOMMENDATIONS[q["id"]]} for q in gaps],
    }
