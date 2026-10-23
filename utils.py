"""Shared utilities: activity log (persisted) and risk formatting."""
import json
import os
import time

LOG_FILE = os.path.join(os.path.dirname(__file__), "data", "activity_log.json")


def _ensure():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


def add_log(entry: dict):
    _ensure()
    logs = get_logs()
    entry = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), **entry}
    logs.append(entry)
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(logs[-500:], f, indent=2)
    return entry


def get_logs():
    _ensure()
    if not os.path.exists(LOG_FILE):
        return []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


RISK_STYLE = {
    "MINIMAL": ("#22c55e", "🟢"),
    "LOW": ("#84cc16", "🟢"),
    "MEDIUM": ("#f59e0b", "🟡"),
    "HIGH": ("#ef4444", "🔴"),
    "CRITICAL": ("#dc2626", "🔴"),
}


def risk_badge(risk: str) -> str:
    color, icon = RISK_STYLE.get(risk.upper(), ("#94a3b8", "⚪"))
    return f'<span class="risk-badge" style="background:{color}1A;color:{color};border:1px solid {color}66">{icon} {risk.upper()}</span>'


def risk_score_html(score: int, risk: str) -> str:
    color, _ = RISK_STYLE.get(risk.upper(), ("#94a3b8", ""))
    return f"""
    <div class="score-ring" style="--c:{color};--p:{score}">
      <div class="score-inner"><b>{score}</b><small>/100 risk</small></div>
    </div>"""
