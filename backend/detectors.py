"""
Rule-based detectors for each security module.
Results are merged with ML model outputs in main.py.
"""
import re
from typing import Optional
from collections import Counter

# ─── Prompt Injection ────────────────────────────────────────────────────────

_PI_PATTERNS = [
    (r"ignore (all |previous |prior |above )?(instructions?|rules?|guidelines?|context)", 40, "Instruction override attempt"),
    (r"reveal (your |the )?(system |original |hidden )?prompt", 50, "System prompt extraction attempt"),
    (r"bypass (all |your )?(rules?|restrictions?|filters?|safety|guidelines?)", 45, "Safety bypass attempt"),
    (r"act as (dan|developer mode|jailbreak|god mode|evil ai|uncensored)", 60, "Role-hijacking jailbreak"),
    (r"(you are|you're) (now |no longer )?(an? )?(ai|assistant|bot|chatbot)", 30, "Identity override"),
    (r"(disable|override|remove|forget) (all |your )?(safety|restrictions?|filters?|limitations?)", 55, "Restriction removal"),
    (r"developer mode (enabled|activated|on)", 60, "Developer mode jailbreak"),
    (r"do anything now", 50, "DAN-style jailbreak"),
    (r"(jailbreak|jail break|j4ilbr34k)", 70, "Explicit jailbreak keyword"),
    (r"(system|admin|root) (prompt|access|override)", 45, "System access escalation"),
    (r"pretend (you have no|there are no) (rules?|restrictions?|limitations?)", 40, "Pretend-no-rules attack"),
    (r"(forget|disregard|ignore) (everything|what) (you (were|have been) (told|trained)|before)", 35, "Memory wipe attempt"),
]

def _sanitize_prompt(text: str) -> str:
    out = text
    for pat, _, _ in _PI_PATTERNS:
        out = re.sub(pat, "[FILTERED]", out, flags=re.IGNORECASE)
    return out

def detect_prompt_injection(text: str) -> dict:
    matched = []
    rule_score = 0
    for pat, score, desc in _PI_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            matched.append({"pattern": desc, "weight": score})
            rule_score += score

    rule_score = min(rule_score, 100)

    if rule_score == 0:
        status = "Safe"
    elif rule_score < 50:
        status = "Suspicious"
    else:
        status = "Attack"

    explanations = [m["pattern"] for m in matched]
    safe_rewrite = _sanitize_prompt(text) if matched else text

    return {
        "rule_status": status,
        "rule_risk_score": rule_score,
        "matched_patterns": matched,
        "explanations": explanations,
        "safe_rewrite": safe_rewrite,
    }


# ─── Phishing / Spoofing ─────────────────────────────────────────────────────

_PH_PATTERNS = [
    (r"(urgent|immediately|asap|right now|act now|time.sensitive)", 25, "Urgency language", "Urgency"),
    (r"(verify|confirm|validate) (your )?(account|identity|password|credentials)", 35, "Credential harvesting", "Phishing"),
    (r"(click here|click this link|click below|follow this link)", 20, "Suspicious CTA link", "Phishing"),
    (r"(your account (will be|has been) (suspended|compromised|locked|hacked))", 40, "Account threat", "Spoofing"),
    (r"(password|passwd|login credentials|pin|otp|2fa code)", 30, "Password request", "Phishing"),
    (r"(bank (account|details|transfer)|wire transfer|western union|gift card)", 40, "Financial request", "Phishing"),
    (r"(won|winner|congratulations|prize|reward|claim your|selected)", 35, "Lottery/prize scam", "Spoofing"),
    (r"(noreply@|no-reply@|[a-z0-9._%+\-]+@(?!gmail\.com|outlook\.com|yahoo\.com)[a-z0-9.\-]+\.(xyz|top|click|live|buzz|info))", 30, "Suspicious sender domain", "Spoofing"),
    (r"(irs|tax authority|government notice|legal action|lawsuit|subpoena)", 35, "Authority impersonation", "Spoofing"),
    (r"http[s]?://(?!(?:www\.)?(google|microsoft|apple|amazon|paypal|bank)\.com)[^\s]{5,}", 25, "Suspicious URL", "Phishing"),
]

_PH_THREAT_TYPES = {
    "Urgency": "Social Engineering",
    "Phishing": "Credential Phishing",
    "Spoofing": "Identity Spoofing",
}

_PH_ACTIONS = {
    0: "Message appears safe. Standard caution advised.",
    1: "Verify sender identity independently before responding.",
    2: "Do NOT click any links. Report to IT security.",
    3: "Delete immediately. Do not engage. Report as phishing.",
}

def detect_phishing(text: str) -> dict:
    matched = []
    rule_score = 0
    threat_types = set()

    for pat, score, desc, threat in _PH_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            matched.append({"pattern": desc, "threat": threat, "weight": score})
            rule_score += score
            threat_types.add(threat)

    rule_score = min(rule_score, 100)
    tier = min(rule_score // 25, 3)

    return {
        "rule_risk_score": rule_score,
        "threat_types": list(threat_types),
        "matched_patterns": matched,
        "explanations": [m["pattern"] for m in matched],
        "recommended_action": _PH_ACTIONS[tier],
    }


# ─── DoS Detection ───────────────────────────────────────────────────────────

_DOS_UA_PATTERNS = [
    r"python-requests", r"curl/", r"wget/", r"scrapy", r"sqlmap",
    r"nikto", r"nmap", r"masscan", r"zgrab", r"go-http-client",
    r"libwww-perl", r"perl", r"java/", r"jakarta", r"bot[^a-z]",
    r"crawler", r"spider", r"headless", r"phantomjs", r"selenium",
]

_DOS_PATH_PATTERNS = [
    r"/admin", r"/wp-login", r"/phpmyadmin", r"\.env",
    r"/\.git", r"/api/v\d+/auth", r"/login", r"/passwd",
]

def parse_traffic_logs(raw: str) -> list[dict]:
    entries = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        ip_match = re.search(r'\b(\d{1,3}\.){3}\d{1,3}\b', line)
        ip = ip_match.group(0) if ip_match else "unknown"
        method_match = re.search(r'\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\b', line, re.IGNORECASE)
        method = method_match.group(0).upper() if method_match else "GET"
        status_match = re.search(r'\b([2345]\d{2})\b', line)
        status = int(status_match.group(0)) if status_match else 200
        path_match = re.search(r'\s(/[^\s]*)', line)
        path = path_match.group(1) if path_match else "/"
        entries.append({"ip": ip, "method": method, "status": status, "path": path, "raw": line})
    return entries

def detect_dos(raw_logs: str) -> dict:
    entries = parse_traffic_logs(raw_logs)
    if not entries:
        return {
            "rule_risk_score": 0,
            "attacker_ips": [],
            "matched_patterns": [],
            "explanations": [],
            "suggested_defenses": [],
        }

    ip_counts = Counter(e["ip"] for e in entries)
    total = len(entries)
    matched = []
    attacker_ips = set()
    rule_score = 0
    defenses = set()

    # High request frequency from single IP
    for ip, count in ip_counts.items():
        ratio = count / total if total > 0 else 0
        if count >= 5 or ratio > 0.6:
            matched.append({"pattern": f"High request frequency from {ip} ({count} requests)", "weight": 35})
            attacker_ips.add(ip)
            rule_score += 35
            defenses.add("Rate Limiting")
            defenses.add("IP Blocking")

    # Suspicious user agents
    for e in entries:
        for pat in _DOS_UA_PATTERNS:
            if re.search(pat, e["raw"], re.IGNORECASE):
                matched.append({"pattern": f"Suspicious user-agent in request from {e['ip']}", "weight": 25})
                attacker_ips.add(e["ip"])
                rule_score += 25
                defenses.add("WAF Rule")
                defenses.add("CAPTCHA")
                break

    # Repeated 4xx/5xx errors (brute force / scan)
    error_ips = Counter(e["ip"] for e in entries if e["status"] in range(400, 600))
    for ip, cnt in error_ips.items():
        if cnt >= 3:
            matched.append({"pattern": f"Repeated error responses ({cnt}x 4xx/5xx) from {ip}", "weight": 30})
            attacker_ips.add(ip)
            rule_score += 30
            defenses.add("IP Blocking")
            defenses.add("WAF Rule")

    # Sensitive path scanning
    for e in entries:
        for pat in _DOS_PATH_PATTERNS:
            if re.search(pat, e["path"], re.IGNORECASE):
                matched.append({"pattern": f"Sensitive path probe: {e['path']} from {e['ip']}", "weight": 20})
                attacker_ips.add(e["ip"])
                rule_score += 20
                defenses.add("WAF Rule")
                break

    rule_score = min(rule_score, 100)

    defense_details = {
        "Rate Limiting": "Limit requests per IP to 100/min using token bucket algorithm.",
        "IP Blocking": "Block identified attacker IPs at firewall/load-balancer level.",
        "CAPTCHA": "Require CAPTCHA for suspicious or high-frequency sessions.",
        "WAF Rule": "Add WAF rules to block known malicious user-agents and path scans.",
    }

    return {
        "rule_risk_score": rule_score,
        "attacker_ips": sorted(attacker_ips),
        "matched_patterns": matched[:10],
        "explanations": [m["pattern"] for m in matched[:10]],
        "suggested_defenses": [
            {"name": d, "description": defense_details[d]} for d in defenses
        ],
        "request_summary": {
            ip: count for ip, count in ip_counts.most_common(10)
        },
    }
