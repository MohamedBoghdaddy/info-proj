"""
AI Cyber Defense Lab — FastAPI Backend
Merges rule-based detection with ML model outputs.
Structured for future LLM API integration (add llm_analysis field alongside).
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime

from detectors import detect_prompt_injection, detect_phishing, detect_dos
from ml_models import classify_prompt_injection, classify_phishing, classify_dos

app = FastAPI(title="AI Cyber Defense Lab API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Request/Response Models ──────────────────────────────────────────────────

class TextInput(BaseModel):
    text: str

class ReportRequest(BaseModel):
    module: str
    result: dict


# ─── Score fusion: weighted average of rule + ML scores ───────────────────────

def _fuse_scores(rule_score: int, ml_score: int, rule_weight: float = 0.55) -> int:
    return int(rule_score * rule_weight + ml_score * (1 - rule_weight))


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.post("/api/prompt-injection")
async def analyze_prompt_injection(body: TextInput):
    rule = detect_prompt_injection(body.text)
    ml = classify_prompt_injection(body.text)

    fused_score = _fuse_scores(rule["rule_risk_score"], ml["ml_risk_score"])

    if fused_score == 0:
        final_status = "Safe"
    elif fused_score < 45:
        final_status = "Suspicious"
    else:
        final_status = "Attack"

    return {
        "status": final_status,
        "risk_score": fused_score,
        "safe_rewrite": rule["safe_rewrite"],
        "explanations": rule["explanations"],
        "matched_patterns": rule["matched_patterns"],
        "rule_analysis": {
            "status": rule["rule_status"],
            "risk_score": rule["rule_risk_score"],
        },
        "ml_analysis": {
            "label": ml["ml_label"],
            "risk_score": ml["ml_risk_score"],
            "probabilities": ml["ml_probabilities"],
            "confidence": ml["ml_confidence"],
        },
        # llm_analysis: placeholder for future OpenAI/Claude API integration
        "llm_analysis": None,
    }


@app.post("/api/phishing")
async def analyze_phishing(body: TextInput):
    rule = detect_phishing(body.text)
    ml = classify_phishing(body.text)

    fused_score = _fuse_scores(rule["rule_risk_score"], ml["ml_risk_score"])

    if fused_score < 20:
        final_label = "Benign"
    elif fused_score < 55:
        final_label = "Suspicious"
    else:
        final_label = "Phishing / Spoofing"

    return {
        "label": final_label,
        "risk_score": fused_score,
        "threat_types": rule["threat_types"],
        "explanations": rule["explanations"],
        "matched_patterns": rule["matched_patterns"],
        "recommended_action": rule["recommended_action"],
        "rule_analysis": {
            "risk_score": rule["rule_risk_score"],
            "threat_types": rule["threat_types"],
        },
        "ml_analysis": {
            "label": ml["ml_label"],
            "risk_score": ml["ml_risk_score"],
            "probabilities": ml["ml_probabilities"],
            "confidence": ml["ml_confidence"],
        },
        # llm_analysis: placeholder for future LLM integration
        "llm_analysis": None,
    }


@app.post("/api/dos")
async def analyze_dos(body: TextInput):
    rule = detect_dos(body.text)
    ml = classify_dos(body.text)

    fused_score = _fuse_scores(rule["rule_risk_score"], ml["ml_risk_score"])

    if fused_score < 20:
        threat_level = "Low"
    elif fused_score < 50:
        threat_level = "Medium"
    elif fused_score < 75:
        threat_level = "High"
    else:
        threat_level = "Critical"

    return {
        "threat_level": threat_level,
        "risk_score": fused_score,
        "attacker_ips": rule["attacker_ips"],
        "explanations": rule["explanations"],
        "matched_patterns": rule["matched_patterns"],
        "suggested_defenses": rule["suggested_defenses"],
        "request_summary": rule.get("request_summary", {}),
        "rule_analysis": {
            "risk_score": rule["rule_risk_score"],
            "attacker_ips": rule["attacker_ips"],
        },
        "ml_analysis": {
            "label": ml["ml_label"],
            "risk_score": ml["ml_risk_score"],
            "probabilities": ml["ml_probabilities"],
            "confidence": ml["ml_confidence"],
        },
        # llm_analysis: placeholder for future LLM integration
        "llm_analysis": None,
    }


@app.post("/api/report")
async def generate_report(body: ReportRequest):
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    r = body.result

    if body.module == "prompt_injection":
        threat = r.get("status", "Unknown")
        risk = r.get("risk_score", 0)
        evidence = r.get("explanations", [])
        defenses = [
            "Implement input sanitization and allowlist validation.",
            "Deploy a prompt firewall layer before LLM processing.",
            "Log and alert on suspicious prompt patterns.",
            "Use the safe rewritten prompt shown above instead of raw input.",
        ]
        summary = (
            f"Prompt injection analysis detected a '{threat}' threat with risk score {risk}/100. "
            f"{len(evidence)} attack pattern(s) identified."
        )

    elif body.module == "phishing":
        threat = r.get("label", "Unknown")
        risk = r.get("risk_score", 0)
        evidence = r.get("explanations", [])
        defenses = [
            r.get("recommended_action", "Exercise caution with this message."),
            "Enable email authentication (SPF, DKIM, DMARC).",
            "Train users to recognize urgency tactics and suspicious links.",
            "Implement email gateway filtering with ML-based detection.",
        ]
        summary = (
            f"Phishing/spoofing analysis classified message as '{threat}' with risk score {risk}/100. "
            f"Detected threat types: {', '.join(r.get('threat_types', ['None']))}."
        )

    elif body.module == "dos":
        threat = r.get("threat_level", "Unknown")
        risk = r.get("risk_score", 0)
        evidence = r.get("explanations", [])
        attacker_ips = r.get("attacker_ips", [])
        defenses_raw = r.get("suggested_defenses", [])
        defenses = [d["description"] if isinstance(d, dict) else d for d in defenses_raw]
        if attacker_ips:
            defenses.insert(0, f"Immediately block attacker IPs: {', '.join(attacker_ips[:5])}.")
        summary = (
            f"DoS analysis detected '{threat}' threat level with risk score {risk}/100. "
            f"{len(attacker_ips)} attacker IP(s) identified."
        )
    else:
        return {"error": "Unknown module"}

    return {
        "generated_at": now,
        "module": body.module,
        "summary": summary,
        "threat": threat,
        "risk_score": risk,
        "evidence": evidence,
        "recommended_defenses": defenses,
        "comparison": {
            "rule_based": r.get("rule_analysis", {}),
            "ml_based": r.get("ml_analysis", {}),
            "llm_based": r.get("llm_analysis"),
        },
    }


@app.get("/health")
async def health():
    return {"status": "ok", "service": "AI Cyber Defense Lab"}
