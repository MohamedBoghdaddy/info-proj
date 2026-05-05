"""
AI Cyber Defense Lab — FastAPI Backend
Merges rule-based detection with ML model outputs.
Structured for future LLM API integration (add llm_analysis field alongside).
"""
import json
import os
import re
from datetime import datetime

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

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

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or os.getenv("gemini_api_key")
GEMINI_API_BASE = os.getenv("GEMINI_API_BASE", "https://gemini.googleapis.com/v1")
GEMINI_API_MODEL = os.getenv("GEMINI_API_MODEL", "gemini-1.5-mini")
GEMINI_API_TIMEOUT = float(os.getenv("GEMINI_API_TIMEOUT", "15"))


def _fuse_scores(rule_score: int, ml_score: int, rule_weight: float = 0.55) -> int:
    return int(rule_score * rule_weight + ml_score * (1 - rule_weight))


def _extract_gemini_text(response_json: dict) -> str:
    if not isinstance(response_json, dict):
        return ''

    if "candidates" in response_json:
        candidates = response_json.get("candidates")
        if isinstance(candidates, list) and candidates:
            first = candidates[0]
            if isinstance(first, dict) and "content" in first:
                return first["content"]

    if "output" in response_json:
        output = response_json.get("output")
        if isinstance(output, list) and output:
            first = output[0]
            if isinstance(first, dict) and "content" in first:
                return first["content"]
        if isinstance(output, str):
            return output

    if "reply" in response_json and isinstance(response_json["reply"], dict):
        return response_json["reply"].get("content", "")

    return response_json.get("text", "") or response_json.get("response", "") or json.dumps(response_json)


def _parse_llm_json(raw_text: str) -> dict | None:
    if not raw_text:
        return None
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", raw_text, flags=re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                return None
    return None


def _build_gemini_prompt(module: str, text: str) -> str:
    if module == "prompt_injection":
        categories = ["Safe", "Suspicious", "Attack"]
        instructions = (
            "Classify the user prompt for prompt injection or jailbreak intent. "
            "Use one of the categories: Safe, Suspicious, Attack. "
            "Return only valid JSON with fields: llm_label, llm_risk_score (0-100), "
            "llm_confidence (0.0-1.0), llm_probabilities, llm_explanation. "
            "Do not include markdown or extra text."
        )
    elif module == "phishing":
        categories = ["Benign", "Suspicious", "Phishing"]
        instructions = (
            "Classify the message for phishing/spoofing risk. "
            "Use one of: Benign, Suspicious, Phishing. "
            "Return only valid JSON with fields: llm_label, llm_risk_score (0-100), "
            "llm_confidence (0.0-1.0), llm_probabilities, llm_explanation. "
            "Do not include markdown or extra text."
        )
    else:
        categories = ["Normal", "Attack"]
        instructions = (
            "Classify the traffic log content for DoS risk. "
            "Use one of: Normal, Attack. "
            "Return only valid JSON with fields: llm_label, llm_risk_score (0-100), "
            "llm_confidence (0.0-1.0), llm_probabilities, llm_explanation. "
            "Do not include markdown or extra text."
        )

    return (
        f"{instructions}\n\n"
        f"Input:\n{text}\n\n"
        f"Interpretation: Compare the content against {', '.join(categories)} categories and provide your best security classification. "
        "If you cannot classify confidently, return llm_label as Unknown and llm_risk_score as 0."
    )


def _normalize_llm_analysis(module: str, payload: dict, raw_text: str) -> dict:
    label = payload.get("llm_label") or payload.get("label") or payload.get("status") or payload.get("classification") or "Unknown"
    risk_score = payload.get("llm_risk_score") or payload.get("risk_score") or 0
    confidence = payload.get("llm_confidence") or payload.get("confidence") or 0.0
    probabilities = payload.get("llm_probabilities") or payload.get("probabilities") or {}
    if not isinstance(probabilities, dict):
        probabilities = {}

    try:
        risk_score = int(risk_score)
    except (TypeError, ValueError):
        risk_score = 0

    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        confidence = 0.0

    if risk_score < 0:
        risk_score = 0
    if risk_score > 100:
        risk_score = 100

    llm_explanation = payload.get("llm_explanation") or payload.get("explanation") or payload.get("reason") or payload.get("summary") or raw_text

    return {
        "llm_label": str(label),
        "llm_risk_score": risk_score,
        "llm_confidence": round(confidence, 3),
        "llm_probabilities": probabilities,
        "llm_explanation": str(llm_explanation),
        "raw_response": raw_text,
    }


async def _query_gemini(prompt: str) -> str:
    if not GEMINI_API_KEY:
        return ""

    url = f"{GEMINI_API_BASE}/models/{GEMINI_API_MODEL}:generate"
    params = {"key": GEMINI_API_KEY}
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {GEMINI_API_KEY}",
    }
    body = {
        "prompt": {"text": prompt},
        "temperature": 0.0,
        "max_output_tokens": 256,
    }

    async with httpx.AsyncClient(timeout=GEMINI_API_TIMEOUT) as client:
        response = await client.post(url, params=params, headers=headers, json=body)
        response.raise_for_status()
        payload = response.json()
        raw_text = _extract_gemini_text(payload)
        return raw_text


async def analyze_with_gemini(module: str, text: str):
    if not GEMINI_API_KEY:
        return None

    prompt = _build_gemini_prompt(module, text)
    try:
        raw_text = await _query_gemini(prompt)
        parsed = _parse_llm_json(raw_text)
        if parsed:
            return _normalize_llm_analysis(module, parsed, raw_text)
        return {
            "llm_label": "Unknown",
            "llm_risk_score": 0,
            "llm_confidence": 0.0,
            "llm_probabilities": {},
            "llm_explanation": raw_text or "Gemini response could not be parsed.",
            "raw_response": raw_text,
        }
    except Exception as exc:
        return {
            "llm_label": "Unknown",
            "llm_risk_score": 0,
            "llm_confidence": 0.0,
            "llm_probabilities": {},
            "llm_explanation": f"Gemini API error: {str(exc)}",
            "raw_response": "",
        }


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.post("/api/prompt-injection")
async def analyze_prompt_injection(body: TextInput):
    rule = detect_prompt_injection(body.text)
    ml = classify_prompt_injection(body.text)
    llm = await analyze_with_gemini("prompt_injection", body.text)

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
        "llm_analysis": llm,
    }


@app.post("/api/phishing")
async def analyze_phishing(body: TextInput):
    rule = detect_phishing(body.text)
    ml = classify_phishing(body.text)
    llm = await analyze_with_gemini("phishing", body.text)

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
        "llm_analysis": llm,
    }


@app.post("/api/dos")
async def analyze_dos(body: TextInput):
    rule = detect_dos(body.text)
    ml = classify_dos(body.text)
    llm = await analyze_with_gemini("dos", body.text)

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
        "llm_analysis": llm,
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
