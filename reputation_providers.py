"""Optional VirusTotal and OpenAI URL assessments (API keys via environment)."""

from __future__ import annotations

import json
import os
from typing import Any

VIRUSTOTAL_URL_API = "https://www.virustotal.com/api/v3/urls"
OPENAI_CHAT_API = "https://api.openai.com/v1/chat/completions"
_REQUEST_TIMEOUT = 45.0


def query_virustotal_url(url: str, user_key: str | None = None) -> dict[str, Any]:
    key = (user_key or os.environ.get("VIRUSTOTAL_API_KEY") or "").strip()
    if not key:
        return {
            "checked": False,
            "reason": "Set VIRUSTOTAL_API_KEY (https://www.virustotal.com/gui/my-apikey)",
        }
    try:
        import requests
    except ImportError:
        return {"checked": False, "error": "requests_not_installed"}

    try:
        import base64
        # VT v3 URL API requires GET /urls/{urlsafe_b64_encoded_url_without_padding}
        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")
        r = requests.get(
            f"{VIRUSTOTAL_URL_API}/{url_id}",
            headers={"x-apikey": key},
            timeout=_REQUEST_TIMEOUT,
        )
        if r.status_code == 404:
            return {"checked": True, "verdict": "clean_or_unknown", "reason": "not_scanned_yet"}
        if r.status_code == 429:
            return {"checked": True, "error": "rate_limited", "status_code": 429}
        if r.status_code >= 400:
            return {"checked": True, "error": r.text[:500], "status_code": r.status_code}
        data = r.json()
    except Exception as e:
        return {"checked": True, "error": str(e)}

    attrs = (data.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    mal = int(stats.get("malicious") or 0)
    sus = int(stats.get("suspicious") or 0)
    harm = int(stats.get("harmless") or 0)
    und = int(stats.get("undetected") or 0)

    engines_flagged = mal + sus

    out: dict[str, Any] = {
        "checked": True,
        "malicious": mal,
        "suspicious": sus,
        "harmless": harm,
        "undetected": und,
        "engines_flagged": engines_flagged,
    }

    if mal >= 1:
        out["verdict"] = "malicious"
    elif sus >= 4 or (mal + sus) >= 5:
        out["verdict"] = "suspicious"
    else:
        out["verdict"] = "clean_or_unknown"

    return out


def query_openai_url_risk(url: str, user_key: str | None = None) -> dict[str, Any]:
    key = (user_key or os.environ.get("OPENAI_API_KEY") or "").strip()
    model = (os.environ.get("OPENAI_MODEL") or "gpt-4o-mini").strip()
    if not key:
        return {"checked": False, "reason": "Set OPENAI_API_KEY to enable AI URL assessment"}
    try:
        import requests
    except ImportError:
        return {"checked": False, "error": "requests_not_installed"}

    body = {
        "model": model,
        "response_format": {"type": "json_object"},
        "temperature": 0.1,
        "max_tokens": 400,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You assess a single HTTP(S) URL for phishing/malware/social-engineering risk. "
                    "Do not fetch the URL. Reply with JSON only: "
                    '{"risk":"benign"|"suspicious"|"malicious","confidence":0.0-1.0,"reasons":["short bullet"]}'
                ),
            },
            {"role": "user", "content": f"URL to assess:\n{url}"},
        ],
    }
    try:
        r = requests.post(
            OPENAI_CHAT_API,
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json=body,
            timeout=60.0,
        )
        if r.status_code >= 400:
            return {"checked": True, "error": r.text[:800], "status_code": r.status_code}
        data = r.json()
        text = (data.get("choices") or [{}])[0].get("message", {}).get("content") or "{}"
        text = text.strip()
        if text.startswith("```"):
            parts = text.split("```")
            text = parts[1] if len(parts) >= 2 else text
            if text.lower().startswith("json"):
                text = text[4:].lstrip()
        parsed = json.loads(text)
    except Exception as e:
        return {"checked": True, "error": str(e)}

    risk = str(parsed.get("risk", "suspicious")).lower()
    conf = float(parsed.get("confidence", 0.5))
    reasons = parsed.get("reasons") if isinstance(parsed.get("reasons"), list) else []
    return {
        "checked": True,
        "risk": risk if risk in ("benign", "suspicious", "malicious") else "suspicious",
        "confidence": conf,
        "reasons": reasons[:5],
        "model": model,
    }
