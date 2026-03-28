"""Orchestrates URL parsing, lexical features, rules, blocklist (full URL + host), and optional live checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from blocklist_engine import EMPTY_BLOCKLIST, BlocklistIndex, match_blocklist
from lexical import extract_features
from rules import apply_rules

DATASET_SCORING_CAVEAT = (
    "Heuristics mirror patterns common in phishing/malware URL benchmarks (length, entropy, path depth, "
    "encoding). Real datasets are temporally biased, class-mixed, and noisy; use live feeds and human "
    "review for high-stakes decisions."
)


@dataclass
class ScanResult:
    url: str
    risk_score: int
    verdict: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    normalized_host: str | None = None
    live_meta: dict[str, Any] | None = None
    features: dict[str, Any] | None = None


def _verdict_from_score(score: int) -> str:
    if score >= 55:
        return "likely_malicious"
    if score >= 25:
        return "suspicious"
    return "likely_safe"


def analyze_url(
    raw: str,
    *,
    live: bool = False,
    blocklist: BlocklistIndex | None = None,
    include_features: bool = True,
    virustotal: bool = False,
    ai: bool = False,
    vt_key: str | None = None,
    openai_key: str | None = None,
) -> ScanResult:
    findings: list[dict[str, Any]] = []
    raw = (raw or "").strip()

    if not raw:
        return ScanResult(
            url=raw,
            risk_score=40,
            verdict="likely_malicious",
            findings=[
                {
                    "severity": "high",
                    "code": "empty",
                    "message": "No URL provided.",
                    "weight": 40,
                }
            ],
            features={"error": "empty"} if include_features else None,
        )

    if "://" not in raw:
        raw = "http://" + raw

    try:
        parsed = urlparse(raw)
    except Exception:
        return ScanResult(
            url=raw,
            risk_score=50,
            verdict="likely_malicious",
            findings=[
                {
                    "severity": "high",
                    "code": "parse_error",
                    "message": "Could not parse URL.",
                    "weight": 50,
                }
            ],
            features={"error": "parse_error"} if include_features else None,
        )

    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    features_obj = extract_features(raw, parsed)

    if not host:
        apply_rules(raw, parsed, "", scheme, features_obj, findings)
        findings.append(
            {
                "severity": "high",
                "code": "no_host",
                "message": "URL has no hostname.",
                "weight": 45,
            }
        )
        score = min(100, sum(f["weight"] for f in findings))
        feat_dict: dict[str, Any] | None = None
        if include_features:
            feat_dict = features_obj.to_public_dict()
            feat_dict["extras"] = dict(features_obj.extras) if features_obj.extras else {}
        return ScanResult(
            url=raw,
            risk_score=score,
            verdict=_verdict_from_score(score),
            findings=findings,
            normalized_host=None,
            features=feat_dict,
        )

    apply_rules(raw, parsed, host, scheme, features_obj, findings)

    idx = blocklist if blocklist is not None else EMPTY_BLOCKLIST
    bl_hit = match_blocklist(raw, host, idx)
    if bl_hit:
        findings.append(
            {
                "severity": "high",
                "code": "blocklist_hit",
                "message": f'Blocklist match ({bl_hit}) — full URL, path prefix, or host.',
                "weight": 65,
            }
        )

    live_meta: dict[str, Any] | None = None
    want_online = live or virustotal or ai
    if want_online and scheme in ("http", "https") and host:
        from live_checks import run_live_checks

        bl_meta = {"checked": True, "hit": bl_hit}
        extra, live_meta = run_live_checks(
            raw,
            host,
            scheme,
            blocklist_meta=bl_meta,
            use_virustotal=virustotal,
            use_openai=ai,
            vt_key=vt_key,
            openai_key=openai_key,
            do_probe=live,
        )
        findings.extend(extra)

    score = min(100, sum(f["weight"] for f in findings))
    feat_dict = features_obj.to_public_dict() if include_features else None
    if include_features:
        feat_dict = feat_dict or {}
        feat_dict["extras"] = dict(features_obj.extras) if features_obj.extras else {}

    return ScanResult(
        url=raw,
        risk_score=score,
        verdict=_verdict_from_score(score),
        findings=findings,
        normalized_host=host,
        live_meta=live_meta,
        features=feat_dict,
    )


def result_to_dict(r: ScanResult) -> dict[str, Any]:
    out: dict[str, Any] = {
        "url": r.url,
        "risk_score": r.risk_score,
        "verdict": r.verdict,
        "normalized_host": r.normalized_host,
        "findings": r.findings,
        "scoring_note": DATASET_SCORING_CAVEAT,
    }
    if r.features is not None:
        out["features"] = r.features
    if r.live_meta is not None:
        out["live"] = r.live_meta
    return out
