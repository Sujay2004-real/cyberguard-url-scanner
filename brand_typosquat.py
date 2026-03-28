"""Brand / homoglyph typosquat checks (common in PhishTank-style phishing URLs)."""

from __future__ import annotations

from typing import Any

_HOMOGLYPH_TRANSLATION = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "6": "g",
        "7": "t",
        "8": "b",
        "@": "a",
        "ı": "i",
        "ɑ": "a",
    }
)

_BRAND_NAMES = frozenset(
    {
        "google",
        "gmail",
        "youtube",
        "facebook",
        "instagram",
        "whatsapp",
        "meta",
        "amazon",
        "microsoft",
        "office",
        "outlook",
        "live",
        "apple",
        "icloud",
        "paypal",
        "ebay",
        "netflix",
        "linkedin",
        "twitter",
        "dropbox",
        "adobe",
        "yahoo",
        "chase",
        "wellsfargo",
        "bankofamerica",
        "citi",
        "coinbase",
        "binance",
        "stripe",
    }
)

_BRAND_LEGIT_SUFFIXES = (
    ".com",
    ".net",
    ".org",
    ".edu",
    ".gov",
    ".co.uk",
    ".com.au",
    ".co.jp",
    ".de",
    ".fr",
)


def _normalize_label_for_brand(label: str) -> str:
    return label.lower().translate(_HOMOGLYPH_TRANSLATION)


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i]
        for j, cb in enumerate(b, start=1):
            ins, delete, sub = cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + (ca != cb)
            cur.append(min(ins, delete, sub))
        prev = cur
    return prev[-1]


def _legitimate_brand_host(host: str, brand: str) -> bool:
    for suf in _BRAND_LEGIT_SUFFIXES:
        tail = f"{brand}{suf}"
        if host == tail or host.endswith("." + tail):
            return True
    return False


def check_typosquat_and_brand_impersonation(host: str, findings: list[dict[str, Any]], add_finding) -> None:
    labels = [p for p in host.split(".") if p]

    for label in labels:
        if label in ("www", "m", "mobile", "mail", "web", "api", "cdn"):
            continue

        norm = _normalize_label_for_brand(label)

        for brand in _BRAND_NAMES:
            if norm == brand and label != brand:
                add_finding(
                    findings,
                    "high",
                    "homoglyph_typosquat",
                    f'Hostname label "{label}" resembles "{brand}" (digit/symbol substitutions).',
                    58,
                )
                return

        for brand in _BRAND_NAMES:
            if label == brand and not _legitimate_brand_host(host, brand):
                add_finding(
                    findings,
                    "high",
                    "brand_subdomain_impersonation",
                    f'Label "{brand}" is not on the real {brand} domain structure.',
                    55,
                )
                return

        for brand in _BRAND_NAMES:
            if len(brand) < 6 or len(label) < 6:
                continue
            d = _levenshtein(label, brand)
            if 0 < d <= 2 and label != brand:
                add_finding(
                    findings,
                    "medium",
                    "brand_typosquat",
                    f'Label "{label}" is very close to "{brand}" (possible typosquat).',
                    35,
                )
                return
