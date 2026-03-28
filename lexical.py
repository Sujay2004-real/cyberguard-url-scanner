"""
Lexical / structural URL features used across phishing benchmarks (e.g. ISCXURL2016-style,
LegitPhish, and similar CSV feature sets in the literature).

Why public "malicious URL" datasets are imperfect (design with these in mind):
- Temporal skew: labels are true at crawl time; sites go offline or are repurposed.
- Source skew: URLhaus is malware-distribution heavy; PhishTank is crowd-reported phishing;
  benign lists (e.g. Common Crawl) can contain undetected abuse.
- Near-duplicate URLs inflate counts and overfit lexical shortcuts.
- Class definition differs (phishing vs malware C2 vs spam), so one model rarely fits all.

Malicious URLs in those corpora often show higher URL length, deeper paths, more query
parameters, higher character entropy (randomized paths/subdomains), more digits/symbols,
raw IPs, @-in-URL tricks, and suspicious file extensions — none of which are sufficient
alone (legitimate sites can match any single signal).
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import ParseResult, parse_qs


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _digit_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(ch.isdigit() for ch in s) / len(s)


def _non_alnum_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(not ch.isalnum() for ch in s) / len(s)


def _path_depth(path: str) -> int:
    return max(0, len([p for p in path.split("/") if p]))


def _query_param_count(query: str) -> int:
    if not query:
        return 0
    return len(parse_qs(query, keep_blank_values=True))


_SUSPICIOUS_PATH_EXT = frozenset(
    {
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".com",
        ".pif",
        ".jar",
        ".apk",
        ".dll",
        ".msi",
        ".ps1",
        ".vbs",
        ".js",
        ".hta",
    }
)


@dataclass
class URLFeatures:
    """Hand-crafted features aligned with common phishing/malware URL datasets."""

    url_length: int = 0
    hostname_length: int = 0
    path_length: int = 0
    query_length: int = 0
    host_dot_count: int = 0
    path_depth: int = 0
    query_param_count: int = 0
    hostname_entropy: float = 0.0
    path_entropy: float = 0.0
    full_url_entropy: float = 0.0
    hostname_digit_ratio: float = 0.0
    path_digit_ratio: float = 0.0
    hostname_non_alnum_ratio: float = 0.0
    path_non_alnum_ratio: float = 0.0
    percent_encode_hits: int = 0
    percent_encode_ratio: float = 0.0
    has_at_in_authority: bool = False
    has_ip_host: bool = False
    has_punycode: bool = False
    suspicious_path_extension: str | None = None
    raw_fragment: str = ""
    has_suspicious_chars: bool = False
    extras: dict[str, Any] = field(default_factory=dict)

    def to_public_dict(self) -> dict[str, Any]:
        d = {
            "url_length": self.url_length,
            "hostname_length": self.hostname_length,
            "path_depth": self.path_depth,
            "query_param_count": self.query_param_count,
            "hostname_entropy": round(self.hostname_entropy, 3),
            "path_entropy": round(self.path_entropy, 3),
            "full_url_entropy": round(self.full_url_entropy, 3),
            "hostname_digit_ratio": round(self.hostname_digit_ratio, 3),
            "percent_encode_ratio": round(self.percent_encode_ratio, 3),
            "has_ip_host": self.has_ip_host,
            "has_at_in_authority": self.has_at_in_authority,
            "has_punycode": self.has_punycode,
            "has_suspicious_chars": self.has_suspicious_chars,
            "suspicious_path_extension": self.suspicious_path_extension,
        }
        return d


def _host_is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _detect_suspicious_extension(path_lower: str) -> str | None:
    path_only = path_lower.split("?")[0].split("#")[0]
    last_seg = path_only.rsplit("/", 1)[-1]
    if not last_seg:
        return None
    for ext in sorted(_SUSPICIOUS_PATH_EXT, key=len, reverse=True):
        if last_seg.endswith(ext):
            return ext
    return None


_SUSPICIOUS_CHARS = frozenset([
    '\u202e',  # Right-to-Left Override
    '\u200b',  # Zero Width Space
    '\u200c',  # Zero Width Non-Joiner
    '\u200d',  # Zero Width Joiner
    '\u202a',  # Left-to-Right Embedding
    '\u202b',  # Right-to-Left Embedding
    '\u0000',  # Null Byte
])

def _has_suspicious_chars(s: str) -> bool:
    return any(ch in _SUSPICIOUS_CHARS for ch in s)


def extract_features(raw_url: str, parsed: ParseResult) -> URLFeatures:
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    path_l = path.lower()

    pct = raw_url.count("%")
    pct_ratio = pct / max(len(raw_url), 1)

    f = URLFeatures(
        url_length=len(raw_url),
        hostname_length=len(host),
        path_length=len(path),
        query_length=len(query),
        host_dot_count=host.count("."),
        path_depth=_path_depth(path),
        query_param_count=_query_param_count(query),
        hostname_entropy=shannon_entropy(host),
        path_entropy=shannon_entropy(path),
        full_url_entropy=shannon_entropy(raw_url),
        hostname_digit_ratio=_digit_ratio(host),
        path_digit_ratio=_digit_ratio(path),
        hostname_non_alnum_ratio=_non_alnum_ratio(host),
        path_non_alnum_ratio=_non_alnum_ratio(path),
        percent_encode_hits=pct,
        percent_encode_ratio=pct_ratio,
        has_at_in_authority="@" in (parsed.netloc or ""),
        has_ip_host=_host_is_ip(host) if host else False,
        has_punycode=bool(host and ("xn--" in host)),
        suspicious_path_extension=_detect_suspicious_extension(path_l),
        raw_fragment=parsed.fragment or "",
        has_suspicious_chars=_has_suspicious_chars(raw_url),
    )

    if re.search(r"//+", path):
        f.extras["path_has_double_slash"] = True

    return f
