"""
Rule engine: map parsed URL + lexical features to weighted findings.
Thresholds are conservative and inspired by aggregated phishing/malware URL datasets
(URL length, entropy, path depth, etc.); tune on your own holdout data if you train models.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import ParseResult

from brand_typosquat import check_typosquat_and_brand_impersonation
from lexical import URLFeatures

_SUSPICIOUS_TLDS = frozenset(
    {
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "xyz",
        "top",
        "work",
        "click",
        "link",
        "zip",
        "mov",
    }
)

_SPAM_TLDS = frozenset(
    {
        "date", "review", "country", "kim", "science", "work", "party", "gq", "bid", "stream", "download",
        "trade", "webcam", "click", "zip", "mov", "racing", "win", "men", "club"
    }
)

_CRYPTO_MINING_KEYWORDS = (
    "coinhive", "cryptoloot", "minr.js", "monero", "xmr", "coin-hive", "webminer", "cryptonight"
)

_DEFACEMENT_KEYWORDS = (
    "hacked by", "owned by", "h4x0r", "defaced", "pwned by"
)

_REDIRECT_PARAMS = (
    "?url=", "&url=", "?redirect=", "&redirect=", "?next=", "&next=",
    "?goto=", "&goto=", "?return_to=", "&return_to=", "?out=", "&out="
)

_SHORTENER_HOSTS = frozenset(
    {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd", "tiny.cc",
        "qr.ae", "adf.ly", "bit.do", "cutt.ly", "rb.gy", "t2mio.com", "lnkd.in", "db.tt",
        "cli.gs", "su.pr", "v.gd", "x.co", "bc.vc", "shorte.st", "s.id"
    }
)

# Substrings matched against the full normalized URL string (path/query), not host alone.
_FULL_URL_SUBSTRINGS: tuple[tuple[str, str, str, int], ...] = (
    ("/.env", "sensitive_path_dotenv", "Full URL path references .env (common leak/exploit probes).", 20),
    ("wp-config", "wordpress_config_in_url", "URL references wp-config (config probing).", 16),
    ("/.git/", "git_path_exposure", "URL references /.git/ (source exposure probes).", 20),
    ("phpmyadmin", "phpmyadmin_in_url", "phpMyAdmin path segment (common target).", 12),
    ("shell.php", "webshell_filename", "Filename shell.php (common webshell).", 24),
    ("c99.php", "webshell_c99", "c99.php pattern (known webshell).", 26),
    ("eval(base64", "encoded_eval_pattern", "eval/base64 pattern in URL (obfuscation).", 22),
    ("%00", "null_byte_in_url", "Null-byte (%00) in URL (historic bypass / attack pattern).", 18),
)

_PHISHING_KEYWORDS = (
    "verify",
    "account",
    "login",
    "signin",
    "update",
    "confirm",
    "suspended",
    "locked",
    "paypal",
    "amazon",
    "microsoft",
    "apple-id",
    "banking",
    "wallet",
    "webscr",
    "cmd=",
)


def add_finding(
    findings: list[dict[str, Any]],
    severity: str,
    code: str,
    message: str,
    weight: int,
) -> None:
    findings.append(
        {
            "severity": severity,
            "code": code,
            "message": message,
            "weight": weight,
        }
    )


def apply_rules(
    raw: str,
    parsed: ParseResult,
    host: str,
    scheme: str,
    features: URLFeatures,
    findings: list[dict[str, Any]],
) -> None:
    if scheme in ("javascript", "data", "vbscript", "file"):
        add_finding(
            findings,
            "high",
            "dangerous_scheme",
            f"Scheme '{scheme}' is commonly used for attacks.",
            60,
        )

    if not host:
        return

    if features.has_at_in_authority:
        add_finding(
            findings,
            "medium",
            "userinfo_in_netloc",
            "Username/password embedded in host (common phishing trick).",
            25,
        )

    if features.has_ip_host:
        add_finding(
            findings,
            "medium",
            "ip_host",
            "Host is a raw IP address; often used to bypass domain reputation.",
            20,
        )

    if features.has_punycode:
        add_finding(
            findings,
            "low",
            "punycode",
            "Internationalized domain (punycode); verify the real site name.",
            10,
        )

    if features.has_suspicious_chars:
        add_finding(
            findings,
            "high",
            "suspicious_chars",
            "URL contains hidden or suspicious control characters (e.g., zero-width spaces, RTL overrides).",
            30,
        )

    parts = host.split(".")
    if len(parts) >= 2:
        tld = parts[-1]
        
        if tld in _SPAM_TLDS:
            add_finding(
                findings,
                "medium",
                "spam_tld",
                f"TLD '.{tld}' is frequently associated with spam or abuse.",
                20,
            )
            
        elif tld in _SUSPICIOUS_TLDS:
            add_finding(
                findings,
                "medium",
                "suspicious_tld",
                f"TLD '.{tld}' is frequently abused in threat feeds.",
                15,
            )

    if host in _SHORTENER_HOSTS or any(host.endswith("." + s) for s in _SHORTENER_HOSTS):
        add_finding(
            findings,
            "medium",
            "url_shortener",
            "Shortened URL; destination is hidden until resolved.",
            25,
        )

    subdomain = host.split(".")[0] if "." in host else host
    if subdomain.count("-") >= 4:
        add_finding(
            findings,
            "low",
            "many_hyphens",
            "Many hyphens in subdomain (common in phishing CSVs).",
            10,
        )

    if features.suspicious_path_extension:
        add_finding(
            findings,
            "high",
            "suspicious_path_extension",
            f"Path references executable/script extension {features.suspicious_path_extension} (malware-dataset pattern).",
            28,
        )

    ul = raw.lower()
    
    for cm_kw in _CRYPTO_MINING_KEYWORDS:
        if cm_kw in ul:
            add_finding(
                findings,
                "high",
                "cryptomining_keyword",
                f"URL contains known cryptomining keyword '{cm_kw}'.",
                45,
            )
            break
            
    for red_param in _REDIRECT_PARAMS:
        if red_param in ul:
            add_finding(
                findings,
                "medium",
                "open_redirect_param",
                "URL contains common redirect parameters (could be Open Redirect abuse).",
                25,
            )
            break
            
    # Defacement heuristic: common keywords in path/query
    if any(df_kw in ul.replace("%20", " ") for df_kw in _DEFACEMENT_KEYWORDS):
        add_finding(
            findings,
            "high",
            "defacement_keyword",
            "URL contains typical website defacement strings/signatures.",
            50,
        )
        
    # C&C (Command & Control) heuristic: Raw IP + high port + suspicious endpoints
    if features.has_ip_host and parsed.port and parsed.port not in (80, 443, 8080, 8443):
        if ul.endswith(".php") or ul.endswith(".exe") or ul.endswith(".bin") or features.path_entropy > 4.5:
            add_finding(
                findings,
                "high",
                "botnet_cc_pattern",
                "Raw IP on non-standard port with high-entropy or scripting path (common C&C pattern).",
                65,
            )

    ul = raw.lower()
    for needle, code, msg, weight in _FULL_URL_SUBSTRINGS:
        if needle in ul:
            add_finding(findings, "medium", code, msg, weight)
            break

    if features.full_url_entropy >= 5.2 and features.url_length >= 80:
        add_finding(
            findings,
            "medium",
            "high_full_url_entropy",
            "Very high entropy across the full URL string (randomized malware delivery links).",
            14,
        )

    if features.hostname_entropy >= 4.35 and features.hostname_length >= 18:
        add_finding(
            findings,
            "medium",
            "high_hostname_entropy",
            "Very high hostname entropy — often random-looking subdomains in malware/phishing campaigns.",
            16,
        )

    if features.url_length >= 120:
        add_finding(
            findings,
            "low",
            "long_url",
            f"Long URL ({features.url_length} chars); common in parameterized phishing links.",
            10,
        )

    if features.path_depth >= 6:
        add_finding(
            findings,
            "low",
            "deep_path",
            f"Deep path ({features.path_depth} segments); seen often in malicious URL datasets.",
            9,
        )

    if features.query_param_count >= 6:
        add_finding(
            findings,
            "medium",
            "many_query_params",
            f"Many query parameters ({features.query_param_count}); can indicate tracking or obfuscation.",
            14,
        )

    if features.percent_encode_ratio >= 0.12 and features.url_length >= 40:
        add_finding(
            findings,
            "medium",
            "heavy_percent_encoding",
            "Heavy percent-encoding in the URL (evasion pattern in some corpora).",
            12,
        )

    if features.path_non_alnum_ratio >= 0.45 and features.path_length >= 12:
        add_finding(
            findings,
            "low",
            "path_symbol_heavy",
            "Path has many non-alphanumeric characters (noisy lexical signal).",
            8,
        )

    if features.extras.get("path_has_double_slash"):
        add_finding(
            findings,
            "medium",
            "path_double_slash",
            "Path contains '//' (sometimes used to confuse parsers or users).",
            14,
        )

    if host.count(".") > 4:
        add_finding(
            findings,
            "low",
            "deep_subdomain",
            "Deep subdomain chain (sometimes used to confuse users).",
            8,
        )

    if features.hostname_digit_ratio >= 0.35 and features.hostname_length > 0:
        add_finding(
            findings,
            "low",
            "numeric_heavy_host",
            "Hostname has a high digit ratio (IP-like or botnet URL pattern).",
            10,
        )

    path_q = f"{parsed.path or ''} {parsed.query or ''}".lower()
    hits = [k for k in _PHISHING_KEYWORDS if k in path_q]
    if hits:
        add_finding(
            findings,
            "medium",
            "phish_keywords",
            f"Path/query contains sensitive keywords: {', '.join(hits[:5])}.",
            18,
        )

    if parsed.port and parsed.port not in (80, 443, 8080, 8443):
        add_finding(
            findings,
            "low",
            "nonstandard_port",
            f"Non-standard port {parsed.port}.",
            8,
        )

    from brand_typosquat import _BRAND_NAMES
    path_only_lower = (parsed.path or "").lower()
    for brand in _BRAND_NAMES:
        # Check if brand appears in path, but host isn't that brand
        if brand in path_only_lower and brand not in host:
            add_finding(
                findings,
                "medium",
                "brand_mismatch",
                f"Brand name '{brand}' appears in the path, but domain does not belong to the brand.",
                25,
            )
            break

    check_typosquat_and_brand_impersonation(host, findings, add_finding)
