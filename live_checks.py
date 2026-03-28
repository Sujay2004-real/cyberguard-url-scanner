"""Optional live reputation: URLhaus, VirusTotal, OpenAI, SSRF-safe HTTP probe."""

from __future__ import annotations

import ipaddress
import os
import socket
from typing import Any
from urllib.parse import urljoin, urlparse

from reputation_providers import query_openai_url_risk, query_virustotal_url

# URLhaus requires a free key: https://auth.abuse.ch/
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"
_MAX_PROBE_BODY = 65536
_MAX_REDIRECTS = 5
_PROBE_TIMEOUT = 8.0


def _ip_allowed(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if addr.version == 6 and addr.ipv4_mapped is not None:
        return _ip_allowed(ipaddress.IPv4Address(addr.ipv4_mapped))
    return bool(addr.is_global)


def _hostnames_safe_for_request(hostname: str) -> tuple[bool, str | None]:
    host = hostname.strip().strip("[]")
    try:
        ipaddress.ip_address(host)
        if not _ip_allowed(ipaddress.ip_address(host.split("%")[0])):
            return False, "literal_ip_not_public"
        return True, None
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        return False, f"dns_error:{e!s}"
    seen: set[str] = set()
    for info in infos:
        sockaddr = info[4]
        ip_str = sockaddr[0].split("%", 1)[0]
        if ip_str in seen:
            continue
        seen.add(ip_str)
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"bad_ip:{ip_str}"
        if not _ip_allowed(ip_obj):
            return False, f"blocked_ip:{ip_str}"
    if not seen:
        return False, "no_addresses"
    return True, None


def query_urlhaus(url: str, auth_key: str) -> dict[str, Any]:
    try:
        import requests
    except ImportError:
        return {"checked": False, "error": "requests_not_installed"}

    headers = {"Auth-Key": auth_key}
    try:
        r = requests.post(
            URLHAUS_URL,
            data={"url": url},
            headers=headers,
            timeout=_PROBE_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        return {"checked": True, "error": str(e)}

    status = data.get("query_status")
    if status == "no_results":
        return {"checked": True, "listed": False}
    if status != "ok" or not data.get("id"):
        return {"checked": True, "listed": False, "query_status": status}

    return {
        "checked": True,
        "listed": True,
        "urlhaus_reference": data.get("urlhaus_reference"),
        "url_status": data.get("url_status"),
        "threat": data.get("threat"),
        "host": data.get("host"),
    }


def safe_http_probe(start_url: str) -> dict[str, Any]:
    try:
        import requests
    except ImportError:
        return {"ok": False, "error": "requests_not_installed"}

    current = start_url
    chain: list[str] = []

    for hop in range(_MAX_REDIRECTS + 1):
        parsed = urlparse(current)
        if parsed.scheme not in ("http", "https"):
            return {"ok": False, "error": "invalid_scheme", "chain": chain}
        host = parsed.hostname
        if not host:
            return {"ok": False, "error": "no_host", "chain": chain}

        ok, reason = _hostnames_safe_for_request(host)
        if not ok:
            return {"ok": False, "error": reason or "ssrf_blocked", "chain": chain}

        try:
            r = requests.get(
                current,
                timeout=_PROBE_TIMEOUT,
                stream=True,
                allow_redirects=False,
                headers={"User-Agent": "MaliciousURLScanner/1.0 (research; +local)"},
            )
        except Exception as e:
            return {"ok": False, "error": str(e), "chain": chain, "last_url": current}

        chain.append(current)

        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location")
            r.close()
            if not loc or hop >= _MAX_REDIRECTS:
                return {
                    "ok": False,
                    "error": "redirect_loop_or_missing_location",
                    "chain": chain,
                    "status_code": r.status_code,
                }
            current = urljoin(current, loc.strip())
            continue

        ct = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        total = 0
        try:
            for chunk in r.iter_content(chunk_size=8192):
                if not chunk:
                    break
                total += len(chunk)
                if total >= _MAX_PROBE_BODY:
                    break
        finally:
            r.close()

        return {
            "ok": True,
            "final_url": current,
            "status_code": r.status_code,
            "content_type": ct or None,
            "bytes_sampled": total,
            "chain": chain,
        }

    return {"ok": False, "error": "too_many_redirects", "chain": chain}


def run_live_checks(
    raw_url: str,
    host: str,
    scheme: str,
    *,
    blocklist_meta: dict[str, Any] | None = None,
    use_virustotal: bool = False,
    use_openai: bool = False,
    vt_key: str | None = None,
    openai_key: str | None = None,
    do_probe: bool = True,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    meta: dict[str, Any] = {}
    if blocklist_meta is not None:
        meta["blocklist"] = blocklist_meta

    key = (os.environ.get("URLHAUS_AUTH_KEY") or "").strip()
    if key:
        uh = query_urlhaus(raw_url, key)
        meta["urlhaus"] = uh
        if uh.get("listed"):
            ref = uh.get("urlhaus_reference") or "URLhaus"
            threat = uh.get("threat") or "malware"
            findings.append(
                {
                    "severity": "high",
                    "code": "urlhaus_listed",
                    "message": f"URL appears in URLhaus ({threat}). See: {ref}",
                    "weight": 70,
                }
            )
    else:
        meta["urlhaus"] = {"checked": False, "reason": "set URLHAUS_AUTH_KEY for URLhaus (free at https://auth.abuse.ch/)"}

    if scheme in ("http", "https"):
        if use_virustotal:
            vt = query_virustotal_url(raw_url, user_key=vt_key)
            meta["virustotal"] = vt
            if vt.get("checked") and not vt.get("error"):
                verdict = vt.get("verdict")
                eng = int(vt.get("engines_flagged") or 0)
                if verdict == "malicious":
                    findings.append(
                        {
                            "severity": "high",
                            "code": "virustotal_malicious",
                            "message": f"VirusTotal: {vt.get('malicious', 0)} engines flagged this URL as malicious.",
                            "weight": 78,
                        }
                    )
                elif verdict == "suspicious" or (eng >= 3 and vt.get("malicious", 0) == 0):
                    findings.append(
                        {
                            "severity": "medium",
                            "code": "virustotal_suspicious",
                            "message": f"VirusTotal: suspicious aggregate score (flagged engines: {eng}).",
                            "weight": 42,
                        }
                    )
        else:
            meta["virustotal"] = {"checked": False, "reason": "disabled (pass virustotal=true)"}

    if scheme in ("http", "https"):
        if use_openai:
            ai = query_openai_url_risk(raw_url, user_key=openai_key)
            meta["openai"] = ai
            if ai.get("checked") and not ai.get("error"):
                risk = ai.get("risk", "benign")
                conf = float(ai.get("confidence") or 0)
                if risk == "malicious" and conf >= 0.45:
                    findings.append(
                        {
                            "severity": "medium",
                            "code": "openai_malicious",
                            "message": f"AI assessment: malicious (confidence {conf:.2f}).",
                            "weight": 32,
                        }
                    )
                elif risk == "suspicious" and conf >= 0.5:
                    findings.append(
                        {
                            "severity": "low",
                            "code": "openai_suspicious",
                            "message": f"AI assessment: suspicious (confidence {conf:.2f}).",
                            "weight": 18,
                        }
                    )
        else:
            meta["openai"] = {"checked": False, "reason": "disabled (pass ai=true); requires OPENAI_API_KEY"}

    urlhaus_listed = bool(meta.get("urlhaus", {}).get("listed"))
    blocklist_hit = bool(meta.get("blocklist", {}).get("hit"))
    vt = meta.get("virustotal") or {}
    vt_flagged = bool(
        vt.get("checked")
        and not vt.get("error")
        and vt.get("verdict") in ("malicious", "suspicious")
    )

    if scheme in ("http", "https"):
        if not do_probe:
            meta["probe"] = {"skipped": True, "reason": "http_probe_disabled (pass live:true for fetch)"}
        elif blocklist_hit or urlhaus_listed or vt_flagged:
            meta["probe"] = {"skipped": True, "reason": "already_flagged_by_reputation"}
        else:
            probe = safe_http_probe(raw_url)
            meta["probe"] = probe
            if probe.get("ok"):
                sc = probe.get("status_code")
                if isinstance(sc, int) and sc >= 500:
                    findings.append(
                        {
                            "severity": "low",
                            "code": "probe_server_error",
                            "message": f"HTTP probe got status {sc} from final URL.",
                            "weight": 5,
                        }
                    )
            else:
                err = str(probe.get("error", "unknown"))
                if (
                    err == "ssrf_blocked"
                    or err == "literal_ip_not_public"
                    or err.startswith("blocked_ip:")
                ):
                    findings.append(
                        {
                            "severity": "medium",
                            "code": "probe_blocked_ssrf",
                            "message": "Live fetch blocked: target resolves to a non-public address.",
                            "weight": 15,
                        }
                    )
                elif "dns_error" in err:
                    findings.append(
                        {
                            "severity": "low",
                            "code": "probe_dns_failed",
                            "message": "Live fetch could not resolve the host.",
                            "weight": 4,
                        }
                    )

    return findings, meta
