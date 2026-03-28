"""Blocklist matching over full URLs (exact + path prefix) and hostnames."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass(frozen=True)
class BlocklistIndex:
    hosts: frozenset[str]
    exact_urls: frozenset[str]
    prefixes: tuple[str, ...]


EMPTY_BLOCKLIST = BlocklistIndex(frozenset(), frozenset(), ())


def normalize_url_for_match(raw: str) -> str:
    s = raw.strip()
    if "://" not in s:
        s = "http://" + s
    p = urlparse(s)
    scheme = (p.scheme or "http").lower()
    host = (p.hostname or "").lower()
    if not host:
        return ""
    port = p.port
    if port:
        def_p = 443 if scheme == "https" else 80
        netloc = f"{host}:{port}" if port != def_p else host
    else:
        netloc = host
    path = p.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    path = path.lower()
    query = (p.query or "").lower()
    q = f"?{query}" if query else ""
    return f"{scheme}://{netloc}{path}{q}"


def _parse_blocklist_line(line: str) -> tuple[set[str], set[str], list[str]]:
    hosts: set[str] = set()
    exact: set[str] = set()
    prefixes: list[str] = []

    line = line.strip()
    if not line or line.startswith("#"):
        return hosts, exact, prefixes
    if "#" in line:
        line = line.split("#", 1)[0].strip()
    if not line:
        return hosts, exact, prefixes

    low = line.lower()
    if "://" not in low and "/" not in low and "?" not in low:
        hosts.add(low.rstrip("."))
        return hosts, exact, prefixes

    if "://" not in low:
        low = "http://" + low

    nu = normalize_url_for_match(low)
    if not nu:
        return hosts, exact, prefixes

    p = urlparse(nu)
    path = p.path or "/"
    query = p.query or ""
    path_stripped = path.rstrip("/") or "/"

    if path_stripped == "/" and not query:
        h = (p.hostname or "").lower()
        if h:
            hosts.add(h.rstrip("."))
        return hosts, exact, prefixes

    exact.add(nu)

    noq = nu.split("?", 1)[0]
    prefixes.append(noq)
    if not noq.endswith("/"):
        prefixes.append(noq + "/")

    return hosts, exact, prefixes


def parse_blocklist_text(text: str) -> BlocklistIndex:
    hosts: set[str] = set()
    exact: set[str] = set()
    prefixes: list[str] = []
    for line in text.splitlines():
        h, e, pf = _parse_blocklist_line(line)
        hosts.update(h)
        exact.update(e)
        prefixes.extend(pf)
    uniq = sorted(set(prefixes), key=len, reverse=True)
    return BlocklistIndex(frozenset(hosts), frozenset(exact), tuple(uniq))


def load_blocklist_file(path: str | Path) -> BlocklistIndex:
    p = Path(path)
    if not p.is_file():
        return EMPTY_BLOCKLIST
    return parse_blocklist_text(p.read_text(encoding="utf-8", errors="ignore"))


def merge_blocklist_indices(*indices: BlocklistIndex) -> BlocklistIndex:
    hosts: set[str] = set()
    exact: set[str] = set()
    prefixes: list[str] = []
    for ix in indices:
        hosts.update(ix.hosts)
        exact.update(ix.exact_urls)
        prefixes.extend(ix.prefixes)
    uniq = sorted(set(prefixes), key=len, reverse=True)
    return BlocklistIndex(frozenset(hosts), frozenset(exact), tuple(uniq))


def match_blocklist(raw_url: str, host: str, index: BlocklistIndex) -> str | None:
    nu = normalize_url_for_match(raw_url)
    h = host.lower().rstrip(".")

    if nu and nu in index.exact_urls:
        return f"exact:{nu}"

    if nu:
        for prefix in index.prefixes:
            if nu == prefix or nu.startswith(prefix):
                rest = nu[len(prefix) :]
                if not rest or rest[0] == "?":
                    return f"prefix:{prefix}"
                if rest[0] == "/":
                    return f"prefix:{prefix}"

    if h in index.hosts:
        return f"host:{h}"
    for domain in index.hosts:
        if h == domain or h.endswith("." + domain):
            return f"host:{domain}"

    return None
