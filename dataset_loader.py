"""Load blocklist-style data from CSV or text (full URLs preserved for path-level matching)."""

from __future__ import annotations

import csv
from pathlib import Path

from blocklist_engine import EMPTY_BLOCKLIST, parse_blocklist_text


def load_dataset_blocklist(path: str | Path) -> BlocklistIndex:
    p = Path(path)
    if not p.is_file():
        return EMPTY_BLOCKLIST

    text = p.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines()
    if not lines:
        return EMPTY_BLOCKLIST

    first_cells = [c.strip().lower() for c in lines[0].split(",")]
    looks_csv = p.suffix.lower() == ".csv" or (
        len(first_cells) > 1 and first_cells[0] in ("url", "uri", "urls", "host", "domain")
    )

    if looks_csv:
        reader = csv.reader(lines)
        rows = list(reader)
        if not rows:
            return EMPTY_BLOCKLIST
        hdr = [c.strip().lower() for c in rows[0]]
        col = 0
        for name in ("url", "uri", "urls"):
            if name in hdr:
                col = hdr.index(name)
                break
        else:
            if "host" in hdr:
                col = hdr.index("host")
            elif "domain" in hdr:
                col = hdr.index("domain")
        start = 1 if hdr and rows and rows[0] and rows[0][0].lower() in ("url", "uri", "urls", "host", "domain") else 0
        chunks: list[str] = []
        for row in rows[start:]:
            if len(row) > col:
                cell = row[col].strip()
                if cell:
                    chunks.append(cell)
        return parse_blocklist_text("\n".join(chunks))

    return parse_blocklist_text(text)
