from __future__ import annotations

import os
import time
from pathlib import Path

from flask import Flask, current_app, jsonify, request, send_from_directory
from flask_cors import CORS

from blocklist_engine import EMPTY_BLOCKLIST, load_blocklist_file, merge_blocklist_indices
from dataset_loader import load_dataset_blocklist
from scanner import analyze_url, result_to_dict


def _blocklist_path() -> Path:
    raw = os.environ.get("BLOCKLIST_PATH", "blocklist.txt")
    p = Path(raw)
    return p if p.is_absolute() else Path(__file__).resolve().parent / p


def _dataset_blocklist_path() -> Path | None:
    raw = (os.environ.get("MALICIOUS_URL_DATASET") or "").strip()
    if not raw:
        return None
    p = Path(raw)
    return p if p.is_absolute() else Path(__file__).resolve().parent / p


def _bool_param(val, default: bool) -> bool:
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in ("1", "true", "yes", "on")
    return bool(val)


def _auto_update_urlhaus(ds_path: Path):
    needs_update = True
    if ds_path.exists():
        if time.time() - ds_path.stat().st_mtime < 12 * 3600:
            needs_update = False
            
    if needs_update:
        print("Updating URLhaus dataset...")
        try:
            import requests
            r = requests.get("https://urlhaus.abuse.ch/downloads/text/", timeout=15)
            if r.status_code == 200:
                ds_path.parent.mkdir(parents=True, exist_ok=True)
                ds_path.write_text(r.text, encoding="utf-8")
                print("URLhaus dataset updated.")
        except Exception as e:
            print(f"Skipping URLhaus update: {e}")

def create_app() -> Flask:
    app = Flask(__name__)
    # Full CORS: r"/api/*" is regex (repeat "/"), so it does NOT match "/api/scan".
    CORS(app)
    frontend_dir = Path(__file__).resolve().parent / "frontend"
    base = load_blocklist_file(_blocklist_path())
    
    ds_path = _dataset_blocklist_path()
    if not ds_path:
        ds_path = Path(__file__).resolve().parent / "data" / "urlhaus_dataset.txt"
        
    _auto_update_urlhaus(ds_path)
    
    ds_ix = load_dataset_blocklist(ds_path) if ds_path and ds_path.exists() else EMPTY_BLOCKLIST
    app.config["BLOCKLIST"] = merge_blocklist_indices(base, ds_ix)

    @app.get("/")
    def serve_index():
        return send_from_directory(frontend_dir, "index.html")

    @app.post("/api/scan")
    def api_scan():
        data = request.get_json(silent=True) or {}
        url = data.get("url") or ""
        live = bool(data.get("live"))
        inc = data.get("include_features", True)
        if isinstance(inc, str):
            inc = inc.strip().lower() in ("1", "true", "yes")
        vt = _bool_param(data.get("virustotal"), False)
        ai = _bool_param(data.get("ai"), False)
        vt_key = data.get("vt_key")
        ai_key = data.get("ai_key")
        result = analyze_url(
            url,
            live=live,
            blocklist=current_app.config["BLOCKLIST"],
            include_features=bool(inc),
            virustotal=vt,
            ai=ai,
            vt_key=vt_key,
            openai_key=ai_key,
        )
        return jsonify(result_to_dict(result))

    return app


app = create_app()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    print(f"CyberGuard: open http://{host}:{port}/ in your browser.")
    print("If port 5000 is in use (common on Windows), run: set PORT=5001 && python app.py")
    app.run(debug=True, host=host, port=port)
