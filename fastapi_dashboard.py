# fastapi_dashboard.py
from __future__ import annotations

import re
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles


APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
INTERP_NAME = "interpretation.json"

DEFAULT_DECRYPTED_SUBDIR = Path("artifacts") / "decrypted"
DEFAULT_FIXED_DEX_NAME = "classes.fixed.dex"

_ASCII_RE = re.compile(rb"[ -~]{4,}")  # printable ascii >=4


def _safe_join(base: Path, user_path: str) -> Path:
    p = Path(user_path)
    if p.is_absolute():
        raise HTTPException(status_code=400, detail="Use relative out_dir (not absolute path).")
    full = (base / p).resolve()
    if not str(full).startswith(str(base.resolve())):
        raise HTTPException(status_code=400, detail="Invalid path (path traversal).")
    return full


def _load_interpretation(run_dir: Path) -> Dict[str, Any]:
    f = run_dir / INTERP_NAME
    if not f.exists():
        raise HTTPException(status_code=404, detail=f"{INTERP_NAME} not found in {run_dir}")
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse {INTERP_NAME}: {e}")


def _get_decrypted_root(run_dir: Path, interp: Dict[str, Any]) -> Path:
    root = None
    try:
        root = (((interp.get("decryption") or {}).get("paths") or {}).get("root"))
    except Exception:
        root = None

    if root:
        p = Path(root)
        if p.is_absolute():
            return p
        return (run_dir / p).resolve()

    return (run_dir / DEFAULT_DECRYPTED_SUBDIR).resolve()


def _list_tree(root: Path, max_files: int = 3000) -> List[Dict[str, Any]]:
    if not root.exists():
        return []
    out: List[Dict[str, Any]] = []
    count = 0
    for p in root.rglob("*"):
        if p.is_file():
            rel = str(p.relative_to(root))
            out.append({"rel": rel.replace("\\", "/"), "size": p.stat().st_size})
            count += 1
            if count >= max_files:
                break
    out.sort(key=lambda x: x["rel"])
    return out


def _dex_strings_from_file(dex_path: Path, min_len: int = 6, top_n: int = 30) -> List[Dict[str, Any]]:
    if not dex_path.exists():
        raise HTTPException(status_code=404, detail=f"dex not found: {dex_path}")

    data = dex_path.read_bytes()
    hits: Dict[str, int] = {}

    for m in _ASCII_RE.finditer(data):
        s = m.group(0).decode("utf-8", errors="ignore").strip()
        if len(s) < min_len:
            continue
        if len(s) > 300:
            s = s[:300]
        hits[s] = hits.get(s, 0) + 1

    items = sorted(hits.items(), key=lambda kv: kv[1], reverse=True)[:top_n]
    return [{"value": k, "count": v} for k, v in items]


def _iter_text_files(root: Path, include_ext: Tuple[str, ...] = (".java", ".kt", ".xml", ".smali", ".txt")):
    if not root.exists():
        return
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() in include_ext:
            yield p


def _context_search(root: Path, needle: str, radius: int = 3, max_hits: int = 50) -> Dict[str, Any]:
    if not needle:
        raise HTTPException(status_code=422, detail="needle is required")
    needle_l = needle.lower()

    hits: List[Dict[str, Any]] = []
    hit_index = 0

    for p in _iter_text_files(root):
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        lines = text.splitlines()
        for i, line in enumerate(lines):
            if needle_l in line.lower():
                start = max(0, i - radius)
                end = min(len(lines), i + radius + 1)
                ctx = lines[start:end]
                hits.append(
                    {
                        "hit_index": hit_index,
                        "file": str(p.relative_to(root)).replace("\\", "/"),
                        "line_no": i + 1,
                        "start_line": start + 1,
                        "lines": ctx,
                        "match_line_offset": i - start,
                    }
                )
                hit_index += 1
                if len(hits) >= max_hits:
                    return {"needle": needle, "radius": radius, "hits": hits, "truncated": True}
    return {"needle": needle, "radius": radius, "hits": hits, "truncated": False}


def _extract_mitre(interp: Dict[str, Any]) -> Dict[str, Any]:
    mitre = interp.get("mitre") or {"techniques": [], "notes": []}
    tags = interp.get("tags") or []

    tag_rows = []
    for t in tags:
        if not isinstance(t, dict):
            continue
        ms = t.get("mitre") or []
        for mid in ms:
            tag_rows.append(
                {
                    "tag": t.get("id", ""),
                    "sev": t.get("severity", ""),
                    "mitre": mid,
                    "source": t.get("source", ""),
                    "reason": t.get("reason", ""),
                }
            )
    return {"mitre": mitre, "tag_mitre_rows": tag_rows}


def _extract_ioc(interp: Dict[str, Any]) -> Dict[str, Any]:
    ioc = interp.get("ioc") or {}
    artifacts = (ioc.get("artifacts") or {})
    return {
        "urls": artifacts.get("urls") or [],
        "domains": artifacts.get("domains") or [],
        "ips": artifacts.get("ips") or [],
        "emails": artifacts.get("emails") or [],
    }


app = FastAPI(title="Deep Guard Dashboard (FastAPI)")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
def index():
    idx = STATIC_DIR / "index.html"
    if not idx.exists():
        return HTMLResponse("<h1>static/index.html not found</h1>", status_code=500)
    return HTMLResponse(idx.read_text(encoding="utf-8"))


@app.get("/api/run", response_class=JSONResponse)
def api_run(out_dir: str = Query(..., description="relative run output dir, e.g. out_runs_b/7a")):
    run_dir = _safe_join(APP_DIR, out_dir)
    interp = _load_interpretation(run_dir)
    return {"run_dir": str(run_dir), "interpretation": interp}


@app.get("/api/raw", response_class=JSONResponse)
def api_raw(out_dir: str = Query(...)):
    run_dir = _safe_join(APP_DIR, out_dir)
    interp = _load_interpretation(run_dir)
    return interp


@app.get("/api/mitre", response_class=JSONResponse)
def api_mitre(out_dir: str = Query(...)):
    run_dir = _safe_join(APP_DIR, out_dir)
    interp = _load_interpretation(run_dir)
    return _extract_mitre(interp)


@app.get("/api/ioc", response_class=JSONResponse)
def api_ioc(out_dir: str = Query(...)):
    run_dir = _safe_join(APP_DIR, out_dir)
    interp = _load_interpretation(run_dir)
    return _extract_ioc(interp)


@app.get("/api/decrypted/tree", response_class=JSONResponse)
def api_decrypted_tree(out_dir: str = Query(...), max_files: int = 3000):
    run_dir = _safe_join(APP_DIR, out_dir)
    interp = _load_interpretation(run_dir)
    root = _get_decrypted_root(run_dir, interp)
    files = _list_tree(root, max_files=max_files)
    return {"root": str(root), "count": len(files), "files": files}


@app.get("/api/decrypted/preview", response_class=JSONResponse)
def api_decrypted_preview(out_dir: str = Query(...), rel: str = Query(...), max_bytes: int = 4096):
    run_dir = _safe_join(APP_DIR, out_dir)
    interp = _load_interpretation(run_dir)
    root = _get_decrypted_root(run_dir, interp)

    target = (root / rel).resolve()
    if not str(target).startswith(str(root.resolve())):
        raise HTTPException(status_code=400, detail="invalid rel path")
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="file not found")

    data = target.read_bytes()[:max_bytes]
    return {"rel": rel, "bytes": len(data), "hex_head": data.hex()}


@app.get("/api/dex/topn", response_class=JSONResponse)
def api_dex_topn(out_dir: str = Query(...), top_n: int = 30, min_len: int = 6):
    run_dir = _safe_join(APP_DIR, out_dir)
    interp = _load_interpretation(run_dir)
    root = _get_decrypted_root(run_dir, interp)

    dex_path = None
    try:
        dex_path = (((interp.get("decryption") or {}).get("paths") or {}).get("dex"))
    except Exception:
        dex_path = None

    if dex_path:
        p = Path(dex_path)
        if not p.is_absolute():
            p = (run_dir / p).resolve()
        dex_file = p
    else:
        dex_file = (root / DEFAULT_FIXED_DEX_NAME).resolve()

    items = _dex_strings_from_file(dex_file, min_len=min_len, top_n=top_n)
    return {"dex": str(dex_file), "top_n": top_n, "min_len": min_len, "items": items}


@app.get("/api/dex/context", response_class=JSONResponse)
def api_dex_context(out_dir: str = Query(...), needle: str = Query(...), radius: int = 3, max_hits: int = 50):
    run_dir = _safe_join(APP_DIR, out_dir)
    interp = _load_interpretation(run_dir)
    root = _get_decrypted_root(run_dir, interp)
    return _context_search(root, needle=needle, radius=radius, max_hits=max_hits)
