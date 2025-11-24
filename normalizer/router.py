# -*- coding: utf-8 -*-
from pathlib import Path
from typing import Callable, Dict, Iterable, Optional
import json
from .asa import parse_cisco_txt
from .splunk import parse_splunk_csv
from .cisco_secure_endpoint import parse_cisco_secure_endpoint_jsonl

def guess_parser(path: Path) -> Optional[Callable[[Path], Iterable[Dict]]]:
    ext = path.suffix.lower()
    if ext == ".csv":
        return parse_splunk_csv
    if ext in (".log", ".txt"):
        return parse_cisco_txt
    if ext in (".jsonl", ".jl", ".json"):
        try:
            first_line = path.read_text(encoding="utf-8", errors="ignore").splitlines()[0].strip()
            sample = json.loads(first_line) if first_line.startswith("{") else {}
        except Exception:
            sample = {}

        keys_lower = {k.lower() for k in sample.keys()} if isinstance(sample, dict) else set()
        blob = (json.dumps(sample) if isinstance(sample, dict) else "").lower()
        amp_hints = any(h in keys_lower for h in ["connector_guid", "computer", "disposition"]) or \
                    ("secure endpoint" in blob or "amp for endpoints" in blob or "disposition" in blob)
        if amp_hints:
            return parse_cisco_secure_endpoint_jsonl

        print(f"[WARN] {path.name}: JSON/JSONL no reconocido como Cisco Secure Endpoint (AMP). Se omitirá.")
        return None

    # Fallback por contenido
    try:
        first = path.read_text(encoding="utf-8", errors="ignore").splitlines()[0].strip()
        if first.startswith("{"):
            print(f"[WARN] {path.name}: JSON detectado pero solo se admite Cisco Secure Endpoint (AMP). Se omitirá.")
            return None
        if "," in first and "timestamp" in first.lower():
            return parse_splunk_csv
        return parse_cisco_txt
    except Exception:
        return parse_cisco_txt
