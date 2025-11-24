# -*- coding: utf-8 -*-
from typing import Dict, Iterable, Optional
from pathlib import Path
import csv, re
from .core import FIELDNAMES, to_iso

def parse_splunk_csv(path: Path) -> Iterable[Dict[str, Optional[str]]]:
    SYNONYMS = {
        "timestamp": ["timestamp", "_time", "time", "date"],
        "device": ["device", "host", "sourcetype"],
        "src_ip": ["src_ip", "src", "source", "client_ip", "srcaddr"],
        "dst_ip": ["dst_ip", "dst", "dest", "destination"],
        "src_port": ["src_port", "sport", "spt"],
        "dst_port": ["dst_port", "dport", "dpt"],
        "protocol": ["protocol", "proto"],
        "action": ["action", "result", "status"],
        "username": ["username", "user", "account"],
        "malware_name": ["malware_name", "threatName", "signature"],
        "malware_hash": ["malware_hash", "sha256", "md5"],
        "msg": ["msg", "_raw", "message", "signature"],
    }

    def find_variant(row_keys_set, variants):
        for v in variants:
            if v in row_keys_set:
                return v
        return None

    with path.open("r", encoding="utf-8", newline="") as f:
        dr = csv.DictReader(f)
        original_keys = dr.fieldnames or []
        header_map = {k: (k.lower().strip() if isinstance(k, str) else k) for k in original_keys}
        normalized_keys_set = {header_map[k] for k in original_keys if isinstance(k, str)}

        variant_map = {}
        for canon, variants in SYNONYMS.items():
            found = find_variant(normalized_keys_set, [v.lower() for v in variants])
            variant_map[canon] = found

        for raw_row in dr:
            row = {}
            for orig_k, val in raw_row.items():
                if orig_k is None:
                    continue
                nk = orig_k.lower().strip()
                row[nk] = val

            out = {k: None for k in FIELDNAMES}
            ts_key = variant_map.get("timestamp")
            if ts_key and row.get(ts_key):
                out["timestamp"] = to_iso(row.get(ts_key))

            dk = variant_map.get("device")
            if dk:
                out["device"] = row.get(dk) or None

            for fld in ("src_ip","dst_ip","src_port","dst_port","protocol","action","username","malware_name","malware_hash","msg"):
                vk = variant_map.get(fld)
                if vk:
                    out[fld] = row.get(vk) or None

            if not out["src_ip"]:
                m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", (out.get("msg") or ""))
                if m:
                    out["src_ip"] = m.group(1)

            yield out
