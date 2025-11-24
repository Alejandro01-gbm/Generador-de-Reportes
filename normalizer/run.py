# -*- coding: utf-8 -*-
from typing import List
import csv
from pathlib import Path
from .core import FIELDNAMES
from .router import guess_parser

def normalize_files(inputs: List[str], out_csv: str):
    rows = []
    for p in inputs:
        path = Path(p)
        if not path.exists():
            print(f"[WARN] No existe: {p}")
            continue
        parser = guess_parser(path)
        if parser is None:
            continue
        for rec in parser(path):
            row = {k: (rec.get(k) if rec.get(k) is not None else "") for k in FIELDNAMES}
            rows.append(row)

    def sortkey(r):
        ts = r.get("timestamp") or ""
        return (ts, r.get("device") or "")
    rows.sort(key=sortkey)

    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDNAMES)
        w.writeheader()
        w.writerows(rows)

    print(f"[OK] Escribí {len(rows)} filas normalizadas en: {out_csv}")
