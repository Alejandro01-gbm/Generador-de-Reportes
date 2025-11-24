# -*- coding: utf-8 -*-
from typing import Dict
from .fields import read_combined, summarize
from .builder_docx import build_docx

def generate_report(combined_csv: str, outfile: str, override: Dict[str,str] = None):
    rows = read_combined(combined_csv)
    data = summarize(rows)

    if override:
        for k, v in override.items():
            if v not in (None, ""):
                data[k] = v

    build_docx(data, outfile)
    print(f"[OK] Borrador generado: {outfile}")


