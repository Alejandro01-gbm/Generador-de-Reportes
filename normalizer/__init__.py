# Re-export útil para clientes
from .run import normalize_files

__all__ = ["normalize_files"]

#python ..\normalize_sources.py --in cisco_lockbit_raw.txt --in splunk_lockbit.csv --in cisco_secure_lockbit.jsonl --out lockbit_combined.csv
