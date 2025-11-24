# -*- coding: utf-8 -*-
from datetime import datetime
from typing import Optional, Tuple
import re

FIELDNAMES = [
    "timestamp","device","src_ip","src_port","dst_ip","dst_port",
    "protocol","action","username","malware_name","malware_hash","msg"
]

MONTHS = {m: i for i, m in enumerate(
    ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"], start=1
)}

def to_iso(ts: str) -> Optional[str]:
    if not ts:
        return None
    ts = ts.strip()
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(microsecond=0).isoformat()
    except Exception:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt).isoformat()
        except Exception:
            continue
    return None

def parse_syslog_prefix(line: str) -> Tuple[Optional[str], Optional[str], str]:
    """
    Extrae 'Mon DD HH:MM:SS host ' al inicio si está presente.
    Retorna (iso_ts, host, msg_sin_prefijo)
    """
    m = re.match(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<msg>.+)$", line.strip())
    if not m:
        return None, None, line.strip()
    mon = m.group("mon")
    day = int(m.group("day"))
    time_str = m.group("time")
    host = m.group("host")
    msg = m.group("msg")
    mon_n = MONTHS.get(mon)
    if not mon_n:
        return None, host, msg
    y = datetime.now().year
    try:
        dt = datetime.strptime(f"{y}-{mon_n:02d}-{day:02d} {time_str}", "%Y-%m-%d %H:%M:%S")
        return dt.isoformat(), host, msg
    except Exception:
        return None, host, msg
