# -*- coding: utf-8 -*-
from typing import Dict, Iterable, Optional
from pathlib import Path
from .core import FIELDNAMES, to_iso
import json, re, ipaddress

KEY_VARIANTS = {
    "timestamp": ["timestamp", "date", "event_time", "occurred_at", "created_at"],
    "device": ["computer_name", "hostname", "hostName", "connector_name", "computer", "device_name"],
    "agent_ip": ["local_ip", "agentIp", "ip_address", "computer.local_ip"],
    "src_ip": ["src_ip", "source_ip"],
    "dst_ip": ["dst_ip", "destination_ip"],
    "src_port": ["src_port", "source_port", "network.src_port"],
    "dst_port": ["dst_port", "destination_port", "network.dst_port"],
    "protocol": ["protocol", "proto", "network.protocol"],
    "username": ["user", "username", "logged_in_user", "account_name"],
    "malware_name": ["threat_name", "detection", "signature", "signature_name", "malware", "threatName"],
    "malware_hash": ["sha256", "file.sha256", "sha1", "md5", "file_hash"],
    "file_path": ["file_path", "file.path", "filePath", "file_path_text", "path"],
    "process_name": ["process_name", "file_name", "process.name", "processName"],
    "action": ["disposition", "action", "event_type", "event"],
    "event_type": ["event_type", "type"],
    "command_line": ["command_line", "cmd_line", "process.command_line", "commandLine"],
    "domain": ["domain", "network.domain", "dns_query", "url.domain", "url.host"],
    "bytes_in": ["bytes_in", "ingress_bytes", "rx_bytes", "network.bytes_in"],
    "bytes_out": ["bytes_out", "egress_bytes", "tx_bytes", "network.bytes_out"],
}

def _get_nested(d: dict, dotted: str):
    cur = d
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur

def _find_one(d: dict, variants):
    for k in variants:
        v = _get_nested(d, k) if "." in k else d.get(k)
        if v not in (None, ""):
            return v
    return None

def _extract_first_ip_any(obj):
    if not obj:
        return None
    s = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False)
    m4 = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", s)
    if m4:
        return m4.group(1)
    m6 = re.search(r"([0-9a-fA-F:]{5,})", s)
    if m6:
        cand = m6.group(1)
        try:
            ipaddress.ip_address(cand)
            return cand
        except Exception:
            return None
    return None

def parse_cisco_secure_endpoint_jsonl(path: Path) -> Iterable[Dict[str, Optional[str]]]:
    with path.open("r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                ev = json.loads(ln)
            except Exception:
                continue

            out = {k: None for k in FIELDNAMES}

            ts = _find_one(ev, KEY_VARIANTS["timestamp"])
            out["timestamp"] = to_iso(ts) if ts else None
            out["device"] = _find_one(ev, KEY_VARIANTS["device"])

            agent_ip = _find_one(ev, KEY_VARIANTS["agent_ip"])
            out["src_ip"] = _find_one(ev, KEY_VARIANTS["src_ip"]) or agent_ip or _extract_first_ip_any(ev)
            out["dst_ip"] = _find_one(ev, KEY_VARIANTS["dst_ip"])

            sp = _find_one(ev, KEY_VARIANTS["src_port"])
            dp = _find_one(ev, KEY_VARIANTS["dst_port"])
            out["src_port"] = str(int(sp)) if isinstance(sp, (int, float)) else (str(sp) if sp else None)
            out["dst_port"] = str(int(dp)) if isinstance(dp, (int, float)) else (str(dp) if dp else None)

            proto = _find_one(ev, KEY_VARIANTS["protocol"])
            out["protocol"] = (proto or "").lower() if proto else None

            out["username"] = _find_one(ev, KEY_VARIANTS["username"])
            out["malware_name"] = _find_one(ev, KEY_VARIANTS["malware_name"])
            out["malware_hash"] = _find_one(ev, KEY_VARIANTS["malware_hash"])

            action = _find_one(ev, KEY_VARIANTS["action"])
            if isinstance(action, str):
                a = action.strip().lower()
                out["action"] = action.title() if a in ("malicious", "quarantined", "blocked", "detected", "clean") else action
            else:
                out["action"] = action

            cmd = _find_one(ev, KEY_VARIANTS["command_line"])
            dom = _find_one(ev, KEY_VARIANTS["domain"])
            bi = _find_one(ev, KEY_VARIANTS["bytes_in"])
            bo = _find_one(ev, KEY_VARIANTS["bytes_out"])
            try: bi = int(bi) if bi is not None else None
            except Exception: pass
            try: bo = int(bo) if bo is not None else None
            except Exception: pass

            parts = []
            fp = _find_one(ev, KEY_VARIANTS["file_path"])
            pn = _find_one(ev, KEY_VARIANTS["process_name"])
            if fp: parts.append(f"file={fp}")
            if pn: parts.append(f"proc={pn}")
            if cmd: parts.append(f"cmd={cmd}")
            if dom: parts.append(f"domain={dom}")
            if out["src_ip"]: parts.append(f"src={out['src_ip']}")
            if out["dst_ip"]: parts.append(f"dst={out['dst_ip']}")
            if out["dst_port"]: parts.append(f"dport={out['dst_port']}")
            if out["protocol"]: parts.append(f"proto={out['protocol']}")
            if bi is not None: parts.append(f"bytes_in={bi}")
            if bo is not None: parts.append(f"bytes_out={bo}")
            if out["malware_name"]: parts.append(f"threat={out['malware_name']}")
            if out["action"]: parts.append(f"disposition={out['action']}")
            out["msg"] = " ".join(parts) if parts else json.dumps(ev, ensure_ascii=False)

            yield {k: (out.get(k) if out.get(k) is not None else "") for k in FIELDNAMES}
