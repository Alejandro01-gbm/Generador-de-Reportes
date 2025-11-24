# -*- coding: utf-8 -*-
from typing import Dict, Iterable, Optional
from pathlib import Path
import re
from .core import FIELDNAMES, parse_syslog_prefix

RE_ASA_BUILT = re.compile(
    r"Built\s+(?:inbound|outbound|local-host|remote-host)?\s*(?:[A-Za-z0-9_-]+)?\s*connection\s+\S+\s+for\s+[^:]+:(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})/(?P<src_port>\d+).*?\s+to\s+[^:]+:(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3})/(?P<dst_port>\d+)",
    re.IGNORECASE,
)
RE_ASA_DENY = re.compile(
    r"Deny\s+(?P<protocol>\w+)\s+src\s+[^:]+:(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})/(?P<src_port>\d+)\s+dst\s+[^:]+:(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3})/(?P<dst_port>\d+)",
    re.IGNORECASE,
)
RE_ASA_TEARDOWN = re.compile(
    r"Teardown\s+(?:UDP|TCP|ICMP)?\s*connection\s+\S+\s+for\s+[^:]+:(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})/(?P<src_port>\d+)\s+to\s+[^:]+:(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3})/(?P<dst_port>\d+)",
    re.IGNORECASE,
)
RE_ASA_NAT = re.compile(
    r"Translation by NAT for\s+[^:]+:(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})/(?P<src_port>\d+)\s+to\s+[^:]+:(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3})/(?P<dst_port>\d+)",
    re.IGNORECASE,
)
RE_LOGIN_FAIL = re.compile(r"Login failed for user\s+(?P<user>\S+)\s+from\s+(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE)

RE_ANY_IP = re.compile(r"\b(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b")
RE_ANY_PORT = re.compile(r"/(?P<port>\d{1,5})\b")

def normalize_asa_line(line: str) -> Dict[str, Optional[str]]:
    iso_ts, host, msg = parse_syslog_prefix(line)
    out = {k: None for k in FIELDNAMES}
    out.update({"timestamp": iso_ts, "device": host, "msg": msg})

    m = RE_ASA_BUILT.search(msg)
    if m:
        out.update({
            "action": "built",
            "src_ip": m.group("src_ip"), "src_port": m.group("src_port"),
            "dst_ip": m.group("dst_ip"), "dst_port": m.group("dst_port"),
            "protocol": "tcp" if "TCP" in msg.upper() else ("udp" if "UDP" in msg.upper() else None),
        })
        return out
    m = RE_ASA_DENY.search(msg)
    if m:
        out.update({
            "action": "deny",
            "protocol": m.group("protocol").lower(),
            "src_ip": m.group("src_ip"), "src_port": m.group("src_port"),
            "dst_ip": m.group("dst_ip"), "dst_port": m.group("dst_port"),
        })
        return out
    m = RE_ASA_TEARDOWN.search(msg)
    if m:
        out.update({
            "action": "teardown",
            "src_ip": m.group("src_ip"), "src_port": m.group("src_port"),
            "dst_ip": m.group("dst_ip"), "dst_port": m.group("dst_port"),
        })
        return out
    m = RE_ASA_NAT.search(msg)
    if m:
        out.update({
            "action": "nat",
            "src_ip": m.group("src_ip"), "src_port": m.group("src_port"),
            "dst_ip": m.group("dst_ip"), "dst_port": m.group("dst_port"),
        })
        return out
    m = RE_LOGIN_FAIL.search(msg)
    if m:
        out.update({
            "action": "failed_login",
            "username": m.group("user"),
            "src_ip": m.group("src_ip"),
        })
        return out

    ips = RE_ANY_IP.findall(msg)
    ports = RE_ANY_PORT.findall(msg)
    if ips:
        out["src_ip"] = ips[0]
        if len(ips) > 1:
            out["dst_ip"] = ips[1]
    if ports:
        if len(ports) >= 2:
            out["src_port"] = ports[0]
            out["dst_port"] = ports[1]
        else:
            out["dst_port"] = ports[0]

    s = msg.lower()
    if "deny" in s: out["action"] = out["action"] or "deny"
    if "built" in s: out["action"] = out["action"] or "built"
    if "teardown" in s: out["action"] = out["action"] or "teardown"
    if "translation by nat" in s: out["action"] = out["action"] or "nat"
    if "tcp" in s: out["protocol"] = out["protocol"] or "tcp"
    if "udp" in s: out["protocol"] = out["protocol"] or "udp"
    if "icmp" in s: out["protocol"] = out["protocol"] or "icmp"
    return out

def parse_cisco_txt(path: Path) -> Iterable[Dict[str, Optional[str]]]:
    PRI_RE = re.compile(r"^<\d+>")
    ISO_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            if PRI_RE.match(ln):
                ln = PRI_RE.sub("", ln).strip()
            if ISO_TS_RE.match(ln):
                parts = ln.split(" ", 1)
                if len(parts) == 2:
                    ts, rest = parts
                    ln = f"{ts} {rest}"
            try:
                rec = normalize_asa_line(ln)
                rec["raw"] = ln
                yield rec
            except Exception as e:
                yield {
                    "timestamp": None,
                    "device": None,
                    "msg": ln,
                    "error": str(e),
                    **{k: None for k in FIELDNAMES if k not in ("timestamp", "device", "msg")},
                }
