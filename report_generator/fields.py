# -*- coding: utf-8 -*-
import csv, re
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

# ----------------- Helpers de saneo -----------------
_IPv4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")

def _is_private(ip: str) -> bool:
    return (
        ip.startswith("10.") or
        ip.startswith("192.168.") or
        (ip.startswith("172.") and ip.split(".")[1].isdigit() and 16 <= int(ip.split(".")[1]) <= 31)
    )

def _safe_dt(s: str) -> Optional[datetime]:
    """Devuelve datetime NAIVE en UTC (sin tzinfo)."""
    if not s:
        return None
    s = s.strip().replace("Z", "+00:00")
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is not None:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
        except Exception:
            continue
    return None

def read_combined(path: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    with open(path, "r", encoding="utf-8", newline="") as f:
        dr = csv.DictReader(f)
        for r in dr:
            rows.append({(k or "").strip(): (v or "").strip() for k, v in r.items()})
    return rows

# ----------------- Reglas de llenado -----------------
ANALYST_FIELDS = {
    "No de alerta", "Criticidad", "Reportado por",
    "Descripción de la alerta", "Análisis", "Recomendaciones"
}
# Campos que el script calcula (si faltan -> N/A)
AUTO_FIELDS = {
    "Fecha y hora de Inicio de la alerta",
    "Total de Eventos",
    "Fuentes de Logs",
    "IP Origen",
    "IP Destino",
    "Indicadores de Compromiso (IoCs)",
    "Cuenta/s",
}

def _na_if_empty(val: str) -> str:
    """Para campos AUTO: si no hay valor -> 'N/A'."""
    return val if (val is not None and val != "") else "N/A"

# ----------------- Resumen principal -----------------
def summarize(rows: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    Mapea el combined CSV a la plantilla SOC.
    - Campos del analista: siempre vacíos.
    - Campos auto: valor calculado o 'N/A' si no hay datos.
    """
    # Base con todos los campos
    out: Dict[str, Any] = {
        "No de alerta": "",
        "Criticidad": "",
        "Reportado por": "",
        "Descripción de la alerta": "",
        "Fecha y hora de Inicio de la alerta": "",
        "Total de Eventos": "",
        "Fuentes de Logs": "",
        "IP Origen": "",
        "IP Destino": "",
        "Evento contenido": "",  
        "Indicadores de Compromiso (IoCs)": "",
        "Cuenta/s": "",
        "Análisis": "",
        "Recomendaciones": "",
    }

    if not rows:
        for f in AUTO_FIELDS:
            out[f] = "N/A"
        return out

    ts_list = [t for t in (_safe_dt(r.get("timestamp", "")) for r in rows) if t]
    ts_min = (min(ts_list).strftime("%Y-%m-%dT%H:%M:%S") + "Z") if ts_list else ""
    out["Fecha y hora de Inicio de la alerta"] = _na_if_empty(ts_min)

    out["Total de Eventos"] = _na_if_empty(str(len(rows)))

    uniq_devices: List[str] = []
    for r in rows:
        d = (r.get("device") or "").strip()
        if d and d not in uniq_devices:
            uniq_devices.append(d)
    fuentes = ", ".join(uniq_devices)
    out["Fuentes de Logs"] = _na_if_empty(fuentes)

    src_ips_all = [(r.get("src_ip") or "").strip() for r in rows if (r.get("src_ip") or "").strip()]
    dst_ips_all = [(r.get("dst_ip") or "").strip() for r in rows if (r.get("dst_ip") or "").strip()]
    src_top = Counter(src_ips_all).most_common(1)[0][0] if src_ips_all else ""
    dst_top = Counter(dst_ips_all).most_common(1)[0][0] if dst_ips_all else ""
    out["IP Origen"]  = _na_if_empty(src_top)
    out["IP Destino"] = _na_if_empty(dst_top)

    malnames = [(r.get("malware_name") or "").strip() for r in rows if (r.get("malware_name") or "").strip()]
    hashes   = [(r.get("malware_hash") or "").strip() for r in rows if (r.get("malware_hash") or "").strip()]

    # Puertos: 1..65535
    norm_ports: List[int] = []
    for p in [r.get("dst_port") for r in rows if r.get("dst_port")]:
        try:
            pi = int(str(p).strip())
            if 1 <= pi <= 65535:
                norm_ports.append(pi)
        except Exception:
            pass

    ext_ips_raw = src_ips_all + dst_ips_all
    ext_ips = [ip for ip in ext_ips_raw if _IPv4_RE.match(ip) and not _is_private(ip)]

    top_mal     = [m for m, _ in Counter(malnames).most_common(3)]
    top_hash    = [h for h, _ in Counter(hashes).most_common(6)]
    top_ext_ips = [ip for ip, _ in Counter(ext_ips).most_common(6)]
    top_ports   = [str(p) for p, _ in Counter(norm_ports).most_common(6)]

    lines: List[str] = []
    if top_mal:
        lines.append("Malware name:")
        lines.extend(top_mal)
        lines.append("")
    if top_hash:
        lines.append("Hash:")
        lines.extend(top_hash)
        lines.append("")
    if top_ext_ips:
        lines.append("IP maliciosa:")
        lines.extend(top_ext_ips)
        lines.append("")
    if top_ports:
        lines.append("Puertos: ")
        lines.extend(top_ports)
        lines.append("")
    while lines and (lines[-1] == "" or lines[-1] == "*"):
        lines.pop()
    iocs = "\n".join([ln for ln in lines if ln.strip() and ln.strip() != "*"])
    out["Indicadores de Compromiso (IoCs)"] = _na_if_empty(iocs)

    # ---------- Cuentas ----------
    users = [(r.get("username") or "").strip() for r in rows if (r.get("username") or "").strip()]
    victims = ", ".join(u for u, _ in Counter(users).most_common(5))
    out["Cuenta/s"] = _na_if_empty(victims)

    return out
