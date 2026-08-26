from pathlib import Path

LOG_PATH = Path(r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log")

APP_PORTS = {5000, 5173}

FIELDS = [
    "date", "time", "action", "protocol", "src_ip", "dst_ip",
    "src_port", "dst_port", "size", "tcpflags", "tcpsyn", "tcpack",
    "tcpwin", "icmptype", "icmpcode", "info", "path", "pid",
]


def _parse_line(line):
    parts = line.strip().split()
    if len(parts) < len(FIELDS):
        return None
    row = dict(zip(FIELDS, parts))
    try:
        row["src_port"] = int(row["src_port"])
        row["dst_port"] = int(row["dst_port"])
    except ValueError:
        return None
    return row


def read_recent_connections(limit=50, app_only=True):
    try:
        log_exists = LOG_PATH.exists()
    except PermissionError:
        return {
            "ok": False,
            "message": (
                f"Permission denied accessing {LOG_PATH}. Run the app as Administrator, "
                "or enable logging in Windows Defender Firewall with Advanced Security "
                "(this also grants read access to the log folder)."
            ),
            "entries": [],
        }

    if not log_exists:
        return {
            "ok": False,
            "message": f"Firewall log not found at {LOG_PATH}. Enable logging in Windows Defender Firewall with Advanced Security.",
            "entries": [],
        }

    try:
        with open(LOG_PATH, "r", encoding="utf-8", errors="ignore") as handle:
            lines = handle.readlines()
    except PermissionError as exc:
        return {
            "ok": False,
            "message": f"Permission denied reading firewall log: {exc}",
            "entries": [],
        }

    entries = []
    last_key = None
    for line in reversed(lines):
        if not line or line.startswith("#") or not line.strip():
            continue
        row = _parse_line(line)
        if not row:
            continue
        if app_only and row["src_port"] not in APP_PORTS and row["dst_port"] not in APP_PORTS:
            continue
        key = (
            row["action"], row["protocol"], row["src_ip"], row["dst_ip"],
            row["src_port"], row["dst_port"], row["time"],
        )
        if key == last_key:
            continue
        last_key = key
        entries.append({
            "timestamp": f"{row['date']} {row['time']}",
            "action": row["action"],
            "protocol": row["protocol"],
            "srcIp": row["src_ip"],
            "dstIp": row["dst_ip"],
            "srcPort": row["src_port"],
            "dstPort": row["dst_port"],
        })
        if len(entries) >= limit:
            break

    return {"ok": True, "entries": entries, "source": str(LOG_PATH)}
