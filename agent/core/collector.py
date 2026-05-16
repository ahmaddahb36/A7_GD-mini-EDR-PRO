import hashlib
import platform
import socket
from datetime import datetime

import psutil


def _safe(value, default=None):
    return value if value is not None else default


def _hash_executable(path):
    if not path:
        return None
    sha = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                sha.update(chunk)
        return sha.hexdigest()
    except Exception:
        return None


def _serialize_process(proc):
    try:
        info = proc.as_dict(
            attrs=[
                "pid",
                "ppid",
                "name",
                "username",
                "cmdline",
                "exe",
                "create_time",
                "cpu_percent",
                "memory_info",
            ]
        )
    except Exception:
        return None

    cmdline = info.get("cmdline") or []
    if isinstance(cmdline, list):
        cmdline = " ".join([str(x) for x in cmdline[:32]])

    created = info.get("create_time")
    started = None
    if created:
        try:
            started = datetime.fromtimestamp(created).isoformat()
        except Exception:
            started = None

    mem_info = info.get("memory_info")
    rss = None
    try:
        rss = int(getattr(mem_info, "rss", 0) or 0)
    except Exception:
        rss = None

    exe = info.get("exe")
    return {
        "pid": _safe(info.get("pid"), 0),
        "ppid": _safe(info.get("ppid"), 0),
        "name": info.get("name") or "",
        "username": info.get("username") or "",
        "cmdline": cmdline or "",
        "exe": exe or "",
        "sha256": _hash_executable(exe),
        "started": started,
        "cpu_percent": float(info.get("cpu_percent") or 0.0),
        "memory_rss": rss or 0,
    }


def _collect_remote_connections(conns):
    local_ips = set()
    try:
        for _, entries in psutil.net_if_addrs().items():
            for ent in entries:
                if ent.family in (socket.AF_INET, socket.AF_INET6):
                    addr = str(ent.address or "")
                    if "%" in addr:
                        addr = addr.split("%", 1)[0]
                    if addr:
                        local_ips.add(addr)
    except Exception:
        pass

    items = []
    for conn in conns:
        try:
            # Keep actionable sessions and avoid short-lived TIME_WAIT flood.
            if str(conn.status or "").upper() in {"TIME_WAIT"}:
                continue
            laddr_ip = conn.laddr.ip if conn.laddr else ""
            laddr_port = conn.laddr.port if conn.laddr else 0
            raddr_ip = conn.raddr.ip if conn.raddr else ""
            raddr_port = conn.raddr.port if conn.raddr else 0

            direction = "unknown"
            status_up = str(conn.status or "").upper()
            if status_up == "LISTEN":
                direction = "listen"
            elif laddr_ip and raddr_ip:
                l_local = laddr_ip in local_ips
                r_local = raddr_ip in local_ips
                if l_local and not r_local:
                    direction = "outbound"
                elif r_local and not l_local:
                    direction = "inbound"
                elif l_local and r_local:
                    direction = "local"

            items.append(
                {
                    "pid": int(conn.pid or 0),
                    "laddr": f"{laddr_ip}:{laddr_port}" if laddr_ip else "",
                    "raddr": f"{raddr_ip}:{raddr_port}" if raddr_ip else "",
                    "rport": raddr_port,
                    "status": conn.status,
                    "type": "tcp" if conn.type == 1 else "udp",
                    "direction": direction,
                }
            )
        except Exception:
            continue
    return items


def _extract_ping_target(cmdline):
    if not cmdline:
        return ""
    parts = [str(p).strip() for p in cmdline.split(" ") if str(p).strip()]
    if not parts:
        return ""
    for token in reversed(parts):
        if token.startswith("-") or token.startswith("/"):
            continue
        if token.lower() in {"ping", "ping.exe", "ping6", "ping6.exe"}:
            continue
        return token
    return ""


def collect_icmp_activity():
    activity = []
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            name = str(proc.info.get("name") or "").lower()
            if name not in {"ping", "ping.exe", "ping6", "ping6.exe"}:
                continue
            cmdline = proc.info.get("cmdline") or []
            if isinstance(cmdline, list):
                cmdline = " ".join([str(x) for x in cmdline])
            target = _extract_ping_target(cmdline)
            if not target:
                continue
            activity.append(
                {
                    "pid": int(proc.info.get("pid") or 0),
                    "target": target,
                    "cmdline": cmdline,
                    "status": "ICMP_ACTIVE",
                    "type": "icmp",
                }
            )
        except Exception:
            continue
    return activity


def _extract_web_target(cmdline):
    if not cmdline:
        return ""
    parts = [str(p).strip() for p in cmdline.split(" ") if str(p).strip()]
    for token in parts:
        low = token.lower()
        if low.startswith("http://") or low.startswith("https://"):
            return token
    return ""


def collect_web_activity():
    web_names = {
        "curl",
        "curl.exe",
        "wget",
        "wget.exe",
        "lynx",
        "lynx.exe",
        "firefox",
        "firefox.exe",
        "chrome",
        "chrome.exe",
        "msedge",
        "msedge.exe",
        "brave",
        "brave.exe",
        "opera",
        "opera.exe",
    }
    items = []
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            name = str(proc.info.get("name") or "").lower()
            if name not in web_names:
                continue
            cmdline = proc.info.get("cmdline") or []
            if isinstance(cmdline, list):
                cmdline = " ".join([str(x) for x in cmdline])
            target = _extract_web_target(cmdline)
            items.append(
                {
                    "pid": int(proc.info.get("pid") or 0),
                    "name": name,
                    "target": target,
                    "cmdline": cmdline,
                    "status": "WEB_ACTIVE",
                    "type": "web",
                }
            )
        except Exception:
            continue
    return items


def collect_realtime_activity():
    conns = psutil.net_connections(kind="inet")
    return {
        "remote_connections": _collect_remote_connections(conns),
        "icmp_activity": collect_icmp_activity(),
        "web_activity": collect_web_activity(),
    }


def collect():
    conns = psutil.net_connections(kind="inet")
    ports = sorted({c.laddr.port for c in conns if c.laddr and c.status == psutil.CONN_LISTEN})
    net_io = psutil.net_io_counters()

    processes = []
    for proc in psutil.process_iter():
        serialized = _serialize_process(proc)
        if serialized:
            processes.append(serialized)

    return {
        "hostname": platform.node(),
        "os": platform.platform(),
        "processes": processes,
        "process_count": len(processes),
        "ports": ports,
        "conn_count": len(conns),
        "bytes_sent": int(net_io.bytes_sent or 0),
        "bytes_recv": int(net_io.bytes_recv or 0),
        "remote_connections": _collect_remote_connections(conns),
        "icmp_activity": collect_icmp_activity(),
        "web_activity": collect_web_activity(),
    }
