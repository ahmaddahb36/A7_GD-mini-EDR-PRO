import json
import os
import hashlib
from collections import Counter

DEFAULT_RULESET = {
    "high_risk_tools": {
        "severity": "High",
        "technique_id": "T1059",
        "tactic": "Execution",
        "source": "process",
        "tools": [
            "nc",
            "ncat",
            "netcat",
            "socat",
            "curl",
            "wget",
            "ssh",
            "sshd",
            "rsync",
            "scp",
            "nmap",
            "masscan",
            "tcpdump",
            "tshark",
            "strace",
            "ltrace",
            "powershell",
            "pwsh",
            "wmic",
        ],
    },
    "scripting_engines": {
        "severity": "Medium",
        "technique_id": "T1059",
        "tactic": "Execution",
        "source": "process",
        "tools": ["bash", "sh", "python", "perl", "ruby", "php", "node", "java", "cmd", "wscript"],
    },
    "suspicious_ports": {
        "severity": "High",
        "technique_id": "T1043",
        "tactic": "Command and Control",
        "source": "network",
        "ports": [22, 23, 2323, 4444, 1337, 5555, 6666, 12345, 9001, 31337],
    },
    "port_spike_threshold": 200,
    "network_exfiltration_threshold": 52428800,
}


def _rules_file():
    base = os.path.dirname(os.path.dirname(__file__))
    return os.path.join(base, "policies", "detection_rules.json")


def _load_rules():
    path = _rules_file()
    if not os.path.exists(path):
        return DEFAULT_RULESET
    try:
        with open(path, "r", encoding="utf-8") as handle:
            loaded = json.load(handle)
            if isinstance(loaded, dict):
                return loaded
    except Exception:
        pass
    return DEFAULT_RULESET


def _normalize_processes(data):
    raw = data.get("processes") or []
    items = []
    for proc in raw:
        if not isinstance(proc, dict):
            continue
        name = str(proc.get("name") or "").strip().lower()
        if not name:
            continue
        items.append(
            {
                "name": name,
                "pid": proc.get("pid"),
                "ppid": proc.get("ppid"),
                "username": proc.get("username"),
                "cmdline": proc.get("cmdline"),
                "sha256": proc.get("sha256"),
            }
        )
    return items


def _build_alert(severity, message, technique_id=None, tactic=None, source=None, details=None):
    aid_base = f"{technique_id or ''}|{tactic or ''}|{source or ''}|{message}"
    alert_id = hashlib.sha1(aid_base.encode()).hexdigest()
    return {
        "alert_id": alert_id,
        "severity": severity,
        "message": message,
        "technique_id": technique_id,
        "tactic": tactic,
        "source": source,
        "details": details or {},
    }


def analyze(data):
    rules = _load_rules()
    alerts = []

    processes = _normalize_processes(data)
    proc_names = {p["name"] for p in processes}
    proc_count = Counter([p["name"] for p in processes])

    high_risk = rules.get("high_risk_tools", {})
    high_tools = set([str(t).lower() for t in high_risk.get("tools", [])])
    high_found = sorted([name for name in proc_names if name in high_tools])
    if high_found:
        sample = []
        for proc in processes:
            if proc["name"] in high_found:
                sample.append(
                    {
                        "name": proc.get("name"),
                        "pid": proc.get("pid"),
                        "ppid": proc.get("ppid"),
                        "cmdline": proc.get("cmdline"),
                    }
                )
                if len(sample) >= 10:
                    break
        details = {"processes": {name: proc_count.get(name, 0) for name in high_found}, "sample": sample}
        alerts.append(
            _build_alert(
                high_risk.get("severity", "High"),
                f"High-risk tools detected: {', '.join(high_found)}",
                high_risk.get("technique_id"),
                high_risk.get("tactic"),
                high_risk.get("source", "process"),
                details,
            )
        )

    script_rule = rules.get("scripting_engines", {})
    script_tools = set([str(t).lower() for t in script_rule.get("tools", [])])
    medium_found = sorted([name for name in proc_names if name in script_tools])
    if medium_found:
        sample = []
        for proc in processes:
            if proc["name"] in medium_found:
                sample.append(
                    {
                        "name": proc.get("name"),
                        "pid": proc.get("pid"),
                        "ppid": proc.get("ppid"),
                        "cmdline": proc.get("cmdline"),
                    }
                )
                if len(sample) >= 10:
                    break
        details = {"processes": {name: proc_count.get(name, 0) for name in medium_found}, "sample": sample}
        alerts.append(
            _build_alert(
                script_rule.get("severity", "Medium"),
                f"Script/shell engines detected: {', '.join(medium_found)}",
                script_rule.get("technique_id"),
                script_rule.get("tactic"),
                script_rule.get("source", "process"),
                details,
            )
        )

    ports = data.get("ports", []) or []
    suspicious_rule = rules.get("suspicious_ports", {})
    suspicious_ports = set([int(p) for p in suspicious_rule.get("ports", []) if str(p).isdigit()])
    suspicious_open = sorted([int(p) for p in ports if int(p) in suspicious_ports])
    if suspicious_open:
        alerts.append(
            _build_alert(
                suspicious_rule.get("severity", "High"),
                f"Suspicious ports open: {', '.join(map(str, suspicious_open))}",
                suspicious_rule.get("technique_id"),
                suspicious_rule.get("tactic"),
                suspicious_rule.get("source", "network"),
                {"ports": suspicious_open},
            )
        )

    if len(ports) >= int(rules.get("port_spike_threshold", 200)):
        alerts.append(
            _build_alert(
                "Medium",
                f"Unusually high number of open ports: {len(ports)}",
                "T1046",
                "Discovery",
                "network",
                {"port_count": len(ports)},
            )
        )

    if high_found and suspicious_open:
        alerts.append(
            _build_alert(
                "Critical",
                "Possible reverse shell activity (tool + port correlation)",
                "T1059",
                "Execution",
                "correlation",
                {"tools": high_found, "ports": suspicious_open},
            )
        )

    # Outbound traffic volume alone is noisy in this environment; keep as telemetry only.

    remote_connections = data.get("remote_connections") or []
    suspicious_remote = []
    for conn in remote_connections:
        port = conn.get("rport")
        if port is None:
            continue
        try:
            p = int(port)
        except Exception:
            continue
        if p in suspicious_ports:
            suspicious_remote.append(conn)
    if suspicious_remote:
        sample = suspicious_remote[:5]
        alerts.append(
            _build_alert(
                "High",
                f"Suspicious remote connections detected: {len(suspicious_remote)}",
                "T1071",
                "Command and Control",
                "network",
                {"sample": sample},
            )
        )

    yara_matches = data.get("yara") or []
    if yara_matches:
        alerts.append(
            _build_alert(
                "Critical",
                f"YARA match: {', '.join(map(str, yara_matches))}",
                "T1204",
                "Execution",
                "yara",
                {"matches": yara_matches},
            )
        )

    return alerts
