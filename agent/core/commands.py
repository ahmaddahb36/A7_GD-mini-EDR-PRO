
import hashlib
import os
import subprocess

import psutil

from yara_scan import scan_file

def execute_shell(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        output = (result.stdout or "") + (result.stderr or "")
        if result.returncode != 0:
            return {"ok": False, "error": output.strip() or "Command failed"}
        return {"ok": True, "output": output.strip()}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

def _roots():
    if os.name == "nt":
        drives = []
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            path = f"{letter}:\\"
            if os.path.exists(path):
                drives.append(path)
        return drives
    return ["/"]

def _hash_file(path):
    sha = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()

def search_by_name(name_query, roots=None):
    matches = []
    needle = name_query.lower()
    roots = roots or _roots()
    for root in roots:
        for base, _, files in os.walk(root, onerror=lambda _: None):
            for filename in files:
                if needle in filename.lower():
                    path = os.path.join(base, filename)
                    try:
                        sha = _hash_file(path)
                        yara = scan_file(path)
                        matches.append({"path": path, "sha256": sha, "yara": yara})
                    except Exception:
                        matches.append({"path": path, "sha256": None, "yara": []})
    return matches

def search_by_hash(hash_query, roots=None):
    matches = []
    target = hash_query.lower()
    if roots is None:
        roots = _roots()
        if os.name != "nt":
            roots = ["/home/kali"]
    for root in roots:
        for base, _, files in os.walk(root, onerror=lambda _: None):
            for filename in files:
                path = os.path.join(base, filename)
                try:
                    sha = _hash_file(path)
                    if sha.lower() == target:
                        yara = scan_file(path)
                        matches.append({"path": path, "sha256": sha, "yara": yara})
                except Exception:
                    continue
    return matches

def kill_process(pid):
    try:
        target = int(pid)
    except Exception:
        return {"ok": False, "error": "Invalid pid"}
    try:
        proc = psutil.Process(target)
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        return {"ok": True, "output": f"Process {target} terminated"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

def close_port(port):
    try:
        target_port = int(port)
    except Exception:
        return {"ok": False, "error": "Invalid port"}

    killed = set()
    errors = []
    for conn in psutil.net_connections(kind="inet"):
        try:
            if not conn.laddr or int(conn.laddr.port) != target_port:
                continue
            pid = int(conn.pid or 0)
            if pid <= 0:
                continue
            if pid in killed:
                continue
            proc = psutil.Process(pid)
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
            killed.add(pid)
        except Exception as exc:
            errors.append(str(exc))
    if not killed:
        # Fallback for platforms where psutil cannot resolve owner PID without elevated rights.
        if os.name == "nt":
            try:
                cmd = f'for /f "tokens=5" %a in (\'netstat -ano ^| findstr "LISTENING" ^| findstr ":{target_port} "\') do taskkill /PID %a /F'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                out = ((result.stdout or "") + (result.stderr or "")).strip()
                if result.returncode == 0:
                    return {"ok": True, "output": f"Close-port fallback executed for {target_port}: {out}"}
                return {"ok": False, "error": out or f"No process found listening on port {target_port}"}
            except Exception as exc:
                return {"ok": False, "error": str(exc)}
        return {"ok": False, "error": f"No process found listening on port {target_port}"}
    msg = f"Closed port {target_port} by terminating PIDs: {', '.join(map(str, sorted(killed)))}"
    if errors:
        msg += f" (with {len(errors)} partial errors)"
    return {"ok": True, "output": msg}

def kill_connection(pid=None, laddr=None, raddr=None):
    if pid is not None:
        return kill_process(pid)

    candidate_pids = set()
    for conn in psutil.net_connections(kind="inet"):
        try:
            local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
            if laddr and local != laddr:
                continue
            if raddr and remote != raddr:
                continue
            if conn.pid:
                candidate_pids.add(int(conn.pid))
        except Exception:
            continue

    if not candidate_pids:
        # Fallback for Windows netstat parsing when psutil PID is unavailable.
        if os.name == "nt" and laddr:
            try:
                local_port = int(str(laddr).rsplit(":", 1)[1])
                return close_port(local_port)
            except Exception:
                pass
        return {"ok": False, "error": "No matching connection owner found"}

    killed = []
    for target in sorted(candidate_pids):
        res = kill_process(target)
        if res.get("ok"):
            killed.append(target)
    if not killed:
        return {"ok": False, "error": "Failed to terminate connection owners"}
    return {"ok": True, "output": f"Terminated connection owner PIDs: {', '.join(map(str, killed))}"}
