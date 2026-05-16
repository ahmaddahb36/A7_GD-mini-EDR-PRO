
import base64
import hashlib
import json
import os
import socket
import threading
import time

from collector import collect, collect_realtime_activity
from commands import close_port, execute_shell, kill_connection, kill_process, search_by_hash, search_by_name
from sender import send
from yara_scan import scan

def _send_chunked(cmd_id, text, status="done"):
    chunk_size = 3000
    for i in range(0, len(text), chunk_size):
        chunk = text[i:i + chunk_size]
        payload = {"type": "command_result_chunk", "cmd_id": cmd_id, "chunk": chunk}
        send(payload)
    send({"type": "command_result_chunk", "cmd_id": cmd_id, "done": True, "status": status})

def _send_file(cmd_id, path):
    sha = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha.update(chunk)
            size += len(chunk)
    send({
        "type": "file_start",
        "cmd_id": cmd_id,
        "source_path": path,
        "size": size,
        "sha256": sha.hexdigest(),
    })
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(256 * 1024), b""):
            b64 = base64.b64encode(chunk).decode()
            send({"type": "file_chunk", "cmd_id": cmd_id, "data": b64})
    send({"type": "file_end", "cmd_id": cmd_id})

def _local_ip():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return None

poll_interval = 2
last_telemetry = 0
in_flight = set()

def _resolve_roots(payload_obj, default_linux_root="/home/kali"):
    roots = payload_obj.get("roots") or payload_obj.get("root")
    if isinstance(roots, str):
        roots = [roots]
    if roots and isinstance(roots, list):
        return roots
    if os.name != "nt":
        return [default_linux_root]
    return None

def _run_search(cmd_id, action, query, payload_obj, agent_ip):
    try:
        roots = _resolve_roots(payload_obj)
        if action == "search_name":
            matches = search_by_name(query, roots=roots)
        else:
            matches = search_by_hash(query, roots=roots)
        output = json.dumps({"query": query, "roots": roots, "matches": matches})
        _send_chunked(cmd_id, output)
    except Exception as exc:
        payload = {"type": "command_result", "cmd_id": cmd_id, "ok": False, "error": str(exc)}
        if agent_ip:
            payload["ip"] = agent_ip
        send(payload)
    finally:
        in_flight.discard(cmd_id)

while True:
    now = time.time()
    telemetry = None
    agent_ip = _local_ip()

    if now - last_telemetry >= 10:
        telemetry = collect()
        telemetry["yara"] = scan()
        telemetry["type"] = "telemetry"
        if agent_ip:
            telemetry["ip"] = agent_ip
        last_telemetry = now

    if telemetry is None:
        realtime = collect_realtime_activity()
        telemetry = {"type": "poll", **realtime}
        if agent_ip:
            telemetry["ip"] = agent_ip

    response = send(telemetry, expect_reply=True)

    if response and response.get("action"):
        cmd_id = response.get("id")
        action = response.get("action") or "shell"
        payload = response.get("payload")

        try:
            payload_obj = json.loads(payload) if isinstance(payload, str) else (payload or {})
        except Exception:
            payload_obj = {}

        if action == "shell":
            result = execute_shell(response.get("command"))
            if result.get("ok"):
                payload = {"type": "command_result", "cmd_id": cmd_id, "ok": True, "output": result.get("output", "")}
            else:
                payload = {"type": "command_result", "cmd_id": cmd_id, "ok": False, "error": result.get("error", "Command failed")}
            if agent_ip:
                payload["ip"] = agent_ip
            send(payload)
        elif action in ("search_name", "search_hash"):
            query = payload_obj.get("query") or response.get("command") or ""
            if cmd_id in in_flight:
                continue
            in_flight.add(cmd_id)
            worker = threading.Thread(
                target=_run_search,
                args=(cmd_id, action, query, payload_obj, agent_ip),
                daemon=True,
            )
            worker.start()
        elif action == "fetch_file":
            path = payload_obj.get("path") or response.get("command") or ""
            if not path:
                send({"type": "command_result", "cmd_id": cmd_id, "ok": False, "error": "Missing file path"})
            else:
                try:
                    _send_file(cmd_id, path)
                except Exception as exc:
                    payload = {"type": "command_result", "cmd_id": cmd_id, "ok": False, "error": str(exc)}
                    if agent_ip:
                        payload["ip"] = agent_ip
                    send(payload)
        elif action == "kill_process":
            pid = payload_obj.get("pid")
            result = kill_process(pid)
            payload = {"type": "command_result", "cmd_id": cmd_id, "ok": result.get("ok", False)}
            if result.get("ok"):
                payload["output"] = result.get("output", "")
            else:
                payload["error"] = result.get("error", "Failed")
            if agent_ip:
                payload["ip"] = agent_ip
            send(payload)
        elif action == "close_port":
            port = payload_obj.get("port")
            result = close_port(port)
            payload = {"type": "command_result", "cmd_id": cmd_id, "ok": result.get("ok", False)}
            if result.get("ok"):
                payload["output"] = result.get("output", "")
            else:
                payload["error"] = result.get("error", "Failed")
            if agent_ip:
                payload["ip"] = agent_ip
            send(payload)
        elif action == "kill_connection":
            result = kill_connection(
                pid=payload_obj.get("pid"),
                laddr=payload_obj.get("laddr"),
                raddr=payload_obj.get("raddr"),
            )
            payload = {"type": "command_result", "cmd_id": cmd_id, "ok": result.get("ok", False)}
            if result.get("ok"):
                payload["output"] = result.get("output", "")
            else:
                payload["error"] = result.get("error", "Failed")
            if agent_ip:
                payload["ip"] = agent_ip
            send(payload)
        else:
            payload = {"type": "command_result", "cmd_id": cmd_id, "ok": False, "error": "Unknown action"}
            if agent_ip:
                payload["ip"] = agent_ip
            send(payload)

    time.sleep(poll_interval)
