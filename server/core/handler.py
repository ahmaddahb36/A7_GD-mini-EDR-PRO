
import base64
import hashlib
import json
import os

from commands import complete_command, get_command
from detection import analyze
from db.models import (
    append_command_output,
    get_file_transfer,
    init_file_transfer,
    insert_endpoint,
    insert_alert,
    insert_network,
    insert_process_snapshot,
    insert_network_connections,
    insert_telemetry_log,
    has_alert_id,
    has_recent_alert,
    update_file_transfer_status,
    update_command_status,
    get_user_id_by_api_key,
    get_pending_command,
)

def handle_client(conn, addr):
    data = b""
    while True:
        part = conn.recv(4096)
        if not part:
            break
        data += part

    try:
        parsed = json.loads(data.decode())
        api_key = parsed.get("key")
        user_id = get_user_id_by_api_key(api_key)
        
        if user_id is None:
            print(f"[-] Unauthorized request from {addr[0]} (missing or invalid API key)")
            conn.sendall(json.dumps({"ok": False, "error": "Unauthorized"}).encode())
            conn.close()
            return

        ip = parsed.get("ip") or addr[0]
        msg_type = parsed.get("type", "telemetry")

        # Store raw operational logs for dashboard visibility.
        if msg_type in ("telemetry", "poll"):
            proc_count = len(parsed.get("processes") or [])
            ports = parsed.get("ports") or []
            remote_connections = parsed.get("remote_connections") or []
            web_activity = parsed.get("web_activity") or []
            insert_telemetry_log(
                user_id,
                ip,
                msg_type,
                f"Telemetry received (processes={proc_count}, ports={len(ports)})",
                {
                    "hostname": parsed.get("hostname"),
                    "os": parsed.get("os"),
                    "process_count": proc_count,
                    "conn_count": parsed.get("conn_count"),
                    "bytes_sent": parsed.get("bytes_sent"),
                    "bytes_recv": parsed.get("bytes_recv"),
                    "ports": ports[:30],
                    "remote_connections_count": len(remote_connections),
                    "web_activity_count": len(web_activity),
                    "yara": parsed.get("yara") or [],
                },
            )
            insert_telemetry_log(
                user_id,
                ip,
                "system.summary",
                f"System snapshot: host={parsed.get('hostname') or '-'} os={parsed.get('os') or '-'} processes={proc_count}",
                {
                    "hostname": parsed.get("hostname"),
                    "os": parsed.get("os"),
                    "process_count": proc_count,
                    "yara_count": len(parsed.get("yara") or []),
                },
            )
            insert_telemetry_log(
                user_id,
                ip,
                "network.summary",
                f"Network snapshot: open_ports={len(ports)} conn_count={parsed.get('conn_count') or 0}",
                {
                    "ports": ports[:50],
                    "conn_count": parsed.get("conn_count"),
                    "bytes_sent": parsed.get("bytes_sent"),
                    "bytes_recv": parsed.get("bytes_recv"),
                },
            )
            for remote_conn in remote_connections[:20]:
                insert_telemetry_log(
                    user_id,
                    ip,
                    "network.connection",
                    f"Remote connection {remote_conn.get('laddr') or '-'} -> {remote_conn.get('raddr') or '-'} ({remote_conn.get('status') or '-'})",
                    remote_conn,
                )
            for web in web_activity[:20]:
                insert_telemetry_log(
                    user_id,
                    ip,
                    "web.activity",
                    f"Web activity {web.get('name') or '-'} target={web.get('target') or '-'} pid={web.get('pid') or 0}",
                    web,
                )
        elif msg_type.startswith("command_result"):
            insert_telemetry_log(
                user_id,
                ip,
                msg_type,
                "Command execution update received",
                {"cmd_id": parsed.get("cmd_id"), "status": parsed.get("status"), "ok": parsed.get("ok", True)},
            )
        elif msg_type.startswith("file_"):
            insert_telemetry_log(
                user_id,
                ip,
                msg_type,
                "File transfer event received",
                {"cmd_id": parsed.get("cmd_id"), "source_path": parsed.get("source_path")},
            )

        if msg_type == "command_result":
            cmd_id = parsed.get("cmd_id")
            output = parsed.get("output", "")
            ok = bool(parsed.get("ok", True))
            error = parsed.get("error")
            if cmd_id is not None:
                status = "done" if ok else "error"
                final_output = output if ok else (error or output or "Command failed")
                complete_command(cmd_id, final_output, status=status)
            conn.sendall(json.dumps({"ok": True}).encode())
            conn.close()
            return

        if msg_type == "command_result_chunk":
            cmd_id = parsed.get("cmd_id")
            chunk = parsed.get("chunk", "")
            done = bool(parsed.get("done", False))
            if cmd_id is not None and chunk:
                append_command_output(cmd_id, chunk)
            if cmd_id is not None and done:
                update_command_status(cmd_id, parsed.get("status", "done"))
            conn.sendall(json.dumps({"ok": True}).encode())
            conn.close()
            return

        if msg_type == "file_start":
            cmd_id = parsed.get("cmd_id")
            source_path = parsed.get("source_path", "")
            size = parsed.get("size", 0)
            expected_sha = parsed.get("sha256", "")

            downloads_root = os.path.join(os.path.dirname(__file__), "..", "downloads")
            downloads_root = os.path.abspath(downloads_root)
            ip_dir = os.path.join(downloads_root, ip)
            os.makedirs(ip_dir, exist_ok=True)
            filename = os.path.basename(source_path) or f"cmd_{cmd_id}.bin"
            dest_path = os.path.join(ip_dir, f"{cmd_id}_{filename}")

            try:
                init_file_transfer(user_id, cmd_id, ip, source_path, dest_path, expected_sha, size)
                with open(dest_path, "wb"):
                    pass
                conn.sendall(json.dumps({"ok": True}).encode())
            except Exception as e:
                complete_command(cmd_id, f"File init failed: {e}", status="error")
                conn.sendall(json.dumps({"ok": False, "error": str(e)}).encode())
            conn.close()
            return

        if msg_type == "file_chunk":
            cmd_id = parsed.get("cmd_id")
            data_b64 = parsed.get("data") or ""
            transfer = get_file_transfer(user_id, cmd_id) if cmd_id is not None else None
            if not transfer:
                conn.sendall(json.dumps({"ok": False, "error": "Unknown transfer"}).encode())
                conn.close()
                return
            dest_path = transfer[3]
            try:
                chunk = base64.b64decode(data_b64.encode())
                with open(dest_path, "ab") as handle:
                    handle.write(chunk)
                conn.sendall(json.dumps({"ok": True}).encode())
            except Exception as e:
                update_file_transfer_status(cmd_id, "error")
                complete_command(cmd_id, f"File write failed: {e}", status="error")
                conn.sendall(json.dumps({"ok": False, "error": str(e)}).encode())
            conn.close()
            return

        if msg_type == "file_end":
            cmd_id = parsed.get("cmd_id")
            transfer = get_file_transfer(user_id, cmd_id) if cmd_id is not None else None
            if not transfer:
                conn.sendall(json.dumps({"ok": False, "error": "Unknown transfer"}).encode())
                conn.close()
                return
            dest_path = transfer[3]
            expected_sha = transfer[4]
            try:
                sha = hashlib.sha256()
                with open(dest_path, "rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        sha.update(chunk)
                actual_sha = sha.hexdigest()
                if expected_sha and expected_sha != actual_sha:
                    update_file_transfer_status(cmd_id, "error")
                    complete_command(
                        cmd_id,
                        f"SHA256 mismatch. Expected {expected_sha}, got {actual_sha}",
                        status="error",
                    )
                else:
                    update_file_transfer_status(cmd_id, "done")
                    complete_command(
                        cmd_id,
                        f"Saved to {dest_path} (sha256: {actual_sha})",
                        status="done",
                    )
                conn.sendall(json.dumps({"ok": True}).encode())
            except Exception as e:
                update_file_transfer_status(cmd_id, "error")
                complete_command(cmd_id, f"File finalize failed: {e}", status="error")
                conn.sendall(json.dumps({"ok": False, "error": str(e)}).encode())
            conn.close()
            return

        insert_endpoint(user_id, ip, parsed.get("hostname"), parsed.get("os"))
        if (
            parsed.get("ports") is not None
            or parsed.get("conn_count") is not None
            or parsed.get("bytes_sent") is not None
            or parsed.get("bytes_recv") is not None
        ):
            insert_network(
                user_id,
                ip,
                parsed.get("ports"),
                parsed.get("conn_count"),
                parsed.get("bytes_sent"),
                parsed.get("bytes_recv"),
            )
        if parsed.get("processes") is not None:
            insert_process_snapshot(user_id, ip, parsed.get("processes"))
        if parsed.get("remote_connections") is not None:
            insert_network_connections(user_id, ip, parsed.get("remote_connections"), parsed.get("processes"))
        if parsed.get("web_activity") is not None:
            web_connections = []
            for web in (parsed.get("web_activity") or []):
                target = str(web.get("target") or "").strip()
                if not target:
                    continue
                target_no_scheme = target.replace("https://", "").replace("http://", "")
                host = target_no_scheme.split("/")[0].strip() if target_no_scheme else target
                if not host:
                    continue
                web_connections.append(
                    {
                        "pid": int(web.get("pid") or 0),
                        "laddr": f"{ip}:0",
                        "raddr": f"{host}:443",
                        "rport": 443,
                        "status": web.get("status") or "WEB_ACTIVE",
                        "type": "web",
                        "cmdline": web.get("cmdline") or "",
                    }
                )
            if web_connections:
                insert_network_connections(user_id, ip, web_connections, parsed.get("processes"))
        if parsed.get("icmp_activity") is not None:
            icmp_connections = []
            for item in (parsed.get("icmp_activity") or []):
                target = str(item.get("target") or "").strip()
                if not target:
                    continue
                icmp_connections.append(
                    {
                        "pid": int(item.get("pid") or 0),
                        "laddr": f"{ip}:0",
                        "raddr": f"{target}:0",
                        "rport": 0,
                        "status": item.get("status") or "ICMP_ACTIVE",
                        "type": "icmp",
                        "cmdline": item.get("cmdline") or "",
                    }
                )
            if icmp_connections:
                insert_network_connections(user_id, ip, icmp_connections, parsed.get("processes"))

        alerts = analyze(parsed)

        for alert in alerts:
            alert_id = alert.get("alert_id")
            if not alert_id:
                fingerprint = f"{ip}|{alert.get('technique_id') or ''}|{alert.get('source') or ''}|{alert.get('message') or ''}"
                alert_id = hashlib.sha1(fingerprint.encode()).hexdigest()
            sev = alert.get("severity", "Unknown")
            msg = alert.get("message", "")
            if has_alert_id(user_id, ip, alert_id):
                continue
            if not has_recent_alert(user_id, ip, sev, msg, seconds=5):
                insert_alert(
                    user_id,
                    ip,
                    alert_id,
                    sev,
                    msg,
                    technique_id=alert.get("technique_id"),
                    tactic=alert.get("tactic"),
                    source=alert.get("source"),
                    details=alert.get("details"),
                )

        cmd = get_pending_command(user_id, ip)
        if cmd:
            update_command_status(cmd[0], "running")
            payload = {
                "id": cmd[0],
                "command": cmd[1],
                "action": cmd[2] or "shell",
                "payload": cmd[3],
            }
        else:
            payload = {"command": None}
        conn.sendall(json.dumps(payload).encode())

        print(f"[+] {ip} Alerts: {[a.get('message') for a in alerts]}")
    except Exception as e:
        print("Error:", e)

    conn.close()
