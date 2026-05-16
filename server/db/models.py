
import json
import os
import sqlite3
import sys
from datetime import datetime, timedelta

# Ensure server package root is on sys.path when run directly.
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config import DB_PATH

conn = sqlite3.connect(DB_PATH, check_same_thread=False)
c = conn.cursor()

def get_user_id_by_api_key(api_key):
    if not api_key:
        return None
    c.execute("SELECT id FROM users WHERE api_key=?", (api_key,))
    row = c.fetchone()
    return row[0] if row else None

c.execute("""
CREATE TABLE IF NOT EXISTS endpoints (
    user_id INTEGER,
    ip TEXT,
    hostname TEXT,
    os TEXT,
    last_seen TEXT
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    user_id INTEGER,
    ip TEXT,
    alert_id TEXT,
    severity TEXT,
    message TEXT,
    technique_id TEXT,
    tactic TEXT,
    source TEXT,
    details TEXT,
    handled INTEGER DEFAULT 0,
    handled_time TEXT,
    time TEXT
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    ip TEXT,
    command TEXT,
    action TEXT,
    payload TEXT,
    status TEXT,
    output TEXT,
    created_time TEXT
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS network_stats (
    user_id INTEGER,
    ip TEXT,
    ports TEXT,
    conn_count INTEGER,
    bytes_sent INTEGER,
    bytes_recv INTEGER,
    time TEXT
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS file_transfers (
    user_id INTEGER,
    cmd_id INTEGER,
    ip TEXT,
    source_path TEXT,
    dest_path TEXT,
    expected_sha256 TEXT,
    size INTEGER,
    status TEXT,
    time TEXT
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS process_snapshots (
    user_id INTEGER,
    ip TEXT,
    pid INTEGER,
    ppid INTEGER,
    name TEXT,
    username TEXT,
    cmdline TEXT,
    exe TEXT,
    sha256 TEXT,
    start_time TEXT,
    cpu_percent REAL,
    rss INTEGER,
    time TEXT
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS telemetry_logs (
    user_id INTEGER,
    ip TEXT,
    log_type TEXT,
    message TEXT,
    details TEXT,
    time TEXT
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS network_connections (
    user_id INTEGER,
    ip TEXT,
    laddr_ip TEXT,
    laddr_port INTEGER,
    raddr_ip TEXT,
    raddr_port INTEGER,
    protocol TEXT,
    status TEXT,
    pid INTEGER,
    process_name TEXT,
    process_cmdline TEXT,
    details TEXT,
    time TEXT
)
""")

conn.commit()

def _ensure_user_id_column():
    tables = [
        "endpoints", "alerts", "commands", "network_stats", "file_transfers",
        "process_snapshots", "telemetry_logs", "network_connections"
    ]
    for table in tables:
        c.execute(f"PRAGMA table_info({table})")
        existing = {row[1] for row in c.fetchall()}
        if "user_id" not in existing:
            c.execute(f"ALTER TABLE {table} ADD COLUMN user_id INTEGER")
    conn.commit()

def _ensure_command_columns():
    c.execute("PRAGMA table_info(commands)")
    existing = {row[1] for row in c.fetchall()}
    if "action" not in existing:
        c.execute("ALTER TABLE commands ADD COLUMN action TEXT")
    if "payload" not in existing:
        c.execute("ALTER TABLE commands ADD COLUMN payload TEXT")
    if "created_time" not in existing:
        c.execute("ALTER TABLE commands ADD COLUMN created_time TEXT")
    conn.commit()

def _ensure_alert_columns():
    c.execute("PRAGMA table_info(alerts)")
    existing = {row[1] for row in c.fetchall()}
    if "alert_id" not in existing:
        c.execute("ALTER TABLE alerts ADD COLUMN alert_id TEXT")
    if "technique_id" not in existing:
        c.execute("ALTER TABLE alerts ADD COLUMN technique_id TEXT")
    if "tactic" not in existing:
        c.execute("ALTER TABLE alerts ADD COLUMN tactic TEXT")
    if "source" not in existing:
        c.execute("ALTER TABLE alerts ADD COLUMN source TEXT")
    if "details" not in existing:
        c.execute("ALTER TABLE alerts ADD COLUMN details TEXT")
    if "handled" not in existing:
        c.execute("ALTER TABLE alerts ADD COLUMN handled INTEGER DEFAULT 0")
    if "handled_time" not in existing:
        c.execute("ALTER TABLE alerts ADD COLUMN handled_time TEXT")
    conn.commit()

def _ensure_alert_indexes():
    c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_alert_id ON alerts(alert_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ip_time ON alerts(ip, time)")
    conn.commit()

def _ensure_network_connections_columns():
    c.execute("PRAGMA table_info(network_connections)")
    existing = {row[1] for row in c.fetchall()}
    required = {
        "ip", "laddr_ip", "laddr_port", "raddr_ip", "raddr_port",
        "protocol", "status", "pid", "process_name", "process_cmdline",
        "details", "time",
    }
    if not existing or required.issubset(existing):
        return
    c.execute("""
        CREATE TABLE IF NOT EXISTS network_connections_new (
            user_id INTEGER,
            ip TEXT, laddr_ip TEXT, laddr_port INTEGER, raddr_ip TEXT, raddr_port INTEGER,
            protocol TEXT, status TEXT, pid INTEGER, process_name TEXT, process_cmdline TEXT,
            details TEXT, time TEXT
        )
    """)
    common = [col for col in required if col in existing]
    if "user_id" in existing:
        common.append("user_id")
    if common:
        cols = ", ".join(common)
        c.execute(f"INSERT INTO network_connections_new ({cols}) SELECT {cols} FROM network_connections")
    c.execute("DROP TABLE network_connections")
    c.execute("ALTER TABLE network_connections_new RENAME TO network_connections")
    conn.commit()

_ensure_user_id_column()
_ensure_command_columns()
_ensure_alert_columns()
_ensure_alert_indexes()
_ensure_network_connections_columns()

def insert_endpoint(user_id, ip, hostname, os):
    if hostname is None or os is None:
        c.execute(
            "SELECT hostname, os FROM endpoints WHERE user_id=? AND ip=? ORDER BY last_seen DESC LIMIT 1",
            (user_id, ip,),
        )
        row = c.fetchone()
        if row:
            if hostname is None:
                hostname = row[0]
            if os is None:
                os = row[1]
    c.execute("INSERT INTO endpoints (user_id, ip, hostname, os, last_seen) VALUES (?, ?, ?, ?, ?)",
              (user_id, ip, hostname, os, str(datetime.now())))
    conn.commit()

def insert_alert(user_id, ip, alert_id, sev, msg, technique_id=None, tactic=None, source=None, details=None):
    details_json = json.dumps(details, ensure_ascii=False) if isinstance(details, (dict, list)) else details
    c.execute(
        """
        INSERT INTO alerts (user_id, ip, alert_id, severity, message, technique_id, tactic, source, details, handled, handled_time, time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?)
        """,
        (user_id, ip, alert_id, sev, msg, technique_id, tactic, source, details_json, str(datetime.now())),
    )
    conn.commit()

def has_recent_alert(user_id, ip, sev, msg, seconds=60):
    c.execute(
        "SELECT time FROM alerts WHERE user_id=? AND ip=? AND severity=? AND message=? ORDER BY time DESC LIMIT 1",
        (user_id, ip, sev, msg),
    )
    row = c.fetchone()
    if not row:
        return False
    try:
        last_time = datetime.fromisoformat(row[0])
    except Exception:
        return False
    return datetime.now() - last_time <= timedelta(seconds=seconds)

def has_alert(user_id, ip, sev, msg):
    c.execute(
        "SELECT 1 FROM alerts WHERE user_id=? AND ip=? AND severity=? AND message=? LIMIT 1",
        (user_id, ip, sev, msg),
    )
    return c.fetchone() is not None

def has_alert_id(user_id, ip, alert_id):
    if not alert_id:
        return False
    c.execute(
        "SELECT 1 FROM alerts WHERE user_id=? AND ip=? AND alert_id=? LIMIT 1",
        (user_id, ip, alert_id),
    )
    return c.fetchone() is not None

def get_pending_command(user_id, ip):
    c.execute(
        """
        SELECT id, command, action, payload
        FROM commands
        WHERE user_id=? AND ip=? AND status='pending'
        ORDER BY id ASC
        LIMIT 1
        """,
        (user_id, ip,),
    )
    return c.fetchone()

def update_command(cmd_id, output, status="done"):
    c.execute("UPDATE commands SET status=?, output=? WHERE id=?", (status, output, cmd_id))
    conn.commit()

def append_command_output(cmd_id, chunk):
    c.execute(
        "UPDATE commands SET output=COALESCE(output, '') || ? WHERE id=?",
        (chunk, cmd_id),
    )
    conn.commit()

def update_command_status(cmd_id, status):
    c.execute("UPDATE commands SET status=? WHERE id=?", (status, cmd_id))
    conn.commit()

def insert_network(user_id, ip, ports, conn_count, bytes_sent, bytes_recv):
    ports_json = json.dumps(ports or [])
    c.execute(
        "INSERT INTO network_stats (user_id, ip, ports, conn_count, bytes_sent, bytes_recv, time) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            user_id,
            ip,
            ports_json,
            int(conn_count or 0),
            int(bytes_sent or 0),
            int(bytes_recv or 0),
            str(datetime.now()),
        ),
    )
    conn.commit()

def insert_process_snapshot(user_id, ip, processes, max_rows=200):
    now = str(datetime.now())
    rows = []
    for proc in (processes or [])[:max_rows]:
        rows.append(
            (
                user_id,
                ip,
                int(proc.get("pid") or 0),
                int(proc.get("ppid") or 0),
                proc.get("name"),
                proc.get("username"),
                proc.get("cmdline"),
                proc.get("exe"),
                proc.get("sha256"),
                proc.get("started"),
                float(proc.get("cpu_percent") or 0.0),
                int(proc.get("memory_rss") or 0),
                now,
            )
        )
    if not rows:
        return
    c.executemany(
        """
        INSERT INTO process_snapshots
        (user_id, ip, pid, ppid, name, username, cmdline, exe, sha256, start_time, cpu_percent, rss, time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    conn.commit()

def insert_telemetry_log(user_id, ip, log_type, message, details=None):
    details_json = json.dumps(details, ensure_ascii=False) if isinstance(details, (dict, list)) else details
    c.execute(
        "INSERT INTO telemetry_logs (user_id, ip, log_type, message, details, time) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, ip, log_type, message, details_json, str(datetime.now())),
    )
    conn.commit()

def insert_network_connections(user_id, ip, connections, processes=None, max_rows=200):
    proc_index = {}
    for proc in (processes or []):
        try:
            pid = int(proc.get("pid") or 0)
        except Exception:
            pid = 0
        if pid <= 0:
            continue
        proc_index[pid] = {
            "name": proc.get("name") or "",
            "cmdline": proc.get("cmdline") or "",
        }

    rows = []
    now = str(datetime.now())
    for conn_item in (connections or [])[:max_rows]:
        laddr = str(conn_item.get("laddr") or "")
        raddr = str(conn_item.get("raddr") or "")
        pid = int(conn_item.get("pid") or 0)

        l_ip = ""
        l_port = 0
        if ":" in laddr:
            l_ip, l_port_raw = laddr.rsplit(":", 1)
            try:
                l_port = int(l_port_raw)
            except Exception:
                l_port = 0

        r_ip = ""
        r_port = 0
        if ":" in raddr:
            r_ip, r_port_raw = raddr.rsplit(":", 1)
            try:
                r_port = int(r_port_raw)
            except Exception:
                r_port = 0

        pinfo = proc_index.get(pid, {})
        rows.append(
            (
                user_id,
                ip,
                l_ip,
                l_port,
                r_ip,
                r_port,
                str(conn_item.get("type") or ""),
                str(conn_item.get("status") or ""),
                pid,
                pinfo.get("name", ""),
                pinfo.get("cmdline", ""),
                json.dumps(conn_item, ensure_ascii=False),
                now,
            )
        )

    if not rows:
        return

    c.executemany(
        """
        INSERT INTO network_connections
        (user_id, ip, laddr_ip, laddr_port, raddr_ip, raddr_port, protocol, status, pid, process_name, process_cmdline, details, time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    conn.commit()

def init_file_transfer(user_id, cmd_id, ip, source_path, dest_path, expected_sha256, size):
    c.execute(
        "INSERT INTO file_transfers (user_id, cmd_id, ip, source_path, dest_path, expected_sha256, size, status, time) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            user_id,
            cmd_id,
            ip,
            source_path,
            dest_path,
            expected_sha256,
            int(size or 0),
            "in_progress",
            str(datetime.now()),
        ),
    )
    conn.commit()

def get_file_transfer(user_id, cmd_id):
    c.execute(
        "SELECT cmd_id, ip, source_path, dest_path, expected_sha256, size, status FROM file_transfers WHERE user_id=? AND cmd_id=?",
        (user_id, cmd_id,),
    )
    return c.fetchone()

def update_file_transfer_status(cmd_id, status):
    c.execute("UPDATE file_transfers SET status=? WHERE cmd_id=?", (status, cmd_id))
    conn.commit()
