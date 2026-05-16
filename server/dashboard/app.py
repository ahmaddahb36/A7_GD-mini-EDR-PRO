
import json
import os
import sys
import csv
import io
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta

import bcrypt
from flask import Flask, Response, jsonify, render_template, request, redirect, url_for, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import sqlite3

# Ensure the server package root is on sys.path when run from repo root.
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config import DB_PATH

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "A7gd-edr-s3cr3t-k3y-2024!")

# ── Email config (set these as environment variables on the server) ───────────
MAIL_USER = os.environ.get("MAIL_USER", "stand7738@gmail.com")   # your Gmail address
MAIL_PASS = os.environ.get("MAIL_PASS", "ejksuwluvvuawzsh")   # your App Password
MAIL_FROM = os.environ.get("MAIL_USER", "A7._.GD mini EDR PRO")
BASE_URL  = os.environ.get("BASE_URL",  "http://194.37.82.174:5000") # in server BASE_URL  = os.environ.get("BASE_URL",  "http://edr.a7gd.tech/")

# ── Flask-Login ───────────────────────────────────────────────────────────────
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = None

class _User(UserMixin):
    def __init__(self, row):
        self.id       = str(row[0])
        self.email    = row[1]
        self.api_key  = row[2]
        self.verified = bool(row[3])

@login_manager.user_loader
def _load_user(uid):
    db = _db_conn()
    row = db.execute("SELECT id,email,api_key,verified FROM users WHERE id=?", (uid,)).fetchone()
    db.close()
    return _User(row) if row else None

# ── User table ────────────────────────────────────────────────────────────────
def _ensure_user_table():
    db = sqlite3.connect(DB_PATH)
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            email      TEXT UNIQUE NOT NULL,
            pw_hash    TEXT NOT NULL,
            api_key    TEXT UNIQUE,
            verified   INTEGER DEFAULT 0,
            verify_code TEXT,
            verify_exp  TEXT,
            reset_token TEXT,
            reset_exp   TEXT,
            created    TEXT DEFAULT (datetime('now'))
        )
    """)
    # Migration: add api_key if missing
    cursor = db.cursor()
    cursor.execute("PRAGMA table_info(users)")
    cols = {row[1] for row in cursor.fetchall()}
    if "api_key" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN api_key TEXT")
        # Generate keys for existing users
        rows = db.execute("SELECT id FROM users WHERE api_key IS NULL").fetchall()
        for r in rows:
            new_key = secrets.token_hex(16)
            db.execute("UPDATE users SET api_key=? WHERE id=?", (new_key, r[0]))
    db.commit()
    db.close()

# ── Email helper ──────────────────────────────────────────────────────────────
def _send_email(to, subject, html_body):
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = MAIL_FROM
        msg["To"]      = to
        msg.attach(MIMEText(html_body, "html"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
            s.login(MAIL_USER, MAIL_PASS)
            s.sendmail(MAIL_USER, to, msg.as_string())
        return True
    except Exception as e:
        app.logger.error(f"Email error: {e}")
        return False

# ── Auth routes ───────────────────────────────────────────────────────────────

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        email    = (request.form.get("email") or "").strip().lower()
        password = (request.form.get("password") or "")
        if len(password) < 8:
            error = "Password must be at least 8 characters"
        else:
            pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            code    = str(secrets.randbelow(900000) + 100000)   # 6-digit code
            exp     = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
            api_key = secrets.token_hex(16)
            try:
                db = _db_conn()
                db.execute(
                    "INSERT INTO users (email,pw_hash,api_key,verify_code,verify_exp) VALUES (?,?,?,?,?)",
                    (email, pw_hash, api_key, code, exp)
                )
                db.commit()
                db.close()
                _send_email(email, "Your EDR verification code", f"""
                <div style="font-family:sans-serif;background:#050505;color:#f4f4f5;padding:40px;border-radius:16px;max-width:480px;border:1px solid #1a1a1a;margin:0 auto">
                  <div style="text-align:center;margin-bottom:24px">
                    <img src="{BASE_URL}/static/logo.png" alt="A7._.GD Logo" style="width:110px;height:auto">
                  </div>
                  <h2 style="color:#00e5ff;margin-bottom:8px;text-align:center">Verification Code</h2>
                  <p style="color:#a1a1aa;text-align:center">Use the code below to complete your registration:</p>
                  <div style="font-size:38px;font-weight:800;letter-spacing:10px;color:#00e5ff;margin:24px 0;text-align:center;background:rgba(0,229,255,0.05);padding:15px;border-radius:10px">{code}</div>
                  <p style="color:#71717a;font-size:13px;text-align:center">Expires in 15 minutes. Do not share this code.</p>
                  <div style="margin-top:32px;padding-top:20px;border-top:1px solid #1a1a1a;text-align:center;font-size:11px;color:#525252">
                    Developed by <a href="https://github.com/ahmaddahb36" style="color:#00e5ff;text-decoration:none;font-weight:600">A7_GD</a>
                  </div>
                </div>""")
                session["pending_email"] = email
                return redirect(url_for("verify_email"))
            except sqlite3.IntegrityError:
                error = "Email already registered"
    return render_template("register.html", error=error)


@app.route("/verify", methods=["GET", "POST"])
def verify_email():
    email = session.get("pending_email")
    if not email:
        return redirect(url_for("register"))
    error = None
    if request.method == "POST":
        code = (request.form.get("code") or "").strip()
        db   = _db_conn()
        row  = db.execute(
            "SELECT id, verify_code, verify_exp FROM users WHERE email=?", (email,)
        ).fetchone()
        if not row:
            return redirect(url_for("register"))
        uid, stored_code, exp_str = row
        expired = datetime.utcnow() > datetime.fromisoformat(exp_str) if exp_str else True
        if expired:
            error = "Code expired — please register again"
        elif code != stored_code:
            error = "Wrong code"
        else:
            db.execute("UPDATE users SET verified=1, verify_code=NULL, verify_exp=NULL WHERE id=?", (uid,))
            db.commit()
            db.close()
            session.pop("pending_email", None)
            return redirect(url_for("login"))
        db.close()
    return render_template("verify.html", email=email, error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        email    = (request.form.get("email") or "").strip().lower()
        password = (request.form.get("password") or "").encode()
        db  = _db_conn()
        row = db.execute("SELECT id,email,api_key,verified,pw_hash FROM users WHERE email=?", (email,)).fetchone()
        db.close()
        if not row:
            error = "Invalid credentials"
        elif not row[3]:
            error = "Email not verified — check your inbox"
        elif not bcrypt.checkpw(password, row[4].encode()):
            error = "Invalid credentials"
        else:
            login_user(_User(row), remember=True)
            return redirect(url_for("index"))
    return render_template("login.html", error=error)


@app.route("/forgot", methods=["GET", "POST"])
def forgot_password():
    sent = False
    error = None
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        db    = _db_conn()
        row   = db.execute("SELECT id FROM users WHERE email=? AND verified=1", (email,)).fetchone()
        if row:
            token = secrets.token_urlsafe(32)
            exp   = (datetime.utcnow() + timedelta(hours=1)).isoformat()
            db.execute("UPDATE users SET reset_token=?, reset_exp=? WHERE id=?", (token, exp, row[0]))
            db.commit()
            link = f"{BASE_URL}/reset/{token}"
            _send_email(email, "Reset your EDR password", f"""
            <div style="font-family:sans-serif;background:#050505;color:#f4f4f5;padding:40px;border-radius:16px;max-width:480px;border:1px solid #1a1a1a;margin:0 auto">
              <div style="text-align:center;margin-bottom:24px">
                <img src="{BASE_URL}/static/logo.png" alt="A7._.GD Logo" style="width:110px;height:auto">
              </div>
              <h2 style="color:#00e5ff;margin-bottom:8px;text-align:center">Password Reset</h2>
              <p style="color:#a1a1aa;text-align:center;margin-bottom:24px">Click the button below to secure your account:</p>
              <div style="text-align:center">
                <a href="{link}" style="display:inline-block;padding:14px 28px;background:#00e5ff;color:#050505;border-radius:10px;text-decoration:none;font-weight:700;box-shadow:0 0 20px rgba(0,229,255,0.3)">Reset My Password</a>
              </div>
              <p style="color:#71717a;font-size:13px;text-align:center;margin-top:24px">Link expires in 1 hour. If you didn't request this, ignore this email.</p>
              <div style="margin-top:32px;padding-top:20px;border-top:1px solid #1a1a1a;text-align:center;font-size:11px;color:#525252">
                Developed by <a href="https://github.com/ahmaddahb36" style="color:#00e5ff;text-decoration:none;font-weight:600">A7_GD</a>
              </div>
            </div>""")
        db.close()
        sent = True   # always show success (security: don't reveal if email exists)
    return render_template("forgot.html", sent=sent, error=error)


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    db  = _db_conn()
    row = db.execute("SELECT id, reset_exp FROM users WHERE reset_token=?", (token,)).fetchone()
    if not row or datetime.utcnow() > datetime.fromisoformat(row[1]):
        db.close()
        return render_template("reset.html", invalid=True)
    error = None
    if request.method == "POST":
        pw = request.form.get("password") or ""
        if len(pw) < 8:
            error = "Password must be at least 8 characters"
        else:
            pw_hash = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
            db.execute("UPDATE users SET pw_hash=?, reset_token=NULL, reset_exp=NULL WHERE id=?", (pw_hash, row[0]))
            db.commit()
            db.close()
            return redirect(url_for("login"))
    db.close()
    return render_template("reset.html", invalid=False, token=token, error=error)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))



def _ensure_dashboard_schema():
    db = sqlite3.connect(DB_PATH)
    c = db.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS telemetry_logs (
            ip TEXT,
            log_type TEXT,
            message TEXT,
            details TEXT,
            time TEXT
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS process_snapshots (
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
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS network_connections (
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
        """
    )
    c.execute("PRAGMA table_info(network_connections)")
    nc_cols = {row[1] for row in c.fetchall()}
    nc_required = {
        "ip",
        "laddr_ip",
        "laddr_port",
        "raddr_ip",
        "raddr_port",
        "protocol",
        "status",
        "pid",
        "process_name",
        "process_cmdline",
        "details",
        "time",
    }
    if nc_cols and not nc_required.issubset(nc_cols):
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS network_connections_new (
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
            """
        )
        common = [col for col in nc_required if col in nc_cols]
        if common:
            cols = ", ".join(common)
            c.execute(
                f"INSERT INTO network_connections_new ({cols}) SELECT {cols} FROM network_connections"
            )
        c.execute("DROP TABLE network_connections")
        c.execute("ALTER TABLE network_connections_new RENAME TO network_connections")
    c.execute("PRAGMA table_info(alerts)")
    cols = {row[1] for row in c.fetchall()}
    if "alert_id" not in cols:
        c.execute("ALTER TABLE alerts ADD COLUMN alert_id TEXT")
    if "technique_id" not in cols:
        c.execute("ALTER TABLE alerts ADD COLUMN technique_id TEXT")
    if "tactic" not in cols:
        c.execute("ALTER TABLE alerts ADD COLUMN tactic TEXT")
    if "source" not in cols:
        c.execute("ALTER TABLE alerts ADD COLUMN source TEXT")
    if "details" not in cols:
        c.execute("ALTER TABLE alerts ADD COLUMN details TEXT")
    if "handled" not in cols:
        c.execute("ALTER TABLE alerts ADD COLUMN handled INTEGER DEFAULT 0")
    if "handled_time" not in cols:
        c.execute("ALTER TABLE alerts ADD COLUMN handled_time TEXT")
    db.commit()
    db.close()

@app.route("/")
@login_required
def index():
    db = sqlite3.connect(DB_PATH)
    c = db.cursor()

    c.execute("SELECT COUNT(DISTINCT ip) FROM endpoints WHERE user_id=?", (current_user.id,))
    total = c.fetchone()[0]

    c.execute("SELECT * FROM alerts WHERE user_id=? ORDER BY time DESC LIMIT 10", (current_user.id,))
    alerts = c.fetchall()

    return render_template("index.html", total=total, alerts=alerts, user=current_user)


def _db_conn():
    return sqlite3.connect(DB_PATH)


_ensure_user_table()
_ensure_dashboard_schema()


@app.route("/api/endpoints")
@login_required
def api_endpoints():
    db = _db_conn()
    c = db.cursor()

    c.execute(
        """
        SELECT e.ip, e.hostname, e.os, e.last_seen
        FROM endpoints e
        INNER JOIN (
            SELECT ip, MAX(last_seen) AS last_seen
            FROM endpoints
            WHERE user_id=?
            GROUP BY ip
        ) latest
        ON e.ip = latest.ip AND e.last_seen = latest.last_seen
        WHERE e.user_id=?
        ORDER BY e.last_seen DESC
        LIMIT 200
        """,
        (current_user.id, current_user.id)
    )
    rows = c.fetchall()

    now = datetime.now()
    # Mark endpoint offline if no telemetry within 20 seconds.
    online_threshold = now - timedelta(seconds=20)

    endpoints = []
    for ip, hostname, os_name, last_seen in rows:
        try:
            last_seen_dt = datetime.fromisoformat(last_seen)
        except Exception:
            last_seen_dt = None
        is_online = bool(last_seen_dt and last_seen_dt >= online_threshold)

        endpoints.append({
            "ip": ip,
            "hostname": hostname or "-",
            "os": os_name or "-",
            "last_seen": last_seen or "-",
            "status": "online" if is_online else "offline",
        })

    return jsonify({"endpoints": endpoints})


@app.route("/api/endpoints/summary")
@login_required
def api_endpoints_summary():
    try:
        db = _db_conn()
        c = db.cursor()
        c.execute(
            """
            SELECT ip, MAX(last_seen) AS last_seen
            FROM endpoints
            WHERE user_id=?
            GROUP BY ip
            """,
            (current_user.id,)
        )
        rows = c.fetchall()
        now = datetime.now()
        online_threshold = now - timedelta(seconds=20)

        online = 0
        offline = 0
        for _, last_seen in rows:
            try:
                last_seen_dt = datetime.fromisoformat(last_seen)
            except Exception:
                last_seen_dt = None
            if last_seen_dt and last_seen_dt >= online_threshold:
                online += 1
            else:
                offline += 1

        return jsonify({"ok": True, "online": online, "offline": offline, "total": online + offline})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/alerts")
@login_required
def api_alerts():
    db = _db_conn()
    c = db.cursor()

    c.execute(
        """
        SELECT a.ip, a.alert_id, a.severity, a.message, a.technique_id, a.tactic, a.source, a.time
               , a.details, a.handled, a.handled_time
        FROM alerts a
        WHERE a.user_id=?
        ORDER BY a.time DESC
        LIMIT 200
        """,
        (current_user.id,)
    )
    alerts = c.fetchall()

    payload = [
        {
            "ip": ip,
            "alert_id": alert_id,
            "severity": (sev or "unknown"),
            "message": msg,
            "technique_id": technique_id,
            "tactic": tactic,
            "source": source,
            "time": t,
            "details": details,
            "handled": int(handled or 0),
            "handled_time": handled_time,
        }
        for ip, alert_id, sev, msg, technique_id, tactic, source, t, details, handled, handled_time in alerts
    ]

    return jsonify({"alerts": payload})


@app.route("/api/alerts/summary")
@login_required
def api_alerts_summary():
    db = _db_conn()
    c = db.cursor()

    c.execute(
        """
        SELECT severity, COUNT(*)
        FROM alerts
        WHERE user_id=?
        GROUP BY severity
        """,
        (current_user.id,)
    )
    rows = c.fetchall()

    summary = {"low": 0, "medium": 0, "high": 0, "critical": 0, "unknown": 0}
    for sev, count in rows:
        key = (sev or "unknown").lower()
        summary[key] = count

    return jsonify(summary)


@app.route("/api/commands", methods=["GET", "POST"])
@login_required
def api_commands():
    if request.method == "GET":
        db = _db_conn()
        c = db.cursor()
        c.execute(
            "SELECT id, ip, command, action, payload, status, output, created_time FROM commands WHERE user_id=? ORDER BY id DESC LIMIT 50",
            (current_user.id,)
        )
        rows = c.fetchall()

        items = [
            {
                "id": row[0],
                "ip": row[1],
                "command": row[2],
                "action": row[3],
                "payload": row[4],
                "status": row[5],
                "output": row[6] or "",
                "created_time": row[7],
            }
            for row in rows
        ]

        return jsonify({"commands": items})

    payload = request.get_json(silent=True) or {}
    ip = (payload.get("ip") or "").strip()
    command = (payload.get("command") or "").strip()
    action = (payload.get("action") or "shell").strip()
    action_payload = payload.get("payload")

    if not ip:
        return jsonify({"ok": False, "error": "Missing ip"}), 400
    if action == "shell" and not command:
        return jsonify({"ok": False, "error": "Missing command"}), 400

    db = _db_conn()
    c = db.cursor()

    c.execute(
        """
        INSERT INTO commands (user_id, ip, command, action, payload, status, output, created_time)
        VALUES (?, ?, ?, ?, ?, 'pending', '', ?)
        """,
        (current_user.id, ip, command, action, json.dumps(action_payload) if action_payload is not None else None, str(datetime.now())),
    )
    db.commit()

    return jsonify({"ok": True})


@app.route("/api/reset", methods=["POST"])
@login_required
def api_reset():
    payload = request.get_json(silent=True) or {}
    ip = (payload.get("ip") or "").strip()
    scope = (payload.get("scope") or "ip").strip()

    db = _db_conn()
    c = db.cursor()

    try:
        if scope == "all":
            c.execute("DELETE FROM endpoints WHERE user_id=?", (current_user.id,))
            c.execute("DELETE FROM alerts WHERE user_id=?", (current_user.id,))
            c.execute("DELETE FROM commands WHERE user_id=?", (current_user.id,))
            c.execute("DELETE FROM network_stats WHERE user_id=?", (current_user.id,))
            c.execute("DELETE FROM network_connections WHERE user_id=?", (current_user.id,))
            c.execute("DELETE FROM file_transfers WHERE user_id=?", (current_user.id,))
            c.execute("DELETE FROM process_snapshots WHERE user_id=?", (current_user.id,))
            c.execute("DELETE FROM telemetry_logs WHERE user_id=?", (current_user.id,))
        else:
            if not ip:
                return jsonify({"ok": False, "error": "Missing ip"}), 400
            c.execute("DELETE FROM endpoints WHERE user_id=? AND ip=?", (current_user.id, ip))
            c.execute("DELETE FROM alerts WHERE user_id=? AND ip=?", (current_user.id, ip))
            c.execute("DELETE FROM commands WHERE user_id=? AND ip=?", (current_user.id, ip))
            c.execute("DELETE FROM network_stats WHERE user_id=? AND ip=?", (current_user.id, ip))
            c.execute("DELETE FROM network_connections WHERE user_id=? AND ip=?", (current_user.id, ip))
            c.execute("DELETE FROM file_transfers WHERE user_id=? AND ip=?", (current_user.id, ip))
            c.execute("DELETE FROM process_snapshots WHERE user_id=? AND ip=?", (current_user.id, ip))
            c.execute("DELETE FROM telemetry_logs WHERE user_id=? AND ip=?", (current_user.id, ip))

        db.commit()
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/alerts/search")
@login_required
def api_alerts_search():
    ip = (request.args.get("ip") or "").strip()
    severity = (request.args.get("severity") or "").strip().lower()
    query = (request.args.get("q") or "").strip()
    since = (request.args.get("since") or "").strip()
    until = (request.args.get("until") or "").strip()
    try:
        limit = int(request.args.get("limit") or 100)
    except ValueError:
        limit = 100
    limit = max(1, min(limit, 200))

    conditions = []
    params = []

    if ip:
        conditions.append("ip = ?")
        params.append(ip)
    if severity:
        conditions.append("LOWER(severity) = ?")
        params.append(severity)
    if query:
        conditions.append("(message LIKE ? OR ip LIKE ?)")
        like = f"%{query}%"
        params.extend([like, like])
    if since:
        conditions.append("time >= ?")
        params.append(since)
    if until:
        conditions.append("time <= ?")
        params.append(until)

    sql = "SELECT ip, alert_id, severity, message, technique_id, tactic, source, time, details, handled, handled_time FROM alerts"
    conditions.append("user_id = ?")
    params.append(current_user.id)
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    sql += " ORDER BY time DESC LIMIT ?"
    params.append(limit)

    db = _db_conn()
    c = db.cursor()
    c.execute(sql, params)
    rows = c.fetchall()

    payload = [
        {
            "ip": row[0],
            "alert_id": row[1],
            "severity": (row[2] or "unknown"),
            "message": row[3],
            "technique_id": row[4],
            "tactic": row[5],
            "source": row[6],
            "time": row[7],
            "details": row[8],
            "handled": int(row[9] or 0),
            "handled_time": row[10],
        }
        for row in rows
    ]

    return jsonify({"alerts": payload})


@app.route("/api/alerts/handle", methods=["POST"])
@login_required
def api_alerts_handle():
    payload = request.get_json(silent=True) or {}
    ip = (payload.get("ip") or "").strip()
    alert_id = (payload.get("alert_id") or "").strip()
    handled = 1 if bool(payload.get("handled", True)) else 0
    if not alert_id:
        return jsonify({"ok": False, "error": "Missing alert_id"}), 400

    db = _db_conn()
    c = db.cursor()
    handled_time = str(datetime.now()) if handled else None
    if ip:
        c.execute(
            "UPDATE alerts SET handled=?, handled_time=? WHERE user_id=? AND ip=? AND alert_id=?",
            (handled, handled_time, current_user.id, ip, alert_id),
        )
    else:
        c.execute(
            "UPDATE alerts SET handled=?, handled_time=? WHERE user_id=? AND alert_id=?",
            (handled, handled_time, current_user.id, alert_id),
        )
    db.commit()
    return jsonify({"ok": True, "updated": c.rowcount, "handled": handled})


@app.route("/api/logs/recent")
@login_required
def api_logs_recent():
    ip = (request.args.get("ip") or "").strip()
    log_type = (request.args.get("type") or "").strip().lower()
    query = (request.args.get("q") or "").strip()
    try:
        limit = int(request.args.get("limit") or 200)
    except ValueError:
        limit = 200
    limit = max(1, min(limit, 500))

    conditions = []
    params = []
    if ip:
        conditions.append("ip = ?")
        params.append(ip)
    if log_type:
        conditions.append("LOWER(log_type) = ?")
        params.append(log_type)
    if query:
        conditions.append("(message LIKE ? OR details LIKE ?)")
        like = f"%{query}%"
        params.extend([like, like])

    sql = "SELECT ip, log_type, message, details, time FROM telemetry_logs"
    conditions.append("user_id = ?")
    params.append(current_user.id)
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    sql += " ORDER BY time DESC LIMIT ?"
    params.append(limit)

    db = _db_conn()
    c = db.cursor()
    c.execute(sql, params)
    rows = c.fetchall()

    logs = []
    for ip_value, type_value, message, details, time_value in rows:
        parsed_details = details
        if isinstance(details, str):
            try:
                parsed_details = json.loads(details)
            except Exception:
                parsed_details = details
        logs.append(
            {
                "ip": ip_value,
                "type": type_value,
                "message": message,
                "details": parsed_details,
                "time": time_value,
            }
        )
    return jsonify({"logs": logs})


@app.route("/api/soc/feed")
@login_required
def api_soc_feed():
    ip_filter = (request.args.get("ip") or "").strip()
    source_filter = (request.args.get("source") or "").strip().lower()
    query = (request.args.get("q") or "").strip().lower()
    try:
        limit = int(request.args.get("limit") or 300)
    except ValueError:
        limit = 300
    limit = max(50, min(limit, 1000))

    db = _db_conn()
    c = db.cursor()
    c.execute(
        """
        SELECT time, ip, source_type, level, message, technique_id, tactic
        FROM (
            SELECT time, ip, 'alert' AS source_type, severity AS level,
                   ('ALERT: ' || message) AS message, technique_id, tactic
            FROM alerts WHERE user_id=?
            UNION ALL
            SELECT time, ip, ('log:' || log_type) AS source_type, 'info' AS level,
                   message, NULL AS technique_id, NULL AS tactic
            FROM telemetry_logs WHERE user_id=?
            UNION ALL
            SELECT time, ip, 'network' AS source_type, 'info' AS level,
                   ('NET: conn=' || COALESCE(conn_count, 0) || ', sent=' || COALESCE(bytes_sent, 0) || ', recv=' || COALESCE(bytes_recv, 0)) AS message,
                   NULL AS technique_id, NULL AS tactic
            FROM network_stats WHERE user_id=?
            UNION ALL
            SELECT time, ip, 'system' AS source_type, 'info' AS level,
                   ('PROC: ' || COALESCE(name, '-') || ' pid=' || COALESCE(pid, 0) || ' user=' || COALESCE(username, '-')) AS message,
                   NULL AS technique_id, NULL AS tactic
            FROM process_snapshots WHERE user_id=?
        )
        ORDER BY time DESC
        LIMIT ?
        """,
        (current_user.id, current_user.id, current_user.id, current_user.id, limit * 3),
    )
    rows = c.fetchall()
    feed = []
    for row in rows:
        item = {
            "time": row[0],
            "ip": row[1],
            "source_type": row[2],
            "level": row[3],
            "message": row[4],
            "technique_id": row[5],
            "tactic": row[6],
        }
        if ip_filter and str(item["ip"]) != ip_filter:
            continue
        if source_filter and source_filter not in str(item["source_type"]).lower():
            continue
        if query:
            blob = f"{item['message']} {item['source_type']} {item['technique_id'] or ''} {item['tactic'] or ''}".lower()
            if query not in blob:
                continue
        feed.append(item)
        if len(feed) >= limit:
            break

    return jsonify({"feed": feed})


@app.route("/api/soc/export.csv")
@login_required
def api_soc_export_csv():
    ip_filter = (request.args.get("ip") or "").strip()
    source_filter = (request.args.get("source") or "").strip().lower()
    query = (request.args.get("q") or "").strip().lower()
    try:
        limit = int(request.args.get("limit") or 5000)
    except ValueError:
        limit = 5000
    limit = max(100, min(limit, 20000))

    db = _db_conn()
    c = db.cursor()
    c.execute(
        """
        SELECT time, ip, source_type, level, message, technique_id, tactic
        FROM (
            SELECT time, ip, 'alert' AS source_type, severity AS level,
                   ('ALERT: ' || message) AS message, technique_id, tactic
            FROM alerts WHERE user_id=?
            UNION ALL
            SELECT time, ip, ('log:' || log_type) AS source_type, 'info' AS level,
                   message, NULL AS technique_id, NULL AS tactic
            FROM telemetry_logs WHERE user_id=?
            UNION ALL
            SELECT time, ip, 'network' AS source_type, 'info' AS level,
                   ('NET: conn=' || COALESCE(conn_count, 0) || ', sent=' || COALESCE(bytes_sent, 0) || ', recv=' || COALESCE(bytes_recv, 0)) AS message,
                   NULL AS technique_id, NULL AS tactic
            FROM network_stats WHERE user_id=?
            UNION ALL
            SELECT time, ip, 'system' AS source_type, 'info' AS level,
                   ('PROC: ' || COALESCE(name, '-') || ' pid=' || COALESCE(pid, 0) || ' user=' || COALESCE(username, '-')) AS message,
                   NULL AS technique_id, NULL AS tactic
            FROM process_snapshots WHERE user_id=?
        )
        ORDER BY time DESC
        LIMIT ?
        """,
        (current_user.id, current_user.id, current_user.id, current_user.id, limit * 3),
    )
    rows = c.fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["time", "ip", "source_type", "level", "message", "technique_id", "tactic"])

    emitted = 0
    for row in rows:
        item = {
            "time": row[0],
            "ip": row[1],
            "source_type": row[2],
            "level": row[3],
            "message": row[4],
            "technique_id": row[5],
            "tactic": row[6],
        }
        if ip_filter and str(item["ip"]) != ip_filter:
            continue
        if source_filter and source_filter not in str(item["source_type"]).lower():
            continue
        if query:
            blob = f"{item['message']} {item['source_type']} {item['technique_id'] or ''} {item['tactic'] or ''}".lower()
            if query not in blob:
                continue
        writer.writerow(
            [
                item["time"],
                item["ip"],
                item["source_type"],
                item["level"],
                item["message"],
                item["technique_id"] or "",
                item["tactic"] or "",
            ]
        )
        emitted += 1
        if emitted >= limit:
            break

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=soc_feed_export.csv"},
    )


@app.route("/api/network/summary")
@login_required
def api_network_summary():
    db = _db_conn()
    c = db.cursor()
    c.execute(
        """
        SELECT n.ip, n.ports, n.conn_count, n.bytes_sent, n.bytes_recv, n.time
        FROM network_stats n
        INNER JOIN (
            SELECT ip, MAX(time) AS time
            FROM network_stats
            WHERE user_id=?
            GROUP BY ip
        ) latest
        ON n.ip = latest.ip AND n.time = latest.time
        WHERE n.user_id=?
        ORDER BY n.time DESC
        LIMIT 50
        """,
        (current_user.id, current_user.id)
    )
    rows = c.fetchall()

    items = []
    for ip, ports_raw, conn_count, bytes_sent, bytes_recv, t in rows:
        try:
            ports = json.loads(ports_raw or "[]")
        except Exception:
            ports = []
        items.append(
            {
                "ip": ip,
                "ports": ports,
                "conn_count": conn_count or 0,
                "bytes_sent": bytes_sent or 0,
                "bytes_recv": bytes_recv or 0,
                "time": t,
            }
        )

    return jsonify({"network": items})


@app.route("/api/network/connections")
@login_required
def api_network_connections():
    ip = (request.args.get("ip") or "").strip()
    protocol = (request.args.get("protocol") or "").strip().lower()
    try:
        limit = int(request.args.get("limit") or 200)
    except ValueError:
        limit = 200
    limit = max(1, min(limit, 1000))

    conditions = []
    params = []
    if ip:
        conditions.append("ip = ?")
        params.append(ip)
    if protocol:
        conditions.append("LOWER(protocol) = ?")
        params.append(protocol)

    sql = (
        "SELECT ip, laddr_ip, laddr_port, raddr_ip, raddr_port, protocol, status, pid, process_name, process_cmdline, details, time "
        "FROM network_connections"
    )
    base_conditions = [
        "UPPER(COALESCE(status, '')) NOT IN ('TIME_WAIT')",
        "COALESCE(laddr_ip, '') != ''",
    ]
    conditions.append("user_id = ?")
    params.append(current_user.id)
    all_conditions = base_conditions + conditions
    if all_conditions:
        sql += " WHERE " + " AND ".join(all_conditions)
    sql += " ORDER BY time DESC LIMIT ?"
    params.append(limit)

    db = _db_conn()
    c = db.cursor()
    c.execute(sql, params)
    rows = c.fetchall()
    items = []
    for row in rows:
        details = row[10]
        parsed_details = details
        if isinstance(details, str):
            try:
                parsed_details = json.loads(details)
            except Exception:
                parsed_details = details
        items.append(
            {
                "ip": row[0],
                "sender_ip": row[1],
                "sender_port": row[2],
                "receiver_ip": row[3],
                "receiver_port": row[4],
                "protocol": row[5],
                "status": row[6],
                "pid": row[7],
                "process_name": row[8],
                "process_cmdline": row[9],
                "direction": (parsed_details.get("direction") if isinstance(parsed_details, dict) else "") or "unknown",
                "details": parsed_details,
                "time": row[11],
            }
        )
    return jsonify({"connections": items})


@app.route("/api/processes/recent")
@login_required
def api_processes_recent():
    ip = (request.args.get("ip") or "").strip()
    try:
        limit = int(request.args.get("limit") or 200)
    except ValueError:
        limit = 200
    limit = max(1, min(limit, 500))

    sql = (
        "SELECT ip, pid, ppid, name, username, cmdline, exe, sha256, start_time, cpu_percent, rss, time "
        "FROM process_snapshots"
    )
    conditions = ["user_id=?"]
    params = [current_user.id]
    if ip:
        conditions.append("ip=?")
        params.append(ip)
    
    sql += " WHERE " + " AND ".join(conditions)
    sql += " ORDER BY time DESC LIMIT ?"
    params.append(limit)

    db = _db_conn()
    c = db.cursor()
    c.execute(sql, params)
    rows = c.fetchall()
    items = [
        {
            "ip": row[0],
            "pid": row[1],
            "ppid": row[2],
            "name": row[3],
            "username": row[4],
            "cmdline": row[5],
            "exe": row[6],
            "sha256": row[7],
            "start_time": row[8],
            "cpu_percent": row[9],
            "rss": row[10],
            "time": row[11],
        }
        for row in rows
    ]
    return jsonify({"processes": items})


@app.route("/api/indicators/summary")
@login_required
def api_indicators_summary():
    db = _db_conn()
    c = db.cursor()
    c.execute(
        """
        SELECT technique_id, tactic, COUNT(*)
        FROM alerts
        WHERE technique_id IS NOT NULL AND technique_id != ''
        GROUP BY technique_id, tactic
        ORDER BY COUNT(*) DESC
        LIMIT 50
        """
    )
    rows = c.fetchall()
    indicators = [{"technique_id": row[0], "tactic": row[1], "count": row[2]} for row in rows]
    return jsonify({"indicators": indicators})

if __name__ == "__main__":
    _ensure_dashboard_schema()
    app.run(host="0.0.0.0", port=5000, debug=True)
