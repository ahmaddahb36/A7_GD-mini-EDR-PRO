import sqlite3
from datetime import datetime

DB_PATH = "database.db"

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

# إنشاء جدول الأجهزة
c.execute("""
CREATE TABLE IF NOT EXISTS endpoints (
    ip TEXT,
    hostname TEXT,
    os TEXT,
    last_seen TEXT
)
""")

# إنشاء جدول التنبيهات
c.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    ip TEXT,
    severity TEXT,
    message TEXT,
    time TEXT
)
""")

# إنشاء جدول الأوامر
c.execute("""
CREATE TABLE IF NOT EXISTS commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    command TEXT,
    status TEXT,
    output TEXT
)
""")

conn.commit()
conn.close()

print(f"[+] Database created successfully at {DB_PATH}")