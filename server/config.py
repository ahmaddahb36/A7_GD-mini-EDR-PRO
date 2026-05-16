
import os

HOST = "0.0.0.0"
PORT = 9999

# Resolve the database path relative to this file so running from any cwd works.
DB_PATH = os.path.join(os.path.dirname(__file__), "db", "database.db")
