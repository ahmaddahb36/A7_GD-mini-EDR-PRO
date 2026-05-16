
import os
import socket
import sys

# Ensure the server package root is on sys.path when run as a script.
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from handler import handle_client
from config import HOST, PORT

s = socket.socket()
s.bind((HOST, PORT))
s.listen(5)

print("[+] Server running...")

while True:
    conn, addr = s.accept()
    handle_client(conn, addr)
