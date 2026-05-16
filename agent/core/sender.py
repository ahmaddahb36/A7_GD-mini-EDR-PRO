
import json
import socket

from config import SERVER_IP, PORT, AGENT_KEY

def send(data, expect_reply=False):
    try:
        data["key"] = AGENT_KEY
        s = socket.socket()
        s.connect((SERVER_IP, PORT))
        s.sendall(json.dumps(data).encode())
        if expect_reply:
            # Signal end of request so the server can respond.
            s.shutdown(socket.SHUT_WR)
            s.settimeout(2)
            raw = s.recv(4096)
            s.close()
            if not raw:
                return None
            return json.loads(raw.decode())
        s.close()
    except:
        pass
    return None
