<div align="center">

<img src="SnapShot/image.png" alt="A7 Mini EDR Pro Logo" width="180"/>

# A7 Mini EDR Pro

### A lightweight, cross-platform Endpoint Detection & Response system
### built with Python — Agent on Linux · Server & Dashboard on Windows

![Python](https://img.shields.io/badge/Python-97.7%25-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-Dashboard-000000?style=flat-square&logo=flask)
![YARA](https://img.shields.io/badge/YARA-Detection-red?style=flat-square)
![Platform](https://img.shields.io/badge/Agent-Linux-FCC624?style=flat-square&logo=linux&logoColor=black)
![Platform](https://img.shields.io/badge/Server-Windows-0078D6?style=flat-square&logo=windows)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

</div>

---

## 📖 Overview

**A7 Mini EDR Pro** is a lightweight, research-grade Endpoint Detection & Response (EDR) system designed for security monitoring in heterogeneous environments. It follows a classic **agent–server** architecture: a Python agent runs silently on a Linux endpoint, continuously collecting deep process telemetry and network activity, then forwards the data over a socket connection to a Windows-based server. A Flask-powered web dashboard provides real-time visibility into endpoint activity, alert management, and threat investigation — all from a browser.

The system is built around a **policy-driven detection engine** with full [MITRE ATT&CK](https://attack.mitre.org/) technique tagging, making it suitable for both educational lab environments and small-scale operational deployments.

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 🔍 **Deep Process Telemetry** | Captures PID, PPID, username, command line, executable path, SHA-256 hash, start time, CPU & memory usage |
| 🌐 **Network Enrichment** | Tracks remote connections with destination IPs and ports per process |
| 🎯 **Policy-Based Detection** | JSON-configurable rules for high-risk tools, scripting engines, suspicious ports, and data exfiltration thresholds |
| 🧠 **MITRE ATT&CK Mapping** | Every alert is tagged with `technique_id`, `tactic`, and `source` |
| 📸 **Process Snapshots** | Historical snapshots stored for forensic investigation and threat hunting |
| 📊 **Web Dashboard** | Real-time Flask dashboard accessible at `http://127.0.0.1:5000` |
| 📡 **REST API** | Built-in API endpoints for programmatic querying of processes and indicators |
| ⚙️ **Configurable Rules** | Edit detection thresholds and watch-lists without touching source code |

---

## 🏗️ Architecture

```
┌─────────────────────────────────┐        ┌──────────────────────────────────────┐
│          Linux Endpoint          │        │           Windows Server              │
│                                 │        │                                      │
│  ┌──────────────────────────┐   │  TCP   │  ┌───────────────────────────────┐  │
│  │    agent/core/agent.py   │◄──┼──9999──┼─►│  server/core/server.py        │  │
│  │                          │   │        │  │  (Socket Backend)             │  │
│  │  • Process telemetry     │   │        │  └───────────────────────────────┘  │
│  │  • Network enrichment    │   │        │                  │                   │
│  │  • SHA-256 hashing       │   │        │                  ▼                   │
│  └──────────────────────────┘   │        │  ┌───────────────────────────────┐  │
│                                 │        │  │  server/dashboard/app.py      │  │
│          agent/config.py        │        │  │  (Flask Web Dashboard)        │  │
│          SERVER_IP = <your-ip>  │        │  │  http://127.0.0.1:5000        │  │
│          PORT       = 9999      │        │  └───────────────────────────────┘  │
└─────────────────────────────────┘        └──────────────────────────────────────┘
```

---

## 📁 Repository Structure

```
A7_GD-mini-EDR-PRO/
├── agent/
│   ├── core/
│   │   └── agent.py              # Main agent entry point
│   └── config.py                 # SERVER_IP and PORT configuration
│
├── server/
│   ├── core/
│   │   └── server.py             # TCP socket server (backend)
│   ├── dashboard/
│   │   └── app.py                # Flask web dashboard
│   └── policies/
│       └── detection_rules.json  # Configurable detection engine rules
│
├── shared/                       # Shared utilities used by agent & server
├── Doc/                          # Project documentation
├── SnapShot/                     # Screenshot references
├── .vscode/                      # VS Code workspace settings
├── requirements.txt              # Python dependencies
├── UPDATE_RUN_GUIDE.md           # Detailed run guide (Arabic)
└── README.md                     # This file
```

---

## ⚙️ Requirements

- **Python 3.8+** — installed on both the server machine and the agent machine
- **Virtual environment** — located at `venv/` inside the project root
- The following Python libraries (from `requirements.txt`):

```
psutil
flask
yara-python
```

---

## 🚀 Getting Started

### Step 1 — Clone the Repository

```bash
git clone https://github.com/ahmaddahb36/A7_GD-mini-EDR-PRO.git
cd A7_GD-mini-EDR-PRO
```

### Step 2 — Install Dependencies (Server — Windows)

```powershell
cd "C:\path\to\A7_GD-mini-EDR-PRO"
.\venv\Scripts\pip.exe install -r requirements.txt
```

For the Linux agent, install with the system Python or a virtual environment:

```bash
pip install -r requirements.txt
```

### Step 3 — Configure the Agent

Open `agent/config.py` and set the correct server IP:

```python
SERVER_IP = "192.168.x.x"   # Replace with your actual server IP
PORT      = 9999
```

> **Important:** Do not leave `SERVER_IP` as `127.0.0.1` if the agent is running on a separate machine.

---

## ▶️ Running the System

Start the three components in this exact order:

#### 1. Start the Socket Server (Windows)

```powershell
.\venv\Scripts\python.exe .\server\core\server.py
```

Expected output:
```
[+] Server running...
```

#### 2. Start the Dashboard (Windows — new terminal)

```powershell
.\venv\Scripts\python.exe .\server\dashboard\app.py
```

Then open your browser at:

```
http://127.0.0.1:5000
```

#### 3. Start the Agent (Linux endpoint)

```bash
python agent/core/agent.py
```

The endpoint should appear in the dashboard within a few seconds.

---

## 🔌 REST API

The dashboard exposes several API endpoints for programmatic access:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/processes/recent` | Recent process telemetry from all agents |
| `GET` | `/api/processes/recent?ip=AGENT_IP&limit=100` | Filtered telemetry by agent IP |
| `GET` | `/api/indicators/summary` | Summary of all active threat indicators |

**Example — PowerShell:**

```powershell
Invoke-RestMethod "http://127.0.0.1:5000/api/indicators/summary"
```

---

## 🎯 Detection Engine

The detection engine is fully driven by `server/policies/detection_rules.json`. You can customize it without touching the source code.

**Configurable rule categories:**

- **High-risk tools** — process names that trigger an immediate alert (e.g., `mimikatz`, `netcat`)
- **Scripting engines** — interpreters flagged for suspicious execution patterns
- **Suspicious ports** — known command-and-control or exfiltration ports to watch
- **`port_spike_threshold`** — maximum number of unique remote ports before alerting
- **`network_exfiltration_threshold`** — outbound data volume threshold

After editing the rules file, restart both the server and the dashboard to apply changes:

```powershell
# Restart server
.\venv\Scripts\python.exe .\server\core\server.py

# Restart dashboard
.\venv\Scripts\python.exe .\server\dashboard\app.py
```

---

## 🧩 MITRE ATT&CK Integration

Every alert generated by the detection engine includes full ATT&CK context:

```json
{
  "technique_id": "T1059",
  "tactic": "Execution",
  "source": "scripting_engine_policy"
}
```

This enables direct mapping to the MITRE ATT&CK framework for threat categorisation and reporting.

---

## 🔬 Telemetry Fields

Each process record collected by the agent includes:

| Field | Description |
|-------|-------------|
| `pid` | Process ID |
| `ppid` | Parent Process ID |
| `username` | User running the process |
| `cmdline` | Full command-line arguments |
| `exe` | Absolute path to the executable |
| `sha256` | SHA-256 hash of the executable |
| `start_time` | Process creation timestamp |
| `cpu` | CPU usage percentage |
| `memory` | Memory usage (RSS) |
| `remote_connections` | List of remote IPs and ports |

---

## 🛠️ Troubleshooting

| Symptom | Solution |
|---------|----------|
| Endpoint not appearing in dashboard | Verify `SERVER_IP` in `agent/config.py`; confirm port `9999` is allowed through the firewall |
| Dashboard shows no data | Confirm the socket server is running and the agent is actively sending telemetry |
| No alerts triggering | Run processes or commands covered in `detection_rules.json` to test |
| Syntax errors on startup | Run `.\venv\Scripts\python.exe -m compileall agent server` to verify all Python files |

---

## 🧪 Quick Syntax Check

From the project root:

```powershell
.\venv\Scripts\python.exe -m compileall agent server
```

A clean run with no errors confirms the codebase is syntactically valid.

---

## 📸 Screenshots

### Dashboard Overview

![Dashboard Overview](SnapShot/Screenshot%202026-04-23%20105549.png)

> The main web dashboard showing connected endpoints, live process telemetry, and threat alerts in real time.

<details>
<summary>View more screenshots</summary>

![Screenshot 1](SnapShot/Screenshot%202026-04-23%20105408.png)

![Screenshot 2](SnapShot/Screenshot%202026-04-23%20105622.png)

![Screenshot 3](SnapShot/Screenshot%202026-04-23%20105706.png)

![Screenshot 4](SnapShot/Screenshot%202026-04-23%20105750.png)

![Screenshot 5](SnapShot/Screenshot%202026-04-23%20105846.png)

![Screenshot 6](SnapShot/Screenshot%202026-04-23%20110006.png)

</details>

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| Agent | Python, `psutil`, `hashlib` |
| Server | Python sockets, SQLite |
| Dashboard | Flask, HTML/CSS/JavaScript |
| Detection | YARA, JSON policy rules |
| ATT&CK Mapping | MITRE ATT&CK framework |

---

## 🤝 Contributing

Contributions are welcome. To contribute:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m "feat: add your feature"`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a Pull Request

---

## ⚠️ Disclaimer

This tool is intended for **educational and authorised security research purposes only**. Do not deploy agents on systems you do not own or have explicit written permission to monitor. The authors assume no liability for misuse.

---

## 👤 Author

**Ahmad Abu-Aldahab** — [@ahmaddahb36](https://github.com/ahmaddahb36)

---

<div align="center">

*Built for learning. Designed for security.*

⭐ If you find this project useful, please consider giving it a star!

</div>
