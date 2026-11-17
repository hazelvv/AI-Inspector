# AI-Inspector (Smart Device & IoT Privacy Auditor)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)

AI-Inspector is a lightweight, local-first smart device inspector and privacy auditor designed for macOS environments. It scans and catalogs active Wi-Fi networks, Bluetooth peripherals, and local network devices (via ARP tables) to identify unknown hardware, detect potentially rogue IoT cameras or unauthorized surveillance devices, and evaluate local privacy risk.

---

## 🔍 Key Features

- **Wi-Fi Scanner**: Detects nearby access points, signal strength (RSSI), security protocols (WPA2/WPA3/Open), and flags unencrypted or hidden networks.
- **Bluetooth Device Discovery**: Identifies nearby Bluetooth Low Energy (BLE) and classic Bluetooth devices, categorizing device classes and audio/video hardware.
- **Local Network (ARP) Audit**: Inspects connected devices on the local subnet and matches MAC addresses against an extensive database of known IoT and camera vendor OUIs.
- **Real-Time Risk Scoring**: Heuristic scoring engine that categorizes detected devices into `LOW`, `MEDIUM`, and `HIGH` risk tiers based on device signatures and behaviors.
- **Dark-Themed Responsive Dashboard**: Built with vanilla CSS/JS and Flask for rapid local auditing without cloud dependencies.

---

## 🛠 Tech Stack

- **Backend**: Python 3.9+, Flask
- **Frontend**: Modern Vanilla JavaScript, HTML5, Responsive CSS
- **System Integration**: Native macOS utilities (`system_profiler`, `arp`, POSIX sockets)

---

## 🚀 Quick Start

### 1. Prerequisites
- macOS (requires native system CLI utilities)
- Python 3.9 or higher

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/hazelvv/AI-Inspector.git
cd AI-Inspector

# (Optional) Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Run the Dashboard
```bash
python3 app.py
```
Open your browser and navigate to:
```
http://localhost:5050
```

---

## 🗺 Roadmap & Planned Work (Upcoming 20+ Hours)

We have active plans to expand AI-Inspector into a comprehensive local security suite:

- [ ] **Cross-Platform Network Engine**: Decouple macOS-specific commands and add support for Linux (`iwlist`, `ip neigh`) and Windows (`netsh`, `arp -a`).
- [ ] **Port & Service Inspection**: Integrate non-intrusive local port probing (e.g., RTSP port 554, HTTP 80/8080) to detect streaming camera endpoints.
- [ ] **Persistent Audit Logging & SQLite Store**: Implement a historical database to track when new devices appear or disappear over time.
- [ ] **Real-time Alerting**: Add desktop notifications and configurable Webhook alerts (Discord/Slack/Telegram) when a high-risk device is detected.
- [ ] **MAC Address Vendor Database Expansion**: Automate IEEE OUI database synchronization for more accurate hardware vendor identification.
- [ ] **Automated Testing Suite**: Introduce unit tests and mock integration tests with `pytest` for the scanning parsers.
- [ ] **CI/CD Pipeline**: GitHub Actions workflow for automated linting (`flake8`, `black`) and automated testing.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
