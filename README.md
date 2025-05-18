# 🔥 Firewall Intrusion Prevention Using Indicators of Attack

This project is a smart firewall enhancement tool that identifies and blocks potential threats using traffic pattern analysis, reverse port scanning, and real-time IoA detection. It integrates dynamic rule updates and optional VPN detection logic to improve overall security.

---

## 🚀 Features

- Real-time suspicious IP detection
- Reverse port scanning to detect attacker services
- VPN detection heuristics
- IP blocklisting via firewall (e.g., iptables)
- Indicator of Attack (IoA) timeline logging
- Lightweight alerting module
- Optional port-hopping and DNS sync module

---

## 📁 Project Structure

Firewall-Tool/
├── attacker.md # Guide for identifying attackers
├── reverse port scan.md # Instructions or scripts for reverse scanning
├── main.py (recommended) # Main integration script (to be created)
├── modules/ # Future home for modular scripts
├── logs/ # Logs from IoA detection and alerts
└── requirements.txt # Python dependencies
