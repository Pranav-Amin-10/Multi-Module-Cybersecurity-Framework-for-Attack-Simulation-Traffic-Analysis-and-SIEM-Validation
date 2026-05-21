# 🔐 Integrated Active Directory Attack Detection, Packet Analysis and SIEM Validation Framework

A multi-module cybersecurity framework designed to simulate real-world Active Directory attacks, validate Wazuh SIEM detections, analyze network packets, and perform security assessments inside a controlled enterprise-style lab environment.

Built using **Python, PySide6, Wazuh API, Scapy, Nmap, and VMware**, this project provides a practical platform for validating detection pipelines, analyzing attacker behavior, and generating SOC-style security reports.

---

# 🚀 Features

## 🛡 Active Directory Attack Validation

* Execute attacks remotely on Kali Linux via SSH
* Validate SIEM detections against generated attack activity
* Correlate expected vs actual Windows Event IDs
* Calculate:

  * Detection Rate
  * False Positives
  * False Negatives
  * Detection Delays

---

## 📡 Packet Capture & Analysis (Mini Wireshark)

* Real-time packet capture using Scapy
* IPv4 packet parsing
* Protocol identification
* Source/Destination IP tracking
* TCP/UDP port analysis
* PCAP save/load support
* Wireshark-style packet table UI

---

## 🔍 Port Scanner

* Fast Nmap-based scanning
* Open port detection
* Service enumeration
* Security recommendations based on exposed services

---

## 📄 SOC-Style Reporting

* Automated HTML/PDF report generation
* Detailed attack analysis
* Packet summaries
* Detection metrics
* Security recommendations
* Structured SOC-style layouts

---

# 🧱 Lab Topology

Default lab hosts configured in `config.py`:

| System                   | IP Address      |
| ------------------------ | --------------- |
| DC01 (Domain Controller) | `192.168.56.10` |
| WIN10 Client             | `192.168.56.20` |
| Kali Linux               | `192.168.56.30` |
| Wazuh Server             | `192.168.56.50` |

---

# ⚔️ Active Directory Attack Flow

For every simulated AD attack, the framework:

1. Connects to Kali Linux via SSH
2. Executes attack tools remotely
3. Waits for Wazuh log ingestion
4. Collects alerts from Wazuh
5. Correlates attack activity with detections
6. Calculates SIEM effectiveness metrics
7. Generates professional security reports

---

# 🎯 Included Active Directory Attack Simulations

| Attack                    | Purpose                                      |
| ------------------------- | -------------------------------------------- |
| SMB Brute Force           | Validate failed login detection              |
| RDP Brute Force           | Test remote access attack monitoring         |
| PsExec Remote Execution   | Simulate lateral movement                    |
| SMB Share Enumeration     | Detect reconnaissance activity               |
| SMB Password Spray        | Validate stealth credential attack detection |
| WinRM Brute Force         | Test WinRM authentication monitoring         |
| Evil-WinRM Login          | Simulate remote PowerShell access            |
| Kerberos User Enumeration | Detect user discovery attempts               |
| AS-REP Roasting           | Simulate Kerberos credential extraction      |
| Kerberoasting             | Validate service ticket abuse detection      |
| LDAP RootDSE Enumeration  | Detect AD information gathering              |
| BloodHound Collection     | Simulate attack path enumeration             |
| DCSync Attempt            | Detect domain replication abuse              |

---

# 🧰 Technology Stack

| Component         | Technology |
| ----------------- | ---------- |
| Language          | Python 3   |
| GUI               | PySide6    |
| SIEM              | Wazuh      |
| Packet Analysis   | Scapy      |
| Port Scanning     | Nmap       |
| SSH Communication | Paramiko   |
| Reporting         | ReportLab  |
| Virtualization    | VMware     |

---

# 📂 Project Structure

```txt
ad_siem_framework/
├── attack_module.py
├── collector.py
├── correlator.py
├── analyzer.py
├── reporter.py
├── packet_analyzer.py
├── port_scanner.py
├── ui_app.py
├── config.py
├── utils.py
├── logs/
└── reports/
```

---

# ⚙️ Requirements

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# 🧪 Required Kali Tools

The Kali VM should contain tools such as:

* CrackMapExec
* Hydra
* Impacket
* Evil-WinRM
* Kerbrute
* ldapsearch
* bloodhound-python

---

# 📡 Packet Capture Requirements

Packet capture requires:

* Npcap/WinPcap (Windows)
* Administrator privileges
* Working network capture interface

---

# 🔍 Port Scanning Requirements

Nmap must be installed and available in system PATH.

---

# 📄 Reports & Logs

Generated artifacts are stored in:

```txt
logs/
reports/
```

---

# ⚙️ Configuration

Primary configuration file:

```txt
config.py
```

Contains:

* VM IPs
* Credentials
* Attack mappings
* Wazuh configuration
* Reporting settings

---

# 🛑 Safety Notice

This project is intended strictly for:

* Educational purposes
* Security research
* Authorized lab environments

Do not use against systems without explicit permission.

---

# 👨‍💻 Author

Developed as an academic cybersecurity project focused on Active Directory attack simulation, SIEM validation, packet analysis, and enterprise security monitoring within a controlled lab environment.
