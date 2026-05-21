"""
port_scanner.py

Structured nmap port scanner.

Provides UI-friendly scan results and Analyzer-compatible output.
"""

import nmap

from reporter import Reporter
from utils import get_current_timestamp, print_error, print_status, print_success


class PortScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()
        self.results = []
        self.raw = {}
        self.target = ""

    # ==============================
    # HELPERS
    # ==============================

    def _normalize_port_entry(self, host, protocol, port, data):
        return {
            "host": host,
            "protocol": protocol,
            "port": int(port),
            "state": data.get("state", "unknown"),
            "service": data.get("name", "unknown"),
            "product": data.get("product", ""),
            "version": data.get("version", ""),
            "extrainfo": data.get("extrainfo", ""),
            "reason": data.get("reason", ""),
        }

    # ==============================
    # SCAN PORTS
    # ==============================

    def scan(self, target):
        self.target = target
        self.results = []
        self.raw = {}

        if not target:
            print_error("No target provided for port scan")
            return []

        print_status(f"Scanning target: {target}")

        try:
            self.scanner.scan(
                hosts=target,
                arguments="-T4 -F -sV"
            )

            for host in self.scanner.all_hosts():
                self.raw[host] = []

                for protocol in self.scanner[host].all_protocols():
                    ports = sorted(self.scanner[host][protocol].keys())

                    for port in ports:
                        data = self.scanner[host][protocol][port]
                        entry = self._normalize_port_entry(host, protocol, port, data)

                        self.raw[host].append(entry)
                        self.results.append(entry)

            print_success(f"Port scan completed. Results: {len(self.results)}")
            return self.results

        except Exception as e:
            print_error(f"Scan error: {e}")
            return []

    # ==============================
    # ANALYSIS
    # ==============================

    def analyze(self):
        open_ports = [
            port for port in self.results
            if port.get("state") == "open"
        ]

        risky_port_numbers = {21, 22, 23, 445, 3389, 5985, 5986}
        risky_ports = [
            port for port in open_ports
            if port.get("port") in risky_port_numbers
        ]

        return {
            "attack_type": "port_scan",
            "target": self.target,
            "open_ports": open_ports,
            "total_open_ports": len(open_ports),
            "risky_ports": risky_ports,
            "all_results": self.results,
            "timestamp": get_current_timestamp(),
        }

    # ==============================
    # RECOMMENDATIONS
    # ==============================

    def recommendations(self, analysis):
        recommendations = []

        for item in analysis.get("risky_ports", []):
            port = item.get("port")

            if port == 21:
                recommendations.append("FTP is exposed. Disable it or replace it with a secure alternative.")
            elif port == 22:
                recommendations.append("SSH is exposed. Enforce key-based authentication and restrict source IPs.")
            elif port == 23:
                recommendations.append("Telnet is exposed. Replace it with SSH.")
            elif port == 445:
                recommendations.append("SMB is exposed. Restrict access and monitor for lateral movement.")
            elif port == 3389:
                recommendations.append("RDP is exposed. Restrict access and require strong authentication.")
            elif port in (5985, 5986):
                recommendations.append("WinRM is exposed. Restrict access and monitor remote PowerShell activity.")

        if analysis.get("total_open_ports", 0) > 10:
            recommendations.append("Large attack surface detected. Close unnecessary services.")

        if not recommendations:
            recommendations.append("No major port exposure risks were detected.")

        return list(dict.fromkeys(recommendations))

    # ==============================
    # REPORT
    # ==============================

    def generate_report(self, analysis, recommendations):
        return Reporter().generate_report(
            {
                "attack_type": "Port Scan",
                "target": analysis.get("target", self.target),
                "timestamp": get_current_timestamp(),
            },
            {},
            {
                "attack_type": "port_scan",
                "open_ports": analysis.get("open_ports", []),
                "total_open_ports": analysis.get("total_open_ports", 0),
                "risky_ports": analysis.get("risky_ports", []),
                "recommendations": recommendations,
            }
        )
