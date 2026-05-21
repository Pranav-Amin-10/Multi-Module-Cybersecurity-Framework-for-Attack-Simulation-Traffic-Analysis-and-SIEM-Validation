"""
analyzer.py

Unified analyzer for:
- AD SIEM attack validation
- Packet capture summaries
- Port scan summaries

Network Analyzer support has been removed.
"""

from utils import print_status, print_success


class Analyzer:
    # ==============================
    # AD THREAT SCORE
    # ==============================

    def calculate_threat_score(self, metrics):
        if not metrics:
            return 0

        detection_rate = metrics.get("detection_rate", 0)
        false_negative_rate = metrics.get("false_negative_rate", 0)
        false_positive_rate = metrics.get("false_positive_rate", 0)

        score = 0
        score += (100 - detection_rate) * 0.5
        score += false_negative_rate * 0.3
        score += false_positive_rate * 0.2

        return round(min(100, max(0, score)), 2)

    def risk_level(self, score):
        if score > 70:
            return "HIGH"
        if score > 40:
            return "MEDIUM"
        return "LOW"

    # ==============================
    # RECOMMENDATIONS
    # ==============================

    def generate_ad_recommendations(self, metrics, threat_score):
        recommendations = []

        if not metrics:
            return ["No detection metrics were available for this attack."]

        detection_rate = metrics.get("detection_rate", 0)
        false_negative_rate = metrics.get("false_negative_rate", 0)
        false_positive_rate = metrics.get("false_positive_rate", 0)
        avg_delay = metrics.get("avg_detection_delay", 0)

        if detection_rate == 100 and false_negative_rate == 0:
            recommendations.append("All expected AD events were detected for this attack.")

        if detection_rate < 80:
            recommendations.append("Review Wazuh rule coverage for the expected Windows Event IDs.")

        if false_negative_rate > 0:
            recommendations.append("Verify Windows audit policy and Sysmon coverage on the target host.")

        if false_positive_rate > 30:
            recommendations.append("Tune noisy Wazuh rules or narrow the correlation time window.")

        if avg_delay > 60:
            recommendations.append("Investigate log forwarding latency between the endpoint and Wazuh.")

        if threat_score > 70:
            recommendations.append("High detection risk observed. Prioritize SIEM rule validation before demonstration.")

        if not recommendations:
            recommendations.append("Detection behavior is within the expected threshold.")

        return recommendations

    def generate_packet_recommendations(self, data):
        recommendations = []

        total_packets = data.get("total_packets", 0)
        protocol_distribution = data.get("protocol_distribution", {})

        if total_packets == 0:
            recommendations.append("No packets were captured. Check capture permissions and interface selection.")

        if total_packets > 1000:
            recommendations.append("High packet volume observed. Review for scanning, flooding, or noisy services.")

        if protocol_distribution.get("UDP", 0) > protocol_distribution.get("TCP", 0):
            recommendations.append("UDP-heavy traffic observed. Review DNS, discovery, or broadcast activity.")

        if not recommendations:
            recommendations.append("Packet capture did not show an obvious high-volume anomaly.")

        return recommendations

    def generate_port_recommendations(self, data):
        recommendations = []

        open_ports = data.get("open_ports", [])
        risky_ports = data.get("risky_ports", [])

        if not open_ports:
            recommendations.append("No open ports were identified in the scan result.")

        for item in risky_ports:
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

        if len(open_ports) > 10:
            recommendations.append("Large exposed service surface detected. Reduce unnecessary open ports.")

        if not recommendations:
            recommendations.append("No major port exposure risks were detected.")

        return list(dict.fromkeys(recommendations))

    # ==============================
    # ANALYSIS TYPES
    # ==============================

    def _analyze_ad(self, data):
        metrics = data.get("metrics", {})
        threat_score = self.calculate_threat_score(metrics)

        return {
            "attack_type": data.get("attack_type"),
            "attack_key": data.get("attack_key"),
            "target": data.get("target"),

            "metrics": metrics,
            "threat_score": threat_score,
            "risk_level": self.risk_level(threat_score),
            "recommendations": self.generate_ad_recommendations(metrics, threat_score),

            "expected_events": data.get("expected_events", []),
            "matched_alerts": data.get("matched_alerts", []),
            "missed_events": data.get("missed_events", []),
            "unexpected_alerts": data.get("unexpected_alerts", []),
            "timeline": data.get("timeline", []),
        }

    def _analyze_packets(self, data):
        packets = data.get("packets", [])

        return {
            "attack_type": "packet_analysis",
            "total_packets": data.get("total_packets", len(packets)),
            "protocol_distribution": data.get("protocol_distribution", {}),
            "top_sources": data.get("top_sources", []),
            "sample_packets": data.get("sample_packets", packets[:50]),
            "recommendations": self.generate_packet_recommendations(data),
        }

    def _analyze_ports(self, data):
        return {
            "attack_type": "port_scan",
            "open_ports": data.get("open_ports", []),
            "total_open_ports": data.get("total_open_ports", len(data.get("open_ports", []))),
            "risky_ports": data.get("risky_ports", []),
            "recommendations": self.generate_port_recommendations(data),
        }

    # ==============================
    # MAIN ANALYSIS
    # ==============================

    def analyze(self, data):
        print_status("Analyzing results...")

        if not data:
            return {}

        if "metrics" in data:
            result = self._analyze_ad(data)
            print_success("AD analysis completed")
            return result

        if "packets" in data:
            result = self._analyze_packets(data)
            print_success("Packet analysis completed")
            return result

        if "open_ports" in data:
            result = self._analyze_ports(data)
            print_success("Port analysis completed")
            return result

        print_status("Unknown data format received in analyzer")
        return {}
