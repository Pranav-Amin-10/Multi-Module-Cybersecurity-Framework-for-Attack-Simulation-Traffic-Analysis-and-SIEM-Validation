"""
packet_analyzer.py

Packet analyzer for UI packet capture.

Captures IP packets with Scapy, emits parsed rows to the UI, and returns
Analyzer-compatible summary data.
"""

import threading
import time
from collections import Counter
from datetime import datetime

from scapy.all import rdpcap, sniff, wrpcap
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP


class PacketAnalyzer:
    def __init__(self):
        self.packets = []
        self.running = False
        self.thread = None
        self.last_emit_time = 0
        self.error = ""

    # ==============================
    # START CAPTURE
    # ==============================

    def start(self, callback, iface=None):
        if self.running:
            return

        self.running = True
        self.packets = []
        self.error = ""
        self.last_emit_time = 0

        def process(packet):
            if not self.running:
                return True

            self.packets.append(packet)

            now = time.time()
            if now - self.last_emit_time < 0.1:
                return None

            self.last_emit_time = now
            parsed = self._parse_packet(packet)

            if not parsed:
                return None

            try:
                callback(parsed)
            except Exception:
                pass

            return None

        def capture():
            try:
                sniff(
                    prn=process,
                    store=False,
                    iface=iface,
                    filter="ip",
                    stop_filter=lambda packet: not self.running,
                )
            except Exception as e:
                self.error = str(e)
                self.running = False

        self.thread = threading.Thread(target=capture, daemon=True)
        self.thread.start()

    # ==============================
    # STOP CAPTURE
    # ==============================

    def stop(self):
        self.running = False

        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)

    # ==============================
    # PARSER
    # ==============================

    def _format_time(self, packet_time):
        try:
            return datetime.fromtimestamp(float(packet_time)).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return str(packet_time)

    def _protocol(self, packet):
        if packet.haslayer(DNS):
            return "DNS"
        if packet.haslayer(TCP):
            return "TCP"
        if packet.haslayer(UDP):
            return "UDP"
        if packet.haslayer(ICMP):
            return "ICMP"
        return "OTHER"

    def _parse_packet(self, packet):
        try:
            if not packet.haslayer(IP):
                return None

            ip = packet[IP]
            protocol = self._protocol(packet)

            sport = "-"
            dport = "-"

            if packet.haslayer(TCP):
                sport = packet[TCP].sport
                dport = packet[TCP].dport
            elif packet.haslayer(UDP):
                sport = packet[UDP].sport
                dport = packet[UDP].dport

            return {
                "time": self._format_time(packet.time),
                "src": ip.src,
                "dst": ip.dst,
                "sport": sport,
                "dport": dport,
                "protocol": protocol,
                "length": len(packet),
                "summary": packet.summary(),
            }

        except Exception:
            return None

    # ==============================
    # SAVE / LOAD
    # ==============================

    def save(self, file_path):
        if self.packets:
            wrpcap(file_path, self.packets)

    def load(self, file_path):
        self.packets = list(rdpcap(file_path))

    # ==============================
    # ANALYSIS
    # ==============================

    def analyze(self):
        parsed_packets = []

        for packet in self.packets:
            parsed = self._parse_packet(packet)
            if parsed:
                parsed_packets.append(parsed)

        protocol_count = Counter(packet["protocol"] for packet in parsed_packets)
        source_count = Counter(packet["src"] for packet in parsed_packets)
        destination_count = Counter(packet["dst"] for packet in parsed_packets)

        total_bytes = sum(packet["length"] for packet in parsed_packets)

        return {
            "attack_type": "packet_analysis",
            "packets": parsed_packets,
            "total_packets": len(parsed_packets),
            "total_bytes": total_bytes,
            "protocol_distribution": dict(protocol_count),
            "top_sources": source_count.most_common(5),
            "top_destinations": destination_count.most_common(5),
            "sample_packets": parsed_packets[:50],
            "capture_error": self.error,
        }

    # ==============================
    # RECOMMENDATIONS
    # ==============================

    def recommendations(self, analysis):
        recommendations = []

        total_packets = analysis.get("total_packets", 0)
        protocol_distribution = analysis.get("protocol_distribution", {})

        if analysis.get("capture_error"):
            recommendations.append(f"Capture error observed: {analysis['capture_error']}")

        if total_packets == 0:
            recommendations.append("No packets captured. Check interface selection and packet capture permissions.")

        if total_packets > 1000:
            recommendations.append("High packet volume detected. Review for scanning or flooding activity.")

        if protocol_distribution.get("DNS", 0) > 100:
            recommendations.append("High DNS volume observed. Review for tunneling or enumeration behavior.")

        if protocol_distribution.get("ICMP", 0) > 100:
            recommendations.append("High ICMP volume observed. Review for ping sweep activity.")

        if not recommendations:
            recommendations.append("Traffic appears normal based on this capture window.")

        return recommendations
