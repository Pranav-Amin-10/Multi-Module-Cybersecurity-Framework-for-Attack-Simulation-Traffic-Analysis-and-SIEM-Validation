"""
ui_app.py

Desktop UI for AD SIEM attack validation, packet analysis, and port scanning.
Network Analyzer module has been removed from the UI.
"""

import sys
import time
import webbrowser

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QPushButton,
    QComboBox,
    QTextEdit,
    QLineEdit,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QLabel,
)

from analyzer import Analyzer
from attack_module import AttackModule
from collector import WazuhCollector
from config import ATTACK_CONFIG, FRAMEWORK_CONFIG, LAB_CONFIG
from correlator import Correlator
from packet_analyzer import PacketAnalyzer
from port_scanner import PortScanner
from reporter import Reporter
from utils import ensure_directories


# ==============================
# UI HELPERS
# ==============================

def open_report(path):
    webbrowser.open(path)


def resolve_target(value):
    value = value.strip()

    shortcuts = {
        "dc01": LAB_CONFIG["DC01"]["ip"],
        "win10": LAB_CONFIG["WIN10"]["ip"],
    }

    return shortcuts.get(value.lower(), value)


def application_stylesheet():
    return """
    QWidget {
        background: #0B1120;
        color: #E5E7EB;
        font-family: Segoe UI, Arial, sans-serif;
        font-size: 10pt;
    }

    QLabel {
        color: #E5E7EB;
        background: transparent;
    }

    QLabel#sectionTitle {
        color: #38BDF8;
        font-size: 15pt;
        font-weight: 700;
        padding: 4px 0 10px 0;
    }

    QLabel#detailsLabel {
        color: #C7D2FE;
        background: #111827;
        border: 1px solid #1E3A8A;
        border-radius: 6px;
        padding: 9px;
    }

    QTabWidget::pane {
        border: 1px solid #1E293B;
        background: #111827;
        border-radius: 8px;
        top: -1px;
    }

    QTabBar::tab {
        background: #111827;
        color: #94A3B8;
        padding: 10px 18px;
        border: 1px solid #1E293B;
        border-bottom: none;
        min-width: 120px;
    }

    QTabBar::tab:selected {
        background: #172554;
        color: #38BDF8;
        border-top: 2px solid #38BDF8;
    }

    QTabBar::tab:hover {
        color: #E5E7EB;
        background: #1E293B;
    }

    QPushButton {
        background: #2563EB;
        color: #FFFFFF;
        border: 1px solid #3B82F6;
        border-radius: 6px;
        padding: 9px 14px;
        font-weight: 600;
    }

    QPushButton:hover {
        background: #1D4ED8;
    }

    QPushButton:pressed {
        background: #1E40AF;
    }

    QPushButton:disabled {
        background: #334155;
        color: #94A3B8;
        border: 1px solid #475569;
    }

    QLineEdit, QComboBox, QTextEdit, QTableWidget {
        background: #111827;
        color: #E5E7EB;
        border: 1px solid #334155;
        border-radius: 6px;
        padding: 7px;
        selection-background-color: #2563EB;
        selection-color: #FFFFFF;
    }

    QLineEdit:focus, QComboBox:focus, QTextEdit:focus, QTableWidget:focus {
        border: 1px solid #38BDF8;
    }

    QComboBox::drop-down {
        border: none;
        width: 26px;
    }

    QComboBox QAbstractItemView {
        background: #111827;
        color: #E5E7EB;
        border: 1px solid #334155;
        selection-background-color: #2563EB;
    }

    QTextEdit {
        font-family: Consolas, Cascadia Mono, monospace;
        background: #020617;
        color: #D1FAE5;
    }

    QHeaderView::section {
        background: #1E3A8A;
        color: #FFFFFF;
        border: 1px solid #334155;
        padding: 7px;
        font-weight: 600;
    }

    QTableWidget {
        gridline-color: #334155;
        alternate-background-color: #0F172A;
    }

    QScrollBar:vertical, QScrollBar:horizontal {
        background: #0B1120;
        border: none;
        width: 12px;
        height: 12px;
    }

    QScrollBar::handle:vertical, QScrollBar::handle:horizontal {
        background: #334155;
        border-radius: 6px;
    }

    QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover {
        background: #475569;
    }
    """


# ==============================
# AD TOOL WORKER
# ==============================

class ADWorker(QThread):
    log = Signal(str)
    finished_signal = Signal(object, object, object)

    def __init__(self, attack_key, target):
        super().__init__()
        self.attack_key = attack_key
        self.target = target

    def run(self):
        attack_data = {}
        correlation = {}
        analysis = {}

        try:
            attack = AttackModule()
            collector = WazuhCollector()
            correlator = Correlator()
            analyzer = Analyzer()

            attack_config = ATTACK_CONFIG.get(self.attack_key, {})
            self.log.emit(f"Selected attack: {attack_config.get('name', self.attack_key)}")
            self.log.emit(f"Tool: {attack_config.get('tool', 'N/A')}")
            self.log.emit(f"Target: {self.target}")
            self.log.emit("Connecting to Kali VM and executing attack...")

            attack_data = attack.run(self.attack_key, self.target)

            if not attack_data:
                self.log.emit("Attack failed. Report generation skipped.")
                self.finished_signal.emit({}, {}, {})
                return

            wait_time = FRAMEWORK_CONFIG.get("log_wait_time", 15)
            self.log.emit(f"Waiting {wait_time} seconds for Wazuh log ingestion...")
            time.sleep(wait_time)

            self.log.emit("Fetching Wazuh alerts...")
            alerts = collector.run(self.target)
            self.log.emit(f"Fetched {len(alerts)} recent alerts for target {self.target}.")

            self.log.emit("Correlating alerts with expected AD events...")
            correlation = correlator.correlate(attack_data, alerts)

            self.log.emit("Analyzing detection results...")
            analysis = analyzer.analyze(correlation)

            metrics = analysis.get("metrics", {})
            if metrics:
                self.log.emit(f"Detection rate: {metrics.get('detection_rate', 0)}%")
                self.log.emit(f"False negative rate: {metrics.get('false_negative_rate', 0)}%")

            self.log.emit("AD validation completed.")

        except Exception as e:
            self.log.emit(f"AD workflow error: {e}")

        self.finished_signal.emit(attack_data, correlation, analysis)


# ==============================
# AD TOOL
# ==============================

class ADTool(QWidget):
    def __init__(self):
        super().__init__()

        self.worker = None
        self.attack_data = {}
        self.correlation = {}
        self.analysis = {}

        layout = QVBoxLayout()

        title = QLabel("Active Directory Attack Validation")
        title.setObjectName("sectionTitle")

        self.attack = QComboBox()
        for attack_key, attack_config in ATTACK_CONFIG.items():
            self.attack.addItem(attack_config["name"], attack_key)

        self.details = QLabel("")
        self.details.setObjectName("detailsLabel")
        self.details.setWordWrap(True)

        self.target = QLineEdit()
        self.target.setPlaceholderText("Target IP or shortcut: dc01 / win10")

        self.run_btn = QPushButton("Run Attack")
        self.report_btn = QPushButton("Generate Report")
        self.report_btn.setEnabled(False)

        self.console = QTextEdit()
        self.console.setReadOnly(True)

        layout.addWidget(title)
        layout.addWidget(self.attack)
        layout.addWidget(self.details)
        layout.addWidget(self.target)
        layout.addWidget(self.run_btn)
        layout.addWidget(self.report_btn)
        layout.addWidget(self.console)

        self.setLayout(layout)

        self.attack.currentIndexChanged.connect(self.update_attack_details)
        self.run_btn.clicked.connect(self.run_attack)
        self.report_btn.clicked.connect(self.generate_report)

        self.update_attack_details()

    def update_attack_details(self):
        attack_key = self.attack.currentData()
        attack_config = ATTACK_CONFIG.get(attack_key, {})

        self.details.setText(
            f"Tool: {attack_config.get('tool', 'N/A')} | "
            f"Category: {attack_config.get('category', 'N/A')} | "
            f"Expected Events: {attack_config.get('expected_event_ids', [])}"
        )

    def run_attack(self):
        target = resolve_target(self.target.text())

        if not target:
            self.console.append("Please enter a target IP.")
            return

        self.console.clear()
        self.report_btn.setEnabled(False)
        self.run_btn.setEnabled(False)

        self.attack_data = {}
        self.correlation = {}
        self.analysis = {}

        attack_key = self.attack.currentData()

        self.worker = ADWorker(attack_key, target)
        self.worker.log.connect(self.console.append)
        self.worker.finished_signal.connect(self._attack_finished)
        self.worker.start()

    def _attack_finished(self, attack_data, correlation, analysis):
        self.attack_data = attack_data or {}
        self.correlation = correlation or {}
        self.analysis = analysis or {}

        self.run_btn.setEnabled(True)

        if self.attack_data and self.analysis:
            self.report_btn.setEnabled(True)
            self.console.append("Report is ready to generate.")
        else:
            self.report_btn.setEnabled(False)
            self.console.append("No valid AD analysis available for report.")

    def generate_report(self):
        if not self.attack_data or not self.analysis:
            self.console.append("Run an attack successfully before generating a report.")
            return

        try:
            path = Reporter().generate_report(
                self.attack_data,
                self.correlation,
                self.analysis
            )

            open_report(path)
            self.console.append(f"Report opened: {path}")

        except Exception as e:
            self.console.append(f"Report generation failed: {e}")


# ==============================
# PACKET TOOL
# ==============================

class PacketTool(QWidget):
    def __init__(self):
        super().__init__()

        self.pkt = PacketAnalyzer()
        self.core_analyzer = Analyzer()
        self.analysis = {}

        layout = QVBoxLayout()

        title = QLabel("Packet Capture")
        title.setObjectName("sectionTitle")

        self.start_btn = QPushButton("Start Capture")
        self.stop_btn = QPushButton("Stop Capture")
        self.report_btn = QPushButton("Generate Report")

        self.stop_btn.setEnabled(False)
        self.report_btn.setEnabled(False)

        self.status = QLabel("Idle")
        self.status.setObjectName("detailsLabel")

        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels(
            ["Time", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Length", "Info"]
        )

        layout.addWidget(title)
        layout.addWidget(self.status)
        layout.addWidget(self.start_btn)
        layout.addWidget(self.stop_btn)
        layout.addWidget(self.report_btn)
        layout.addWidget(self.table)

        self.setLayout(layout)

        self.start_btn.clicked.connect(self.start)
        self.stop_btn.clicked.connect(self.stop)
        self.report_btn.clicked.connect(self.report)

    def start(self):
        self.table.setRowCount(0)
        self.analysis = {}

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.report_btn.setEnabled(False)
        self.status.setText("Capturing packets...")

        self.pkt.start(self.add_packet)

    def stop(self):
        self.pkt.stop()

        raw = self.pkt.analyze()
        self.analysis = self.core_analyzer.analyze(raw)

        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

        if self.analysis:
            self.report_btn.setEnabled(True)

        self.status.setText(f"Stopped. Packets captured: {self.analysis.get('total_packets', 0)}")

    def add_packet(self, packet):
        row = self.table.rowCount()
        self.table.insertRow(row)

        values = [
            packet.get("time", ""),
            packet.get("src", ""),
            packet.get("sport", ""),
            packet.get("dst", ""),
            packet.get("dport", ""),
            packet.get("protocol", ""),
            packet.get("length", ""),
            packet.get("summary", ""),
        ]

        for column, value in enumerate(values):
            self.table.setItem(row, column, QTableWidgetItem(str(value)))

    def report(self):
        if not self.analysis:
            self.status.setText("Stop a capture before generating a report.")
            return

        path = Reporter().generate_report(
            {"attack_type": "Packet"},
            {},
            self.analysis
        )

        open_report(path)
        self.status.setText(f"Report opened: {path}")


# ==============================
# PORT TOOL
# ==============================

class PortTool(QWidget):
    def __init__(self):
        super().__init__()

        self.scanner = PortScanner()
        self.core_analyzer = Analyzer()
        self.analysis = {}

        layout = QVBoxLayout()

        title = QLabel("Port Scanner")
        title.setObjectName("sectionTitle")

        self.target = QLineEdit()
        self.target.setPlaceholderText("Target IP or shortcut: dc01 / win10")

        self.scan_btn = QPushButton("Scan")
        self.report_btn = QPushButton("Generate Report")
        self.report_btn.setEnabled(False)

        self.console = QTextEdit()
        self.console.setReadOnly(True)

        layout.addWidget(title)
        layout.addWidget(self.target)
        layout.addWidget(self.scan_btn)
        layout.addWidget(self.report_btn)
        layout.addWidget(self.console)

        self.setLayout(layout)

        self.scan_btn.clicked.connect(self.scan)
        self.report_btn.clicked.connect(self.report)

    def scan(self):
        target = resolve_target(self.target.text())

        if not target:
            self.console.append("Please enter a target IP.")
            return

        self.console.clear()
        self.report_btn.setEnabled(False)
        self.analysis = {}

        result = self.scanner.scan(target)

        if not result:
            self.console.append("No scan results returned.")
        else:
            for item in result:
                self.console.append(
                    f"{item.get('host')} | Port {item.get('port')} | "
                    f"{item.get('service')} | {item.get('state')}"
                )

        raw = self.scanner.analyze()
        self.analysis = self.core_analyzer.analyze(raw)

        if self.analysis:
            self.report_btn.setEnabled(True)
            self.console.append("Port scan report is ready to generate.")

    def report(self):
        if not self.analysis:
            self.console.append("Run a scan before generating a report.")
            return

        path = Reporter().generate_report(
            {"attack_type": "Port"},
            {},
            self.analysis
        )

        open_report(path)
        self.console.append(f"Report opened: {path}")


# ==============================
# MAIN UI
# ==============================

class MainUI(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("AD SIEM Framework")
        self.resize(1200, 800)

        layout = QVBoxLayout()

        tabs = QTabWidget()
        tabs.addTab(ADTool(), "AD Attacks")
        tabs.addTab(PacketTool(), "Packets")
        tabs.addTab(PortTool(), "Port Scan")

        layout.addWidget(tabs)
        self.setLayout(layout)


# ==============================
# ENTRY POINT
# ==============================

if __name__ == "__main__":
    ensure_directories()

    app = QApplication(sys.argv)
    app.setStyleSheet(application_stylesheet())
    window = MainUI()
    window.show()
    sys.exit(app.exec())
