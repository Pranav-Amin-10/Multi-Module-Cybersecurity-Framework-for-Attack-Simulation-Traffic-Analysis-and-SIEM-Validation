"""
reporter.py

HTML SOC report generator.

Supports:
- AD attack validation reports
- Packet capture reports
- Port scan reports

Network Analyzer reporting has been removed.
"""

import html
import os
from collections import Counter
from datetime import datetime

from config import PATHS, REPORT_CONFIG
from utils import print_success


class Reporter:
    # ==============================
    # BASIC HELPERS
    # ==============================

    def _safe(self, value):
        if value is None:
            return "N/A"
        return html.escape(str(value))

    def _filename(self, tool):
        now = datetime.now()
        return f"{tool}_{now.strftime('%d%m%Y_%H%M%S')}.html"

    def _identify_tool(self, value):
        value = str(value).lower()

        if "packet" in value:
            return "Packet"

        if "port" in value:
            return "Port"

        return "AD"

    def _windows_event_id(self, alert):
        if not isinstance(alert, dict):
            return "N/A"

        direct = alert.get("windows_event_id")
        if direct not in (None, ""):
            return direct

        try:
            return (
                alert.get("raw", {})
                .get("data", {})
                .get("win", {})
                .get("system", {})
                .get("eventID", "N/A")
            )
        except Exception:
            return "N/A"

    def _source_ip(self, alert):
        if not isinstance(alert, dict):
            return "N/A"

        direct = alert.get("source_ip")
        if direct not in (None, "", "-"):
            return direct

        try:
            value = (
                alert.get("raw", {})
                .get("data", {})
                .get("win", {})
                .get("eventdata", {})
                .get("ipAddress", "N/A")
            )

            if value in (None, "", "-"):
                return "N/A"

            return value

        except Exception:
            return "N/A"

    # ==============================
    # HTML SECTIONS
    # ==============================

    def _base_html_start(self, tool, analysis):
        title = REPORT_CONFIG.get("title", "Cybersecurity Framework Report")
        author = REPORT_CONFIG.get("author", "AD SIEM Framework")
        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{self._safe(tool)} SOC Report</title>
    <style>
        :root {{
            --page: #FFFFFF;
            --ink: #111827;
            --muted: #4B5563;
            --panel: #FFFFFF;
            --line: #CBD5E1;
            --soft-line: #E5E7EB;
            --header: #111827;
            --primary: #1D4ED8;
            --primary-dark: #1E3A8A;
            --success: #166534;
            --warning: #92400E;
            --danger: #991B1B;
            --code: #F8FAFC;
        }}

        body {{
            background: var(--page);
            color: var(--ink);
            font-family: Arial, Helvetica, sans-serif;
            margin: 0;
            line-height: 1.5;
        }}

        .container {{
            max-width: 1120px;
            margin: 0 auto;
            padding: 30px;
        }}

        .report-header {{
            background: #FFFFFF;
            color: var(--header);
            padding: 0 0 16px 0;
            margin-bottom: 20px;
            border-bottom: 4px solid var(--primary-dark);
        }}

        .report-header h1 {{
            color: var(--header);
            margin: 0 0 8px 0;
            font-size: 27px;
            letter-spacing: 0;
        }}

        .report-header p {{
            margin: 4px 0;
            color: var(--muted);
        }}

        .card {{
            background: var(--panel);
            padding: 18px 0 6px 0;
            margin-bottom: 18px;
            border-radius: 0;
            border: none;
            border-bottom: 1px solid var(--soft-line);
            box-shadow: none;
        }}

        h1 {{
            color: var(--header);
            margin-top: 0;
        }}

        h2 {{
            color: var(--primary-dark);
            margin: 0 0 10px 0;
            font-size: 18px;
            border-bottom: 1px solid var(--soft-line);
            padding-bottom: 6px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            table-layout: fixed;
            font-size: 13px;
        }}

        th {{
            background: #E5E7EB;
            color: var(--header);
            padding: 8px;
            text-align: left;
            border: 1px solid var(--line);
        }}

        td {{
            padding: 7px;
            border: 1px solid var(--soft-line);
            word-wrap: break-word;
            vertical-align: top;
            background: #FFFFFF;
        }}

        tr:nth-child(even) td {{
            background: #F8FAFC;
        }}

        .metric {{
            display: inline-block;
            background: #F8FAFC;
            border: 1px solid var(--line);
            color: var(--ink);
            padding: 10px 14px;
            margin: 5px 8px 5px 0;
            border-radius: 4px;
            min-width: 190px;
        }}

        .ok {{
            color: var(--success);
            font-weight: 700;
        }}

        .warn {{
            color: var(--warning);
            font-weight: 700;
        }}

        .bad {{
            color: var(--danger);
            font-weight: 700;
        }}

        .muted {{
            color: var(--muted);
        }}

        pre {{
            white-space: pre-wrap;
            word-wrap: break-word;
            background: var(--code);
            color: #0F172A;
            border: 1px solid var(--line);
            padding: 10px;
            border-radius: 4px;
            max-height: 360px;
            overflow: auto;
            font-family: Consolas, Cascadia Mono, monospace;
            font-size: 12px;
        }}

        @media print {{
            body {{
                background: #FFFFFF;
            }}

            .container {{
                max-width: none;
                padding: 0;
            }}

            .card, .report-header {{
                box-shadow: none;
                break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
<div class="container">
    <div class="report-header">
        <h1>{self._safe(tool)} Security Report</h1>
        <p>{self._safe(title)} | {self._safe(author)}</p>
        <p>Generated At: {self._safe(generated_at)}</p>
    </div>
    <div class="card">
        <h2>Executive Summary</h2>
        <p>{self._safe(self._narrative(tool, analysis))}</p>
    </div>
"""

    def _base_html_end(self):
        return """
</div>
</body>
</html>
"""

    def _narrative(self, tool, analysis):
        if tool == "AD":
            metrics = analysis.get("metrics", {})
            detection_rate = metrics.get("detection_rate", 0)
            false_negative_rate = metrics.get("false_negative_rate", 0)

            if detection_rate == 100:
                return "All configured Windows event detections were observed for this attack."
            if detection_rate == 0:
                return "No configured Windows event detections were observed for this attack."
            if false_negative_rate > 50:
                return "Several expected detections were missed, indicating visibility or rule coverage gaps."
            return "The SIEM detected part of the expected activity, but rule coverage should be reviewed."

        if tool == "Packet":
            total = analysis.get("total_packets", 0)
            return f"{total} packets were captured and summarized for traffic review."

        if tool == "Port":
            total = len(analysis.get("open_ports", []))
            return f"{total} open ports were identified during the scan."

        return "Analysis completed."

    # ==============================
    # AD REPORT
    # ==============================

    def _render_ad_report(self, attack_data, correlation, analysis):
        metrics = analysis.get("metrics", {})
        matched = analysis.get("matched_alerts", [])
        missed = analysis.get("missed_events", [])
        unexpected = analysis.get("unexpected_alerts", [])
        timeline = analysis.get("timeline", [])
        recommendations = analysis.get("recommendations", [])

        html_body = f"""
    <div class="card">
        <h2>Attack Overview</h2>
        <p><b>Attack Type:</b> {self._safe(analysis.get("attack_type") or attack_data.get("attack_type"))}</p>
        <p><b>Tool:</b> {self._safe(attack_data.get("tool"))}</p>
        <p><b>Category:</b> {self._safe(attack_data.get("category"))}</p>
        <p><b>Target:</b> {self._safe(analysis.get("target") or attack_data.get("target"))}</p>
        <p><b>Duration:</b> {self._safe(attack_data.get("duration"))} seconds</p>
        <p><b>Command Status:</b> {self._safe(attack_data.get("command_status"))}</p>
        <p><b>Exit Status:</b> {self._safe(attack_data.get("exit_status"))}</p>
    </div>

    <div class="card">
        <h2>Detection Metrics</h2>
        <div class="metric"><b>Detection Rate:</b> {self._safe(metrics.get("detection_rate", 0))}%</div>
        <div class="metric"><b>False Positive Rate:</b> {self._safe(metrics.get("false_positive_rate", 0))}%</div>
        <div class="metric"><b>False Negative Rate:</b> {self._safe(metrics.get("false_negative_rate", 0))}%</div>
        <div class="metric"><b>Average Delay:</b> {self._safe(metrics.get("avg_detection_delay", 0))}s</div>
    </div>

    <div class="card">
        <h2>Detection Summary</h2>
        <p><b>Expected Events:</b> {self._safe(len(analysis.get("expected_events", [])))}</p>
        <p><b>Matched Alerts:</b> <span class="ok">{self._safe(len(matched))}</span></p>
        <p><b>Missed Events:</b> <span class="bad">{self._safe(len(missed))}</span></p>
        <p><b>Unexpected Alerts:</b> <span class="warn">{self._safe(len(unexpected))}</span></p>
    </div>
"""

        html_body += """
    <div class="card">
        <h2>Matched Alerts</h2>
"""

        if matched:
            html_body += """
        <table>
            <tr>
                <th>Time</th>
                <th>Windows Event ID</th>
                <th>Wazuh Rule ID</th>
                <th>Description</th>
                <th>Agent</th>
                <th>Source IP</th>
            </tr>
"""
            for alert in matched[:50]:
                html_body += f"""
            <tr>
                <td>{self._safe(alert.get("timestamp"))}</td>
                <td>{self._safe(self._windows_event_id(alert))}</td>
                <td>{self._safe(alert.get("rule_id"))}</td>
                <td>{self._safe(alert.get("rule_description"))}</td>
                <td>{self._safe(alert.get("agent"))}</td>
                <td>{self._safe(self._source_ip(alert))}</td>
            </tr>
"""
            html_body += """
        </table>
"""
        else:
            html_body += """
        <p>No expected alerts were matched.</p>
"""

        html_body += """
    </div>

    <div class="card">
        <h2>Missed Events</h2>
"""

        if missed:
            for event_id in missed:
                html_body += f"<p class='bad'>Windows Event ID {self._safe(event_id)} was not detected.</p>"
        else:
            html_body += "<p class='ok'>No expected Windows events were missed.</p>"

        html_body += """
    </div>
"""

        if unexpected:
            html_body += """
    <div class="card">
        <h2>Unexpected Alerts</h2>
        <table>
            <tr>
                <th>Time</th>
                <th>Windows Event ID</th>
                <th>Wazuh Rule ID</th>
                <th>Description</th>
                <th>Agent</th>
            </tr>
"""
            for alert in unexpected[:50]:
                html_body += f"""
            <tr>
                <td>{self._safe(alert.get("timestamp"))}</td>
                <td>{self._safe(self._windows_event_id(alert))}</td>
                <td>{self._safe(alert.get("rule_id"))}</td>
                <td>{self._safe(alert.get("rule_description"))}</td>
                <td>{self._safe(alert.get("agent"))}</td>
            </tr>
"""
            html_body += """
        </table>
    </div>
"""

        if recommendations:
            html_body += """
    <div class="card">
        <h2>Recommendations</h2>
"""
            for item in recommendations:
                html_body += f"<p>{self._safe(item)}</p>"

            html_body += """
    </div>
"""

        if timeline:
            html_body += """
    <div class="card">
        <h2>Attack Timeline</h2>
        <table>
            <tr>
                <th>Timestamp</th>
                <th>Step</th>
            </tr>
"""
            for item in timeline[:75]:
                html_body += f"""
            <tr>
                <td>{self._safe(item.get("timestamp"))}</td>
                <td>{self._safe(item.get("step"))}</td>
            </tr>
"""

            html_body += """
        </table>
    </div>
"""

        if attack_data.get("command"):
            html_body += f"""
    <div class="card">
        <h2>Executed Command</h2>
        <pre>{self._safe(attack_data.get("command"))}</pre>
    </div>
"""

        if attack_data.get("output"):
            html_body += f"""
    <div class="card">
        <h2>Command Output</h2>
        <pre>{self._safe(attack_data.get("output"))}</pre>
    </div>
"""

        if attack_data.get("error"):
            html_body += f"""
    <div class="card">
        <h2>Command Errors Or Warnings</h2>
        <pre>{self._safe(attack_data.get("error"))}</pre>
    </div>
"""

        return html_body

    # ==============================
    # PACKET REPORT
    # ==============================

    def _render_packet_report(self, analysis):
        packets = analysis.get("sample_packets", [])
        protocol_counts = Counter(packet.get("protocol", "OTHER") for packet in packets if packet)
        source_counts = Counter(packet.get("src", "N/A") for packet in packets if packet)

        html_body = f"""
    <div class="card">
        <h2>Packet Summary</h2>
        <p><b>Total Packets:</b> {self._safe(analysis.get("total_packets", 0))}</p>
    </div>
"""

        if protocol_counts:
            html_body += """
    <div class="card">
        <h2>Protocol Distribution</h2>
        <table>
            <tr>
                <th>Protocol</th>
                <th>Count</th>
            </tr>
"""
            for protocol, count in protocol_counts.items():
                html_body += f"""
            <tr>
                <td>{self._safe(protocol)}</td>
                <td>{self._safe(count)}</td>
            </tr>
"""
            html_body += """
        </table>
    </div>
"""

        if source_counts:
            html_body += """
    <div class="card">
        <h2>Top Source IPs</h2>
        <table>
            <tr>
                <th>Source IP</th>
                <th>Packets</th>
            </tr>
"""
            for source, count in source_counts.most_common(10):
                html_body += f"""
            <tr>
                <td>{self._safe(source)}</td>
                <td>{self._safe(count)}</td>
            </tr>
"""
            html_body += """
        </table>
    </div>
"""

        if packets:
            html_body += """
    <div class="card">
        <h2>Sample Packets</h2>
        <table>
            <tr>
                <th>Time</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Protocol</th>
                <th>Length</th>
                <th>Summary</th>
            </tr>
"""
            for packet in packets[:50]:
                html_body += f"""
            <tr>
                <td>{self._safe(packet.get("time"))}</td>
                <td>{self._safe(packet.get("src"))}:{self._safe(packet.get("sport"))}</td>
                <td>{self._safe(packet.get("dst"))}:{self._safe(packet.get("dport"))}</td>
                <td>{self._safe(packet.get("protocol"))}</td>
                <td>{self._safe(packet.get("length"))}</td>
                <td>{self._safe(packet.get("summary"))}</td>
            </tr>
"""
            html_body += """
        </table>
    </div>
"""

        return html_body

    # ==============================
    # PORT REPORT
    # ==============================

    def _render_port_report(self, analysis):
        ports = analysis.get("open_ports", [])

        html_body = f"""
    <div class="card">
        <h2>Port Summary</h2>
        <p><b>Total Open Ports:</b> {self._safe(len(ports))}</p>
    </div>
"""

        if ports:
            html_body += """
    <div class="card">
        <h2>Open Ports</h2>
        <table>
            <tr>
                <th>Host</th>
                <th>Port</th>
                <th>Service</th>
                <th>State</th>
                <th>Version</th>
            </tr>
"""
            for port in ports:
                html_body += f"""
            <tr>
                <td>{self._safe(port.get("host"))}</td>
                <td>{self._safe(port.get("port"))}</td>
                <td>{self._safe(port.get("service"))}</td>
                <td>{self._safe(port.get("state"))}</td>
                <td>{self._safe(port.get("version"))}</td>
            </tr>
"""
            html_body += """
        </table>
    </div>
"""
        else:
            html_body += """
    <div class="card">
        <h2>Open Ports</h2>
        <p>No open ports were reported.</p>
    </div>
"""

        return html_body

    # ==============================
    # MAIN
    # ==============================

    def generate_report(self, attack_data, corr, analysis):
        attack_data = attack_data or {}
        corr = corr or {}
        analysis = analysis or {}

        tool = self._identify_tool(attack_data.get("attack_type", analysis.get("attack_type", "")))

        os.makedirs(PATHS["reports_dir"], exist_ok=True)
        path = os.path.join(PATHS["reports_dir"], self._filename(tool))

        report_html = self._base_html_start(tool, analysis)

        if tool == "Packet":
            report_html += self._render_packet_report(analysis)

        elif tool == "Port":
            report_html += self._render_port_report(analysis)

        else:
            report_html += self._render_ad_report(attack_data, corr, analysis)

        report_html += self._base_html_end()

        with open(path, "w", encoding="utf-8") as file:
            file.write(report_html)

        print_success(f"Report generated: {path}")
        return path
