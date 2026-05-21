"""
correlator.py

Correlation engine for AD SIEM attack validation.

Matches configured expected Windows Event IDs against normalized Wazuh alerts,
while keeping reporter/analyzer compatibility keys stable.
"""

from datetime import datetime

from config import ATTACK_CONFIG
from utils import print_status, print_success, print_warning, parse_timestamp


class Correlator:
    def __init__(self):
        pass

    # ==============================
    # TIMESTAMP HELPERS
    # ==============================

    def _parse_time(self, value):
        if not value:
            return None

        parsed = parse_timestamp(value)
        if parsed:
            return parsed

        try:
            cleaned = str(value).replace("Z", "+00:00")
            return datetime.fromisoformat(cleaned)
        except Exception:
            return None

    # ==============================
    # ALERT EXTRACTION HELPERS
    # ==============================

    def _get_raw_alert(self, alert):
        if not isinstance(alert, dict):
            return {}
        return alert.get("raw", {}) or {}

    def _get_windows_event_id(self, alert):
        raw = self._get_raw_alert(alert)

        paths = [
            ["data", "win", "system", "eventID"],
            ["data", "win", "system", "eventId"],
            ["data", "win", "eventdata", "eventID"],
        ]

        for path in paths:
            current = raw
            for key in path:
                if not isinstance(current, dict):
                    current = None
                    break
                current = current.get(key)

            if current not in (None, ""):
                return str(current)

        direct_keys = ["event_id", "eventID", "win_event_id"]
        for key in direct_keys:
            value = alert.get(key)
            if value not in (None, ""):
                return str(value)

        return None

    def _get_wazuh_rule_id(self, alert):
        rule_id = alert.get("rule_id")
        if rule_id not in (None, ""):
            return str(rule_id)

        raw = self._get_raw_alert(alert)
        rule_id = raw.get("rule", {}).get("id")
        if rule_id not in (None, ""):
            return str(rule_id)

        return None

    def _alert_identity(self, alert):
        windows_event_id = self._get_windows_event_id(alert)
        wazuh_rule_id = self._get_wazuh_rule_id(alert)

        return {
            "windows_event_id": windows_event_id,
            "wazuh_rule_id": wazuh_rule_id,
            "primary_id": windows_event_id or wazuh_rule_id,
        }

    def _alert_matches_expected(self, alert, expected_event_id, expected_rule_ids):
        identity = self._alert_identity(alert)
        expected_event_id = str(expected_event_id)

        if identity["windows_event_id"] == expected_event_id:
            return True

        if identity["wazuh_rule_id"] in expected_rule_ids:
            return True

        return False

    # ==============================
    # TIMELINE
    # ==============================

    def _build_timeline(self, attack_data, alerts):
        timeline = []

        for item in attack_data.get("timeline", []):
            if isinstance(item, dict):
                timeline.append(item)

        for alert in alerts:
            identity = self._alert_identity(alert)
            event_label = identity["windows_event_id"] or identity["wazuh_rule_id"] or "N/A"

            timeline.append({
                "step": f"Alert {event_label}: {alert.get('rule_description', 'N/A')}",
                "timestamp": alert.get("timestamp")
            })

        return sorted(
            timeline,
            key=lambda x: self._parse_time(x.get("timestamp")) or datetime.min
        )

    # ==============================
    # MAIN CORRELATION
    # ==============================

    def correlate(self, attack_data, alerts):
        print_status("Starting correlation process...")

        if not attack_data:
            print_warning("No attack data provided")
            return {}

        if not alerts:
            alerts = []

        attack_key = attack_data.get("attack_key")
        attack_time = self._parse_time(attack_data.get("timestamp"))

        if attack_key not in ATTACK_CONFIG:
            print_warning("Attack key mismatch with config")
            return {}

        attack_config = ATTACK_CONFIG[attack_key]
        expected_events = attack_config.get("expected_event_ids", [])
        expected_rule_ids = set(str(x) for x in attack_config.get("expected_rule_ids", []))
        expected_event_set = set(str(x) for x in expected_events)

        matched_alerts = []
        missed_events = []
        unexpected_alerts = []
        detection_delays = []
        matched_alert_indexes = set()

        # ==============================
        # MATCH EXPECTED WINDOWS EVENTS
        # ==============================

        for event_id in expected_events:
            found = False

            for index, alert in enumerate(alerts):
                if index in matched_alert_indexes:
                    continue

                if not self._alert_matches_expected(alert, event_id, expected_rule_ids):
                    continue

                found = True
                matched_alert_indexes.add(index)
                matched_alerts.append(alert)

                alert_time = self._parse_time(alert.get("timestamp"))
                if attack_time and alert_time:
                    delay = (alert_time - attack_time).total_seconds()
                    if delay >= 0:
                        detection_delays.append(delay)

                break

            if not found:
                missed_events.append(event_id)

        # ==============================
        # UNEXPECTED ALERTS
        # ==============================

        for index, alert in enumerate(alerts):
            if index in matched_alert_indexes:
                continue

            identity = self._alert_identity(alert)
            primary_id = identity["primary_id"]

            if not primary_id:
                continue

            if primary_id not in expected_event_set and primary_id not in expected_rule_ids:
                unexpected_alerts.append(alert)

        # ==============================
        # METRICS
        # ==============================

        total_expected = len(expected_events)
        total_detected = len(matched_alerts)

        detection_rate = (total_detected / total_expected * 100) if total_expected else 0
        false_positive_rate = len(unexpected_alerts) / (len(alerts) or 1) * 100
        false_negative_rate = len(missed_events) / (total_expected or 1) * 100

        avg_delay = (
            sum(detection_delays) / len(detection_delays)
            if detection_delays else 0
        )

        result = {
            "attack_type": attack_data.get("attack_type"),
            "attack_key": attack_key,
            "target": attack_data.get("target"),

            "expected_events": expected_events,
            "matched_alerts": matched_alerts,
            "missed_events": missed_events,
            "unexpected_alerts": unexpected_alerts,

            "matched": matched_alerts,
            "missed": missed_events,
            "unexpected": unexpected_alerts,

            "metrics": {
                "detection_rate": round(detection_rate, 2),
                "false_positive_rate": round(false_positive_rate, 2),
                "false_negative_rate": round(false_negative_rate, 2),
                "avg_detection_delay": round(avg_delay, 2)
            },

            "timeline": self._build_timeline(attack_data, alerts),
            "detection_delays": detection_delays
        }

        print_success("Correlation completed")
        return result
