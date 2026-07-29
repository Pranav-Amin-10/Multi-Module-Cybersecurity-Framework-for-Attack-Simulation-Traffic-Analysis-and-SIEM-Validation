"""
collector.py

Wazuh alert collector.

Reads recent alerts from the Wazuh server over SSH, normalizes them into the
shape expected by the correlator/analyzer/reporter pipeline, and preserves the
raw alert for detailed AD event correlation.
"""

import json
import os
import datetime

import paramiko

import config
import utils


class WazuhCollector:
    def __init__(self):
        wazuh_config = config.LAB_CONFIG["WAZUH_API"]

        self.host = wazuh_config["host"]
        self.username = os.getenv("WAZUH_SSH_USER", "wazuh")
        self.password = os.getenv("WAZUH_SSH_PASSWORD", "1234")
        self.log_path = os.getenv("WAZUH_ALERT_LOG", "/var/ossec/logs/alerts/alerts.json")

    def _connect(self):
        try:
            utils.print_status("Connecting to Wazuh via SSH...")

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            ssh.connect(
                hostname=self.host,
                username=self.username,
                password=self.password,
                timeout=10,
                banner_timeout=10,
                auth_timeout=10,
            )

            utils.print_success("SSH connected to Wazuh")
            return ssh

        except Exception as e:
            utils.print_error(f"SSH connection failed: {e}")
            return None

    def _parse_wazuh_timestamp(self, value):
        if not value:
            return None

        value = str(value).strip()

        formats = [
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
        ]

        for fmt in formats:
            try:
                return datetime.datetime.strptime(value, fmt)
            except ValueError:
                pass

        try:
            return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None

    def _display_timestamp(self, value):
        parsed = self._parse_wazuh_timestamp(value)
        if not parsed:
            return value or ""
        return parsed.strftime("%Y-%m-%d %H:%M:%S")

    def _is_recent(self, raw_timestamp):
        parsed = self._parse_wazuh_timestamp(raw_timestamp)

        if not parsed:
            return False

        if parsed.tzinfo:
            parsed = parsed.astimezone(datetime.timezone.utc)
            now = datetime.datetime.now(datetime.timezone.utc)
        else:
            now = datetime.datetime.now()

        past = now - datetime.timedelta(minutes=config.FRAMEWORK_CONFIG["time_window_minutes"])
        return parsed >= past

    def _get_windows_event_id(self, alert):
        try:
            value = alert.get("data", {}).get("win", {}).get("system", {}).get("eventID")
            if value not in (None, ""):
                return str(value)
        except Exception:
            pass

        return None

    def _get_source_ip(self, alert):
        try:
            value = alert.get("data", {}).get("win", {}).get("eventdata", {}).get("ipAddress")
            if value not in (None, "", "-"):
                return str(value)
        except Exception:
            pass

        return None

    def _is_ipv4_address(self, value):
        parts = str(value).split(".")
        return len(parts) == 4 and all(part.isdigit() for part in parts)

    def _add_alias(self, aliases, value):
        if value in (None, "", "-"):
            return

        value = str(value).strip().lower()
        if not value or value == "none":
            return

        aliases.add(value)

        if "." in value and not self._is_ipv4_address(value):
            aliases.add(value.split(".")[0])

    def _target_aliases(self, target):
        aliases = set()

        if not target:
            return aliases

        target = str(target).strip().lower()
        self._add_alias(aliases, target)

        for host_key, host_config in config.LAB_CONFIG.items():
            if not isinstance(host_config, dict):
                continue

            values = {
                str(host_key).lower(),
                str(host_config.get("ip", "")).lower(),
                str(host_config.get("hostname", "")).lower(),
                str(host_config.get("fqdn", "")).lower(),
            }

            if target in values:
                for value in values:
                    self._add_alias(aliases, value)

        return aliases

    def _alert_agent_aliases(self, alert):
        raw = alert.get("raw", {}) if isinstance(alert, dict) else {}

        values = {
            alert.get("agent"),
            alert.get("agent_ip"),
            raw.get("agent", {}).get("name"),
            raw.get("agent", {}).get("ip"),
        }

        try:
            values.add(
                raw.get("data", {})
                .get("win", {})
                .get("system", {})
                .get("computer")
            )
        except Exception:
            pass

        aliases = set()
        for value in values:
            self._add_alias(aliases, value)

        return aliases

    def _matches_target_agent(self, alert, target):
        target_aliases = self._target_aliases(target)

        if not target_aliases:
            return True

        return bool(target_aliases.intersection(self._alert_agent_aliases(alert)))

    def _normalize(self, alert):
        try:
            rule = alert.get("rule", {})
            agent = alert.get("agent", {})

            return {
                "timestamp": self._display_timestamp(alert.get("timestamp", "")),
                "rule_id": str(rule.get("id", "")),
                "rule_description": rule.get("description", "N/A"),
                "severity": rule.get("level", 0),
                "agent": agent.get("name", "N/A"),
                "agent_ip": agent.get("ip"),
                "windows_event_id": self._get_windows_event_id(alert),
                "source_ip": self._get_source_ip(alert),
                "raw": alert,
            }

        except Exception:
            return None

    def fetch_alerts(self, target=None):
        ssh = self._connect()

        if not ssh:
            return []

        try:
            utils.print_status("Reading alerts.json from Wazuh...")

            max_alerts = config.FRAMEWORK_CONFIG["max_alerts_fetch"]
            cmd = f"tail -n {max_alerts} {self.log_path}"

            stdin, stdout, stderr = ssh.exec_command(cmd)

            output = stdout.read().decode(errors="replace")
            error = stderr.read().decode(errors="replace").strip()

            if error:
                utils.print_error(f"Wazuh log read warning: {error}")

            alerts = []

            for line in output.splitlines():
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if not self._is_recent(data.get("timestamp", "")):
                    continue

                normalized = self._normalize(data)
                if normalized and self._matches_target_agent(normalized, target):
                    alerts.append(normalized)

            if target:
                utils.print_success(f"Collected {len(alerts)} alerts from logs for target {target}")
            else:
                utils.print_success(f"Collected {len(alerts)} alerts from logs")

            utils.log_event("wazuh_alerts.json", alerts)

            return alerts

        except Exception as e:
            utils.print_error(f"Log fetch error: {e}")
            return []

        finally:
            try:
                ssh.close()
            except Exception:
                pass

    def run(self, target=None):
        alerts = self.fetch_alerts(target)

        if not alerts:
            utils.print_error("No alerts collected (check Wazuh agent/logs)")
        else:
            utils.print_success("Alerts successfully collected")

        return alerts
