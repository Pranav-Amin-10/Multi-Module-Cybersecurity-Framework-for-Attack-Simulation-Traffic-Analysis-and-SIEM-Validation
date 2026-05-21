"""
utils.py

Helper utilities for directory management, timestamps, JSON logging, and
console output.
"""

import json
import os
from datetime import datetime

from config import PATHS


# ==============================
# DIRECTORY MANAGEMENT
# ==============================

def ensure_directories():
    os.makedirs(PATHS["logs_dir"], exist_ok=True)
    os.makedirs(PATHS["reports_dir"], exist_ok=True)


# ==============================
# TIME UTILITIES
# ==============================

def get_current_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_filename_timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def parse_timestamp(value):
    if not value:
        return None

    value = str(value).strip()

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
    ]

    for timestamp_format in formats:
        try:
            parsed = datetime.strptime(value, timestamp_format)
            if parsed.tzinfo is not None:
                parsed = parsed.replace(tzinfo=None)
            return parsed
        except ValueError:
            pass

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            parsed = parsed.replace(tzinfo=None)
        return parsed
    except ValueError:
        return None


# ==============================
# JSON FILE HELPERS
# ==============================

def _log_path(file_name):
    ensure_directories()
    return os.path.join(PATHS["logs_dir"], file_name)


def _read_json_file(file_path, default):
    if not os.path.exists(file_path):
        return default

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError):
        return default


def _write_json_file(file_path, data):
    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, default=str)


def log_event(file_name, data):
    file_path = _log_path(file_name)
    existing_data = _read_json_file(file_path, [])

    if not isinstance(existing_data, list):
        existing_data = [existing_data]

    existing_data.append(data)
    _write_json_file(file_path, existing_data)


def save_json(file_name, data):
    file_path = _log_path(file_name)
    _write_json_file(file_path, data)


def load_json(file_name):
    file_path = _log_path(file_name)
    return _read_json_file(file_path, None)


# ==============================
# CONSOLE OUTPUT
# ==============================

def print_status(message, status="INFO"):
    timestamp = get_current_timestamp()
    print(f"[{timestamp}] [{status}] {message}")


def print_success(message):
    print_status(message, "SUCCESS")


def print_error(message):
    print_status(message, "ERROR")


def print_warning(message):
    print_status(message, "WARNING")


# ==============================
# DATA HELPERS
# ==============================

def format_attack_log(attack_type, target_ip):
    return {
        "timestamp": get_current_timestamp(),
        "attack_type": attack_type,
        "target": target_ip,
    }


def format_alert_log(alert):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})

    try:
        windows_event_id = (
            alert.get("data", {})
            .get("win", {})
            .get("system", {})
            .get("eventID")
        )
    except Exception:
        windows_event_id = None

    return {
        "timestamp": alert.get("timestamp"),
        "rule_id": rule.get("id"),
        "rule_description": rule.get("description"),
        "windows_event_id": windows_event_id,
        "agent_name": agent.get("name"),
        "full_log": alert,
    }
