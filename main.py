"""
main.py

CLI entry point for AD SIEM Attack Detection & Validation Framework.

Primary demonstration flow is ui_app.py. This file remains as a lightweight
command-line fallback for running AD attacks and generating reports.
"""

import time

from analyzer import Analyzer
from attack_module import AttackModule
from collector import WazuhCollector
from config import ATTACK_CONFIG, FRAMEWORK_CONFIG, LAB_CONFIG
from correlator import Correlator
from reporter import Reporter
from utils import (
    ensure_directories,
    print_status,
    print_success,
    print_error,
)


# ==============================
# DISPLAY MENU
# ==============================

def display_menu():
    print("\n===== AD SIEM Framework =====")
    print("Select AD Attack Type:\n")

    for index, attack_key in enumerate(ATTACK_CONFIG.keys(), start=1):
        attack = ATTACK_CONFIG[attack_key]
        tool = attack.get("tool", "N/A")
        category = attack.get("category", "N/A")

        print(f"{index}. {attack['name']} [{tool} | {category}]")

    print("0. Exit")


def get_attack_choice():
    attack_keys = list(ATTACK_CONFIG.keys())

    try:
        choice = int(input("\nEnter choice: ").strip())

        if choice == 0:
            return None

        if 1 <= choice <= len(attack_keys):
            return attack_keys[choice - 1]

        print_error("Invalid choice")
        return ""

    except ValueError:
        print_error("Please enter a valid number")
        return ""


def get_target_ip():
    target = input("Enter Target IP (DC01/WIN10 or IP): ").strip()

    shortcuts = {
        "dc01": LAB_CONFIG["DC01"]["ip"],
        "win10": LAB_CONFIG["WIN10"]["ip"],
    }

    return shortcuts.get(target.lower(), target)


# ==============================
# AD WORKFLOW
# ==============================

def run_ad_workflow(attack_key, target_ip):
    attack_module = AttackModule()
    collector = WazuhCollector()
    correlator = Correlator()
    analyzer = Analyzer()
    reporter = Reporter()

    attack_data = attack_module.run(attack_key, target_ip)

    if not attack_data:
        print_error("Attack failed. Skipping report generation.")
        return None

    wait_time = FRAMEWORK_CONFIG.get("log_wait_time", 15)
    print_status(f"Waiting {wait_time} seconds for Wazuh log ingestion...")
    time.sleep(wait_time)

    alerts = collector.run(target_ip)

    if not alerts:
        print_error("No alerts fetched. Correlation may show missed detections.")

    correlation_result = correlator.correlate(attack_data, alerts)

    if not correlation_result:
        print_error("Correlation failed.")
        return None

    analysis_result = analyzer.analyze(correlation_result)

    if not analysis_result:
        print_error("Analysis failed.")
        return None

    report_path = reporter.generate_report(
        attack_data,
        correlation_result,
        analysis_result
    )

    print_success(f"Process completed. Report saved at: {report_path}")
    return report_path


# ==============================
# MAIN FLOW
# ==============================

def main():
    ensure_directories()

    while True:
        display_menu()

        attack_key = get_attack_choice()

        if attack_key is None:
            print_status("Exiting framework...")
            break

        if not attack_key:
            continue

        target_ip = get_target_ip()

        if not target_ip:
            print_error("Target IP is required.")
            continue

        run_ad_workflow(attack_key, target_ip)


# ==============================
# ENTRY POINT
# ==============================

if __name__ == "__main__":
    main()
