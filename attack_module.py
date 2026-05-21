"""
attack_module.py

Attack execution module.

Connects to the Kali VM over SSH, runs the configured AD attack command, records
timeline data, and returns structured output for collector/correlator/analyzer.
"""

import re
import time
from datetime import datetime

import paramiko

from config import ATTACK_CONFIG, LAB_CONFIG
from utils import (
    print_status,
    print_success,
    print_error,
    format_attack_log,
    log_event,
)


class AttackModule:
    def __init__(self):
        self.kali_config = LAB_CONFIG["KALI"]
        self.ssh_client = None

    # ==============================
    # TIMELINE
    # ==============================

    def _timestamp(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _add_timeline_step(self, timeline, step):
        timestamp = self._timestamp()
        timeline.append({
            "step": step,
            "timestamp": timestamp
        })
        print_status(f"[{timestamp}] {step}")

    # ==============================
    # SSH CONNECTION
    # ==============================

    def connect(self):
        try:
            print_status("Connecting to Kali VM via SSH...")

            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            self.ssh_client.connect(
                hostname=self.kali_config["ip"],
                username=self.kali_config["username"],
                password=self.kali_config["password"],
                timeout=10,
                banner_timeout=10,
                auth_timeout=10,
            )

            print_success("SSH connection established with Kali")
            return True

        except Exception as e:
            print_error(f"SSH connection failed: {e}")
            self.ssh_client = None
            return False

    def disconnect(self):
        if not self.ssh_client:
            return

        try:
            self.ssh_client.close()
            print_status("SSH connection closed")
        except Exception as e:
            print_error(f"SSH disconnect warning: {e}")
        finally:
            self.ssh_client = None

    # ==============================
    # COMMAND HELPERS
    # ==============================

    def _clean_command_output(self, text):
        if not text:
            return ""

        text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)
        text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)

        return text.strip()

    def _status_message(self, exit_status, output, error):
        combined = f"{output}\n{error}"

        if "[PRECHECK_FAILED]" in combined:
            return "Target service precheck failed"

        if exit_status == 0:
            return "Completed"

        if exit_status == -1:
            return "Timed out"

        return "Completed with tool error"

    def _build_command(self, attack_key, target_ip):
        attack = ATTACK_CONFIG[attack_key]
        return attack["command"].format(target=target_ip)

    def _read_channel(self, channel, stdout, stderr, timeout):
        output_chunks = []
        error_chunks = []

        started = time.time()

        while True:
            if stdout.channel.recv_ready():
                output_chunks.append(stdout.channel.recv(4096).decode(errors="replace"))

            if stderr.channel.recv_stderr_ready():
                error_chunks.append(stderr.channel.recv_stderr(4096).decode(errors="replace"))

            if channel.exit_status_ready():
                break

            if timeout and time.time() - started > timeout:
                channel.close()
                error_chunks.append(f"\nCommand timed out after {timeout} seconds.")
                return "".join(output_chunks), "".join(error_chunks), -1

            time.sleep(0.2)

        exit_status = channel.recv_exit_status()

        remaining_output = stdout.read().decode(errors="replace")
        remaining_error = stderr.read().decode(errors="replace")

        if remaining_output:
            output_chunks.append(remaining_output)

        if remaining_error:
            error_chunks.append(remaining_error)

        return "".join(output_chunks), "".join(error_chunks), exit_status

    # ==============================
    # EXECUTION
    # ==============================

    def execute_attack(self, attack_key, target_ip):
        if attack_key not in ATTACK_CONFIG:
            print_error("Invalid attack type selected")
            return None

        if not self.ssh_client:
            print_error("SSH client is not connected")
            return None

        attack = ATTACK_CONFIG[attack_key]
        command = self._build_command(attack_key, target_ip)
        timeout = attack.get("timeout", 180)

        timeline = []

        try:
            start_time = time.time()

            self._add_timeline_step(timeline, "Attack started")
            self._add_timeline_step(timeline, f"Selected attack: {attack.get('name', attack_key)}")
            self._add_timeline_step(timeline, f"Tool: {attack.get('tool', 'N/A')}")
            self._add_timeline_step(timeline, "Command execution started")

            stdin, stdout, stderr = self.ssh_client.exec_command(
                command,
                get_pty=True,
                timeout=timeout
            )

            channel = stdout.channel
            output, error, exit_status = self._read_channel(
                channel,
                stdout,
                stderr,
                timeout
            )

            output = self._clean_command_output(output)
            error = self._clean_command_output(error)
            command_status = self._status_message(exit_status, output, error)

            self._add_timeline_step(timeline, "Command execution completed")

            duration = round(time.time() - start_time, 2)

            if output:
                print_status("Attack output:")
                print(output)

            if error:
                print_error("Attack errors/warnings:")
                print(error)

            if exit_status == 0:
                print_success("Attack command completed successfully")
            elif command_status == "Target service precheck failed":
                print_error("Attack command skipped because the target service is not reachable")
            else:
                print_error(f"Attack command completed with exit status {exit_status}")

            attack_log = format_attack_log(attack_key, target_ip)
            attack_log.update({
                "attack_name": attack.get("name", attack_key),
                "tool": attack.get("tool", "N/A"),
                "category": attack.get("category", "N/A"),
                "command": command,
                "exit_status": exit_status,
                "command_status": command_status,
                "duration": duration,
            })

            log_event("attack_logs.json", attack_log)

            return {
                "attack_type": attack.get("name", attack_key),
                "attack_key": attack_key,
                "target": target_ip,
                "tool": attack.get("tool", "N/A"),
                "category": attack.get("category", "N/A"),
                "description": attack.get("description", ""),
                "command": command,
                "output": output,
                "error": error,
                "exit_status": exit_status,
                "command_status": command_status,
                "timestamp": attack_log["timestamp"],
                "duration": duration,
                "timeline": timeline,
            }

        except Exception as e:
            print_error(f"Attack execution failed: {e}")
            self._add_timeline_step(timeline, "Attack execution failed")
            return None

    # ==============================
    # MAIN FLOW
    # ==============================

    def run(self, attack_key, target_ip):
        if not self.connect():
            return None

        try:
            return self.execute_attack(attack_key, target_ip)
        finally:
            self.disconnect()
