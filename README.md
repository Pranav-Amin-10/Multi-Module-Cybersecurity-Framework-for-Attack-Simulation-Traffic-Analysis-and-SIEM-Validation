The UI provides:

- AD attack validation
- Packet capture
- Port scanning
- HTML report generation

The Network Analyzer module has been removed.

## Lab Topology

Default lab hosts are configured in `config.py`:

| Host | Default IP |
| --- | --- |
| DC01 | `192.168.56.10` |
| WIN10 | `192.168.56.20` |
| Kali | `192.168.56.30` |
| Wazuh | `192.168.56.50` |

## AD Attack Flow

For each AD attack, the framework:

1. Connects to Kali over SSH.
2. Runs the configured Kali tool command.
3. Waits for Wazuh log ingestion.
4. Reads recent Wazuh alerts from `/var/ossec/logs/alerts/alerts.json`.
5. Matches expected Windows Event IDs.
6. Calculates detection metrics.
7. Generates an HTML SOC report.

## Included AD Attack Types

Configured attacks include:

- SMB brute force
- RDP brute force
- PsExec remote execution
- SMB share enumeration
- SMB password spray
- WinRM brute force
- Evil-WinRM login
- Kerberos user enumeration
- AS-REP roasting
- Kerberoasting
- LDAP RootDSE enumeration
- BloodHound collection
- DCSync attempt

## Requirements

Install dependencies:

```bash
pip install -r requirements.txt
```

The Kali VM must have the referenced attack tools installed, such as:

- CrackMapExec
- Hydra
- Impacket
- Evil-WinRM
- Kerbrute
- ldapsearch
- bloodhound-python

Packet capture may require administrator/root privileges and a working packet capture backend.

Port scanning requires nmap installed and available on PATH.

## Reports And Logs

Generated logs are stored in:

```txt
logs/
```

Generated HTML reports are stored in:

```txt
reports/
```

## Configuration

Primary configuration is in:

```txt
config.py
```

No `.env` file is required. The project uses default lab values directly from `config.py`.

Some values can optionally be overridden through environment variables, but this is not required for normal lab demonstration.

## Safety Note

Run this framework only inside a lab where you have explicit permission to execute attacks and collect logs.
```

Next file: `collector.py`

I want to revisit it once more because it connects directly to Wazuh and must align perfectly with the updated correlation logic. Please send the current final version you plan to use for `collector.py`.