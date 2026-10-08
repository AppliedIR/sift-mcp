---
name: vhir-playbooks
description: 'Investigation playbooks: step-by-step procedures, each with its triggers, phases and MITRE techniques. Use when an investigation needs one of: Credential Access Investigation; Data Staging Investigation; DNS Anomaly Investigation; Email Compromise Investigation; Log Tampering Investigation; Malware Analysis Investigation; PowerShell Anomaly Investigation; Remote Access Investigation; Suspicious Autorun Investigation; Suspicious Network Connection Investigation; Suspicious Execution Investigation; Timestomping Investigation; Unusual Logon Investigation; USB Activity Investigation.'
metadata:
  generated-by: valhuntir-generator
  source: packages/forensic-knowledge/data/discipline/playbooks
---

# Investigation playbooks

Each playbook is in `references/`. Read the one that matches the activity you are investigating, and follow its phases with the MCP tools it names. forensic-mcp's `get_playbook` serves the same text.

- `references/credential_access.md`: Credential Access Investigation. Investigate indicators of credential theft, dumping, or Kerberos abuse
- `references/data_staging.md`: Data Staging Investigation. Investigate data collection and staging activity indicating preparation for exfiltration
- `references/dns_anomaly.md`: DNS Anomaly Investigation. Investigate DNS tunneling, domain generation algorithms, and unusual query patterns
- `references/email_compromise.md`: Email Compromise Investigation. Investigate email account takeover, mailbox rule manipulation, and business email compromise
- `references/log_tampering.md`: Log Tampering Investigation. Investigate event log clearing, suspicious gaps, and anti-forensic activity targeting log integrity
- `references/malware_analysis.md`: Malware Analysis Investigation. Investigation procedure when suspicious executables, documents, or scripts are discovered during forensic triage
- `references/powershell_anomaly.md`: PowerShell Anomaly Investigation. Investigate suspicious PowerShell activity including encoded commands, download cradles, and obfuscated scripts
- `references/remote_access.md`: Remote Access Investigation. Investigate unexpected remote access including RDP, PsExec, WMI, and WinRM connections
- `references/suspicious_autorun.md`: Suspicious Autorun Investigation. Investigate unexpected persistence mechanisms including registry autoruns, services, and scheduled tasks
- `references/suspicious_connection.md`: Suspicious Network Connection Investigation. Investigate anomalous network connections including beaconing, unusual ports, and known-bad destinations
- `references/suspicious_execution.md`: Suspicious Execution Investigation. Investigate unknown or unexpected program execution from forensic artifacts
- `references/timestomping.md`: Timestomping Investigation. Investigate timestamp manipulation in NTFS file system metadata
- `references/unusual_logon.md`: Unusual Logon Investigation. Investigate unexpected authentication events indicating unauthorized access or credential misuse
- `references/usb_activity.md`: USB Activity Investigation. Investigate USB device connections and removable media activity for data theft or malware delivery
