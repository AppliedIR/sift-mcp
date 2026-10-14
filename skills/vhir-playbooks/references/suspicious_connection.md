# Suspicious Network Connection Investigation

Investigate anomalous network connections including beaconing, unusual ports, and known-bad destinations

MITRE ATT&CK: T1071, T1573

## Triggers

- Regular beaconing pattern detected in network traffic
- Outbound connections on unusual ports
- Connections to known-bad IP addresses or domains
- High-volume data transfer to external destination
- Long-duration connections inconsistent with normal traffic

## Phase 1: Identify

1. Analyze PCAP or Zeek logs using tshark or zeek (via sift-mcp)
2. Check conversation statistics for beaconing patterns — regular intervals, consistent payload sizes
3. Identify top talkers and unusual protocol usage

## Phase 2: Threat Intel

1. Check destination IPs and domains against threat intelligence (opencti: lookup_ioc)
2. Search for C2 communication patterns and known malware profiles (forensic-rag: search_knowledge)

## Phase 3: Process Mapping

1. If process data available, identify which process made the connection using Volatility3 netscan (via sift-mcp)
2. Check Sysmon Event ID 3 for network connection events with process context
3. Verify processes against baseline (windows-triage: check_process_tree)

## Phase 4: Payload

1. Extract HTTP objects from PCAP using tshark's HTTP object export (via sift-mcp)
2. Check DNS queries for tunneling indicators — long labels, high query volume, TXT records
3. Analyze extracted payloads for malicious content (remnux: analyze_file)

## Phase 5: Record

1. Record finding including network indicators, process context, and threat intelligence results
2. Include all evidence IDs from each analysis phase

## Sources

- SANS FOR572 — Advanced Network Forensics
- MITRE ATT&CK T1071 — Application Layer Protocol
- MITRE ATT&CK T1573 — Encrypted Channel
