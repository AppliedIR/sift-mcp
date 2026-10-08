# DNS Anomaly Investigation

Investigate DNS tunneling, domain generation algorithms, and unusual query patterns

MITRE ATT&CK: T1071.004, T1568.002

## Triggers

- High-entropy domain queries suggesting DGA
- Excessive DNS query volume from single host
- Long subdomain labels suggesting DNS tunneling
- Unusual TXT record queries or responses

## Phase 1: Identify

1. Analyze DNS logs or PCAP using tshark with DNS filter (via sift-mcp) — tshark -Y dns
2. Parse Zeek dns.log for query patterns (via sift-mcp)
3. Filter for unusual query patterns — long names, high frequency, non-standard types

## Phase 2: Classify

1. Check for DGA characteristics — random-looking labels, high character entropy, mathematical patterns
2. Check for tunneling indicators — long subdomain labels (>30 chars), high volume TXT queries, encoded data in queries
3. Compare against known benign high-volume DNS patterns (CDN, telemetry)

## Phase 3: Threat Intel

1. Check suspicious domains against threat intelligence (opencti: lookup_ioc)
2. Search for DNS exfiltration and tunneling techniques (forensic-rag: search)

## Phase 4: Source

1. Identify which systems and processes are generating the anomalous queries
2. Check if DNS queries correlate with process execution on endpoint using Sysmon Event ID 22

## Phase 5: Record

1. Record finding including DNS patterns, source systems, and threat intelligence results
2. Include all evidence IDs from each analysis phase

## Sources

- SANS FOR572 — Advanced Network Forensics
- MITRE ATT&CK T1071.004 — DNS
- MITRE ATT&CK T1568.002 — Domain Generation Algorithms
