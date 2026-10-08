# Email Compromise Investigation

Investigate email account takeover, mailbox rule manipulation, and business email compromise

MITRE ATT&CK: T1114, T1534

## Triggers

- New mailbox forwarding rules created
- Delegate access granted to mailbox
- Sign-in from unusual location or impossible travel detected
- Sent items containing fraudulent or phishing content
- OAuth application granted mail permissions

## Phase 1: Account

1. Review sign-in logs for unauthorized access patterns
2. Check for impossible travel — logins from geographically distant locations in short timeframes
3. Identify all compromised accounts and the initial access method

## Phase 2: Rules

1. Check mailbox rules for forwarding rules, auto-delete rules, or move-to-folder rules that hide activity
2. Check for delegated access grants — full access, send-as, send-on-behalf
3. Check OAuth application permissions for mail.read, mail.send, or similar scopes

## Phase 3: Content

1. Review sent items for phishing emails or fraudulent messages
2. Check for internal spearphishing — compromised account targeting other employees
3. Search for related social engineering techniques (forensic-rag: search)

## Phase 4: Impact

1. Identify financial transactions initiated through compromised email accounts
2. Determine scope of data exposure — what emails, attachments, or contacts were accessed
3. Check if compromised account credentials were used for other services

## Phase 5: Record

1. Record finding with all evidence of compromise, rule changes, and impact
2. HITL checkpoint — financial impact requires examiner decision on notification and containment

## Sources

- SANS FOR509 — Enterprise Cloud Forensics and Incident Response
- MITRE ATT&CK T1114 — Email Collection
- MITRE ATT&CK T1534 — Internal Spearphishing
- FBI IC3 — Business Email Compromise guidance
