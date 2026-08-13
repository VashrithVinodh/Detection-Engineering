# T1105 - Suspicious Host-to-Email Activity

**MITRE ATT&CK:** T1105 — Ingress Tool Transfer  
**Tactic:** Command and Control  
**Data Source:** `ProcessEvents`, `Employees`, `Email`  
**Severity:** High

### Behavior

A host associated with suspicious `curl` activity is subsequently associated with an employee account that sends an email containing a potentially malicious or socially engineered subject.

### Detection Logic

Correlates hosts executing `curl` with employee identities and searches for subsequent outbound email activity originating from those identities.

### False Positives

Legitimate use of `curl` by employees, developers, administrators, or automated systems followed by normal business email activity.

### Detection

```kql
let compromised_hosts =
ProcessEvents
| where process_commandline contains "curl"
| distinct hostname;

let compromised_sender =
Employees
| where hostname in (compromised_hosts)
| distinct email_addr;

Email
| where sender in (compromised_sender)
| where subject contains "software documentation"
| project timestamp, sender, recipient, subject
