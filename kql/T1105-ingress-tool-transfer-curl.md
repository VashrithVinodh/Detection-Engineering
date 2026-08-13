
# T1105 — Ingress Tool Transfer via curl

**MITRE ATT&CK:** T1105 — Ingress Tool Transfer  
**Tactic:** Command and Control  
**Data Source:** `ProcessEvents`  
**Severity:** Medium

### Behavior

The `curl` utility is used to retrieve resources from a remote HTTP/HTTPS location.

### Detection Logic

Detects execution of `curl` where the command line contains an HTTP or HTTPS URL.

### False Positives

Legitimate software installation, system administration, API requests, development, automation, and CI/CD activity.

### Detection

```kql
ProcessEvents
| where process_name =~ "curl"
| where process_commandline has_any ("http://", "https://")
| project timestamp, hostname, process_name, process_commandline
