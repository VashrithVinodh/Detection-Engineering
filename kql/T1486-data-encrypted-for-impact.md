# T1486 — Data Encrypted for Impact

**MITRE ATT&CK:** T1486 — Data Encrypted for Impact  
**Tactic:** Impact  
**Data Source:** `FileCreationEvents`  
**Severity:**  High

### Behavior

Multiple files are created with an encryption-related extension, potentially indicating ransomware activity.

### Detection Logic

Detects hosts creating 10 or more files with the `.encrypted` extension.

### False Positives

Legitimate encryption, compression, backup, or file-processing software that creates files using an `.encrypted` extension.

### Detection

```kql
FileCreationEvents
| where filename endswith ".encrypted"
| summarize EncryptedFiles = count() by hostname
| where EncryptedFiles >= 10
