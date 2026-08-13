# Detection Engineering

A collection of security detections developed using KQL and Sigma, mapped to the MITRE ATT&CK framework.

This repository focuses on translating attacker behavior into practical detection logic, starting with KQL and progressing toward vendor-neutral Sigma rules.

## Repository Structure

```text
.
├── kql/
|   ├── T1021.002-persistent-network-share-connection.md
|   ├── T1071.001-suspicious-web-c2-pattern.md
|   ├── T1071.004-dns-c2-beaconing.md
│   ├── T1071.001-suspicious-web-c2-pattern.md
│   ├── T1105-ingress-tool-transfer-curl.md
│   ├── T1105-suspicious-host-to-email-activity.md
│   ├── T1486-data-encrypted-for-impact.md
|   └── T1566.002-suspicious-phishing-link.md
│
├── sigma/
│   └── ...
│
└── README.md
