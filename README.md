# Detection Engineering

A collection of security detections developed using KQL and Sigma, mapped to the MITRE ATT&CK framework.

This repository focuses on translating attacker behavior into practical detection logic, starting with KQL and progressing toward vendor-neutral Sigma rules.

## Repository Structure

```text
.
├── kql/
│   ├── T1105-ingress-tool-transfer-curl.kql
│   ├── T1486-data-encrypted-for-impact.kql
|   └── T1071.001-suspicious-web-c2-pattern.md
│
├── sigma/
│   └── ...
│
└── README.md
