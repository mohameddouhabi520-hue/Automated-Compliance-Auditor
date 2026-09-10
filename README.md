# Automated Cloud Compliance & Hardening Auditor

![Python Version](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Security](https://img.shields.io/badge/Compliance-PCI__DSS%20%7C%20CIS-blue.svg)
![Build](https://img.shields.io/badge/Status-Operational-brightgreen.svg)

## 📌 Overview
This project is an automated **Cloud Security Posture Management (CSPM)** tool. It is designed to bridge the gap between traditional security auditing and modern Infrastructure-as-Code (IaC) environments. 

Instead of manually reviewing configurations in spreadsheets, this Python engine programmatically parses cloud infrastructure configurations (JSON) and validates them against strict security frameworks such as **PCI DSS v4.0** and **CIS Benchmarks**.

## 🚀 Core Features
- **IAM Hardening Checks:** Automatically flags users operating without Multi-Factor Authentication (MFA) enabled.
- **Network Security Auditing:** Parses Security Group rules to detect critically exposed ports (e.g., SSH port 22 open to `0.0.0.0/0`).
- **Data Protection Validation:** Verifies that all storage buckets have encryption-at-rest enabled to prevent data breaches.
- **Dynamic Scoring:** Generates a real-time compliance score and a categorized incident report (Critical, High, Medium) for fast remediation.

## 💻 How to Run
1. Clone this repository.
2. Ensure you have Python 3 installed.
3. Run the auditor against the sample configuration file:
   
```bash
   python compliance_auditor.py
🔍 Expected Output
The script generates a clean, SOC-ready audit report in the terminal:

--- Starting Automated Compliance Audit for: cloud_config.json ---

================ AUDIT REPORT ================
Total Resources Scanned : 6
Security Violations     : 3
Compliance Score        : 50.00%

--- CRITICAL & HIGH FINDINGS ---
[CRITICAL] IAM-001 (CIS / PCI DSS 8.3)
    Issue:  User 'service_account_dev' does not have MFA enabled.
    Fix:    Ensure MFA is enabled for all IAM users

[CRITICAL] NET-001 (CIS / PCI DSS 1.2.1)
    Issue:  Security Group 'web-tier-sg' allows unrestricted SSH access.
    Fix:    Ensure SSH is not open to the world

[HIGH] STO-001 (PCI DSS 3.4)
    Issue:  Storage bucket 'customer-data-backup-legacy' is unencrypted.
    Fix:    Ensure storage buckets are encrypted at rest
==============================================
