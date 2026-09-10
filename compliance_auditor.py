# Fichier : compliance_auditor.py
# Description : Automated Infrastructure Compliance & Hardening Auditor

import json
import logging
from typing import Dict, List

# Configuration du logging
logging.basicConfig(level=logging.INFO, format="%(message)s")

class SecurityRule:
    def __init__(self, rule_id: str, description: str, severity: str, framework: str):
        self.rule_id = rule_id
        self.description = description
        self.severity = severity
        self.framework = framework

class CloudComplianceAuditor:
    def __init__(self):
        self.findings = []
        self.total_resources = 0
        self.failed_checks = 0

    def load_infrastructure_config(self, filepath: str) -> Dict:
        """Loads a simulated cloud infrastructure configuration (JSON/IaC state)."""
        with open(filepath, 'r') as file:
            return json.load(file)

    def check_iam_mfa(self, users: List[Dict]):
        """Check if Multi-Factor Authentication (MFA) is enabled for all IAM users."""
        rule = SecurityRule("IAM-001", "Ensure MFA is enabled for all IAM users", "CRITICAL", "CIS / PCI DSS 8.3")
        for user in users:
            self.total_resources += 1
            if not user.get("mfa_active", False):
                self._record_finding(rule, f"User '{user.get('username')}' does not have MFA enabled.")

    def check_security_groups_ssh(self, security_groups: List[Dict]):
        """Check if SSH (Port 22) is open to the world (0.0.0.0/0)."""
        rule = SecurityRule("NET-001", "Ensure SSH is not open to the world", "CRITICAL", "CIS / PCI DSS 1.2.1")
        for sg in security_groups:
            self.total_resources += 1
            for rule_ingress in sg.get("ingress_rules", []):
                if rule_ingress.get("port") == 22 and rule_ingress.get("cidr") == "0.0.0.0/0":
                    self._record_finding(rule, f"Security Group '{sg.get('group_name')}' allows unrestricted SSH access.")

    def check_storage_encryption(self, buckets: List[Dict]):
        """Check if cloud storage buckets have encryption at rest enabled."""
        rule = SecurityRule("STO-001", "Ensure storage buckets are encrypted at rest", "HIGH", "PCI DSS 3.4")
        for bucket in buckets:
            self.total_resources += 1
            if not bucket.get("encryption_enabled", False):
                self._record_finding(rule, f"Storage bucket '{bucket.get('bucket_name')}' is unencrypted.")

    def _record_finding(self, rule: SecurityRule, detail: str):
        self.failed_checks += 1
        self.findings.append({
            "Rule ID": rule.rule_id,
            "Framework": rule.framework,
            "Severity": rule.severity,
            "Description": rule.description,
            "Detail": detail
        })

    def run_audit(self, config_file: str):
        logging.info(f"--- Starting Automated Compliance Audit for: {config_file} ---\n")
        config_data = self.load_infrastructure_config(config_file)
        
        # Run checks
        self.check_iam_mfa(config_data.get("iam_users", []))
        self.check_security_groups_ssh(config_data.get("security_groups", []))
        self.check_storage_encryption(config_data.get("storage_buckets", []))
        
        self.generate_report()

    def generate_report(self):
        """Generates a clean, readable audit report."""
        compliance_score = ((self.total_resources - self.failed_checks) / self.total_resources) * 100 if self.total_resources > 0 else 100
        
        logging.info("================ AUDIT REPORT ================")
        logging.info(f"Total Resources Scanned : {self.total_resources}")
        logging.info(f"Security Violations     : {self.failed_checks}")
        logging.info(f"Compliance Score        : {compliance_score:.2f}%\n")
        
        if self.failed_checks > 0:
            logging.info("--- CRITICAL & HIGH FINDINGS ---")
            for finding in self.findings:
                logging.info(f"[{finding['Severity']}] {finding['Rule ID']} ({finding['Framework']})")
                logging.info(f"    Issue:  {finding['Detail']}")
                logging.info(f"    Fix:    {finding['Description']}\n")
        else:
            logging.info("✅ Infrastructure is fully compliant with baseline policies.")
        logging.info("==============================================")

if __name__ == "__main__":
    auditor = CloudComplianceAuditor()
    auditor.run_audit("cloud_config.json")
