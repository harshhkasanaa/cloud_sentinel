# scanner/main.py

import os
import sys
import argparse
import hcl2
from report import SarifReportGenerator


class CloudSentinelScanner:
    def __init__(self, target_dir):
        self.target_dir = target_dir
        self.violations = []

    def load_tf_files(self):
        """Find and parse all .tf files in target directory into AST dicts."""
        parsed_files = {}
        for root, _, files in os.walk(self.target_dir):
            for file in files:
                if file.endswith(".tf"):
                    full_path = os.path.join(root, file)
                    with open(full_path, "r", encoding="utf-8") as f:
                        try:
                            parsed_files[full_path] = hcl2.load(f)
                        except Exception as e:
                            print(f"[-] Error parsing HCL file {full_path}: {e}")
        return parsed_files

    def evaluate_rules(self, parsed_files):
        """Evaluate AST tree against defined security rules."""
        for file_path, ast_data in parsed_files.items():
            resources = ast_data.get("resource", [])
            
            for resource_block in resources:
                for resource_type, resource_config in resource_block.items():
                    for resource_name, details in resource_config.items():
                        
                        # Rule 1: Security Group 0.0.0.0/0 Ingress on Sensitive Ports
                        if resource_type == "aws_security_group":
                            self._check_security_group_ingress(file_path, resource_name, details)
                        
                        # Rule 2: Unencrypted / Unprotected S3 Buckets
                        elif resource_type == "aws_s3_bucket":
                            self._check_s3_bucket(file_path, resource_name, details)

    def _check_security_group_ingress(self, file_path, resource_name, details):
        ingress_rules = details.get("ingress", [])
        for rule in ingress_rules:
            cidr_blocks = rule.get("cidr_blocks", [])
            from_port = rule.get("from_port")
            
            for cidr in cidr_blocks:
                if "0.0.0.0/0" in cidr and from_port in [22, 3389, "22", "3389"]:
                    self.violations.append({
                        "file": file_path,
                        "resource": f"aws_security_group.{resource_name}",
                        "severity": "CRITICAL",
                        "rule_id": "CS-SG-001",
                        "message": f"Security Group exposes sensitive port ({from_port}) to the public internet (0.0.0.0/0)."
                    })

    def _check_s3_bucket(self, file_path, resource_name, details):
        self.violations.append({
            "file": file_path,
            "resource": f"aws_s3_bucket.{resource_name}",
            "severity": "HIGH",
            "rule_id": "CS-S3-001",
            "message": "S3 Bucket created without explicit server-side encryption or Public Access Block enabled."
        })

    def print_report(self):
        """Display terminal audit report."""
        print("\n" + "="*70)
        print("          🛡️  CLOUD SENTINEL PRE-DEPLOYMENT SECURITY REPORT  🛡️          ")
        print("="*70 + "\n")
        
        if not self.violations:
            print("✅ PASS: No security violations found in IaC templates.\n")
            return 0

        print(f"❌ FAIL: Found {len(self.violations)} security violation(s) in target infrastructure:\n")
        
        for idx, v in enumerate(self.violations, 1):
            print(f"[{idx}] {v['severity']} - {v['rule_id']}")
            print(f"    Resource : {v['resource']}")
            print(f"    File     : {v['file']}")
            print(f"    Message  : {v['message']}\n")
            
        print("="*70)
        print("Action Required: Fix the violations above or CI/CD deployment will remain blocked.")
        print("="*70 + "\n")
        
        return 1


def main():
    parser = argparse.ArgumentParser(description="Cloud Sentinel IaC Static Security Scanner")
    parser.add_argument("--dir", default="iac/vulnerable", help="Directory containing Terraform files to scan")
    parser.add_argument("--sarif", default="report.sarif", help="Path to output SARIF report JSON file")
    args = parser.parse_args()

    scanner = CloudSentinelScanner(args.dir)
    parsed_files = scanner.load_tf_files()
    scanner.evaluate_rules(parsed_files)
    
    # Generate SARIF Report
    sarif_gen = SarifReportGenerator()
    sarif_gen.generate(scanner.violations, output_file=args.sarif)

    exit_code = scanner.print_report()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()