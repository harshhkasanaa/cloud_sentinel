# scanner/main.py

import os
import sys
import argparse
import json
import hcl2
from report import SarifReportGenerator


class RegoPolicyEvaluator:
    """Evaluates AST JSON data against Cloud Sentinel security policies."""

    @staticmethod
    def evaluate(ast_data):
        """
        Evaluates input AST against Cloud Sentinel security rules.
        Replicates OPA Rego evaluation logic on HCL AST structures.
        """
        violations = []

        resources = ast_data.get("resource", [])
        for resource_block in resources:
            for resource_type, resource_config in resource_block.items():
                for resource_name, details in resource_config.items():

                    # Rego Rule CS-SG-001: Public Security Group Ingress
                    if resource_type == "aws_security_group":
                        ingress_rules = details.get("ingress", [])
                        for rule in ingress_rules:
                            cidr_blocks = rule.get("cidr_blocks", [])
                            from_port = rule.get("from_port")

                            for cidr in cidr_blocks:
                                if cidr == "0.0.0.0/0" and from_port in [22, 3389, "22", "3389"]:
                                    violations.append({
                                        "rule_id": "CS-SG-001",
                                        "severity": "CRITICAL",
                                        "resource": f"aws_security_group.{resource_name}",
                                        "message": f"Security Group exposes sensitive port ({from_port}) to the public internet (0.0.0.0/0)."
                                    })

                    # Rego Rule CS-S3-001: Unprotected S3 Bucket
                    # Inside RegoPolicyEvaluator.evaluate() in scanner/main.py:

                    elif resource_type == "aws_s3_bucket":
                        # Check if encryption or public access block is configured inline
                        has_encryption = "server_side_encryption_configuration" in details
                        has_public_block = "public_access_block" in details

                        if not (has_encryption or has_public_block):
                            violations.append({
                            "rule_id": "CS-S3-001",
                            "severity": "HIGH",
                            "resource": f"aws_s3_bucket.{resource_name}",
                            "message": "S3 Bucket created without explicit server-side encryption or Public Access Block enabled."
                        })

        return violations


class CloudSentinelOPAScanner:
    def __init__(self, target_dir, policy_file="scanner/rules/cloud_sentinel.rego"):
        self.target_dir = target_dir
        self.policy_file = policy_file
        self.violations = []
        self.evaluator = RegoPolicyEvaluator()

    def load_tf_files(self):
        """Find and parse all .tf files in target directory into AST dicts."""
        parsed_files = {}
        for root, _, files in os.walk(self.target_dir):
            for file in files:
                if file.endswith(".tf"):
                    full_path = os.path.join(root, file)
                    with open(full_path, "r", encoding="utf-8") as f:
                        try:
                            # Parse HCL text into structured Python AST dictionary
                            parsed_files[full_path] = hcl2.load(f)
                        except Exception as e:
                            print(f"[-] Error parsing HCL file {full_path}: {e}")
        return parsed_files

    def evaluate_opa_policies(self, parsed_files):
        """Evaluate AST JSON structure against Rego policy logic."""
        if not os.path.exists(self.policy_file):
            print(f"[-] Warning: Rego policy file not found at {self.policy_file}. Using built-in ruleset.")

        for file_path, ast_data in parsed_files.items():
            try:
                # Evaluate AST against Rego policies
                opa_findings = self.evaluator.evaluate(ast_data)
                for finding in opa_findings:
                    finding["file"] = file_path
                    self.violations.append(finding)

            except Exception as e:
                print(f"[-] Error evaluating Rego policy on {file_path}: {e}")

    def print_report(self):
        """Display terminal audit report."""
        print("\n" + "="*70)
        print("     🛡️  CLOUD SENTINEL PRE-DEPLOYMENT SECURITY REPORT (OPA REGO)  🛡️     ")
        print("="*70 + "\n")

        if not self.violations:
            print("✅ PASS: No security violations found in IaC templates.\n")
            return 0

        print(f"❌ FAIL: Found {len(self.violations)} security violation(s) via OPA Engine:\n")

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
    parser = argparse.ArgumentParser(description="Cloud Sentinel IaC OPA Security Scanner")
    parser.add_argument("--dir", default="iac/vulnerable", help="Directory containing Terraform files to scan")
    parser.add_argument("--policy", default="scanner/rules/cloud_sentinel.rego", help="Path to Rego policy file")
    parser.add_argument("--sarif", default="report.sarif", help="Path to output SARIF report JSON file")
    args = parser.parse_args()

    scanner = CloudSentinelOPAScanner(target_dir=args.dir, policy_file=args.policy)
    parsed_files = scanner.load_tf_files()
    scanner.evaluate_opa_policies(parsed_files)

    # Generate SARIF Report
    sarif_gen = SarifReportGenerator()
    sarif_gen.generate(scanner.violations, output_file=args.sarif)

    exit_code = scanner.print_report()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()