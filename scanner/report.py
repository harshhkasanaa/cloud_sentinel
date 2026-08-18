# scanner/report.py

import json
import os


class SarifReportGenerator:
    """Generates SARIF v2.1.0 compliant JSON reports for GitHub Code Scanning integration."""

    def __init__(self, tool_name="CloudSentinel", tool_version="1.0.0"):
        self.tool_name = tool_name
        self.tool_version = tool_version

    def generate(self, violations, output_file="report.sarif"):
        """Converts Cloud Sentinel internal violation dicts into SARIF format."""
        
        # Define SARIF v2.1.0 Schema Structure
        sarif_structure = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "informationUri": "https://github.com/cloud-sentinel/guardrail",
                            "rules": self._extract_rule_definitions(violations)
                        }
                    },
                    "results": self._format_results(violations)
                }
            ]
        }

        # Write SARIF JSON to disk
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(sarif_structure, f, indent=2)

        print(f"📄 SARIF Security Report generated successfully: {output_file}")
        return output_file

    def _extract_rule_definitions(self, violations):
        """Extract unique security rules metadata for SARIF driver rules section."""
        rules = {}
        for v in violations:
            rule_id = v["rule_id"]
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": rule_id.replace("-", ""),
                    "shortDescription": {
                        "text": f"Cloud Sentinel Rule {rule_id}"
                    },
                    "fullDescription": {
                        "text": v["message"]
                    },
                    "defaultConfiguration": {
                        "level": self._map_severity_to_sarif_level(v["severity"])
                    }
                }
        return list(rules.values())

    def _format_results(self, violations):
        """Map individual findings into SARIF result objects."""
        results = []
        for v in violations:
            # Normalize path for SARIF URI compatibility
            relative_path = os.path.relpath(v["file"]).replace("\\", "/")
            
            results.append({
                "ruleId": v["rule_id"],
                "level": self._map_severity_to_sarif_level(v["severity"]),
                "message": {
                    "text": f"[{v['severity']}] {v['resource']} - {v['message']}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": relative_path
                            },
                            "region": {
                                "startLine": 1,
                                "startColumn": 1
                            }
                        }
                    }
                ]
            })
        return results

    @staticmethod
    def _map_severity_to_sarif_level(severity):
        """Maps internal severity levels (CRITICAL, HIGH, MEDIUM) to SARIF levels."""
        mapping = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note"
        }
        return mapping.get(severity.upper(), "warning")