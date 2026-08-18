package cloud_sentinel.iac

default allow = false

# Rule 1: Security Group exposes sensitive ports (22, 3389) to 0.0.0.0/0
violations[v] {
    some resource_type, resource_block in input.resource
    resource_type == "aws_security_group"
    some resource_name, details in resource_block
    some rule in details.ingress
    some cidr in rule.cidr_blocks
    cidr == "0.0.0.0/0"
    
    port := rule.from_port
    sensitive_ports := [22, 3389, "22", "3389"]
    port == sensitive_ports[_]

    v := {
        "rule_id": "CS-SG-001",
        "severity": "CRITICAL",
        "resource": sprintf("aws_security_group.%s", [resource_name]),
        "message": sprintf("Security Group exposes sensitive port (%v) to the public internet (0.0.0.0/0).", [port])
    }
}

# Rule 2: S3 Bucket created without encryption or explicit public blocks
violations[v] {
    some resource_type, resource_block in input.resource
    resource_type == "aws_s3_bucket"
    some resource_name, details in resource_block

    v := {
        "rule_id": "CS-S3-001",
        "severity": "HIGH",
        "resource": sprintf("aws_s3_bucket.%s", [resource_name]),
        "message": "S3 Bucket created without explicit server-side encryption or Public Access Block enabled."
    }
}