# remediation/handlers/sg_remediator.py

import os
import logging
import boto3
from botocore.exceptions import ClientError
from notifier import IncidentNotifier

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SecurityGroupRemediator")


def log_audit_record(group_id, user_arn, event_time, action):
    """Writes an immutable audit record to DynamoDB for compliance tracking."""
    localstack_host = os.environ.get("LOCALSTACK_HOSTNAME", "localhost")
    endpoint_url = f"http://{localstack_host}:4566" if os.environ.get("USE_LOCALSTACK") == "true" else None

    dynamodb = boto3.resource('dynamodb', endpoint_url=endpoint_url)
    table = dynamodb.Table('CloudSentinelAuditTrail')

    try:
        table.put_item(
            Item={
                'IncidentId': f"INC-{group_id}-{int(os.urandom(2).hex(), 16)}",
                'Timestamp': event_time,
                'ResourceId': group_id,
                'UserARN': user_arn,
                'ActionTaken': action,
                'Status': 'AUTO_REMEDIATED'
            }
        )
        logger.info("✅ Audit record persisted to DynamoDB table 'CloudSentinelAuditTrail'.")
    except Exception as e:
        logger.warning(f"[-] Could not persist audit log to DynamoDB: {e}")


def lambda_handler(event, context):
    """
    AWS Lambda entrypoint triggered by EventBridge on AuthorizeSecurityGroupIngress events.
    Parses event telemetry, checks for 0.0.0.0/0 on Port 22, revokes rule via boto3,
    dispatches notification alerts, and records an audit log to DynamoDB.
    """
    logger.info("Received CloudTrail Audit Event payload via EventBridge.")

    # LocalStack / AWS SDK endpoint override for local environment testing
    localstack_host = os.environ.get("LOCALSTACK_HOSTNAME", "localhost")
    endpoint_url = f"http://{localstack_host}:4566" if os.environ.get("USE_LOCALSTACK") == "true" else None

    ec2_client = boto3.client('ec2', endpoint_url=endpoint_url)

    # Extract details from CloudTrail JSON structure
    detail = event.get("detail", {})
    event_name = detail.get("eventName")
    request_params = detail.get("requestParameters", {})
    group_id = request_params.get("groupId")
    user_arn = detail.get("userIdentity", {}).get("arn", "Unknown")
    event_time = detail.get("eventTime", "N/A")

    if event_name != "AuthorizeSecurityGroupIngress" or not group_id:
        logger.info("Event does not contain AuthorizeSecurityGroupIngress parameters. Skipping.")
        return {"statusCode": 200, "body": "Ignored non-matching event."}

    # Inspect IP permission items inside requestParameters
    ip_permissions = request_params.get("ipPermissions", {}).get("items", [])

    remediated = False
    for item in ip_permissions:
        from_port = item.get("fromPort")
        to_port = item.get("toPort")
        ip_ranges = item.get("ipRanges", {}).get("items", [])

        # Check if Port 22 is exposed to 0.0.0.0/0
        for ip_range in ip_ranges:
            cidr_ip = ip_range.get("cidrIp")
            if cidr_ip == "0.0.0.0/0" and (from_port == 22 or to_port == 22):
                logger.warning(f"🚨 CRITICAL: Insecure SSH rule detected on Security Group {group_id}!")

                # Execute Boto3 SDK call to revoke rule
                try:
                    ec2_client.revoke_security_group_ingress(
                        GroupId=group_id,
                        IpPermissions=[{
                            'IpProtocol': 'tcp',
                            'FromPort': 22,
                            'ToPort': 22,
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                        }]
                    )
                    logger.info(f"✅ SUCCESS: Revoked 0.0.0.0/0 Port 22 ingress rule from {group_id}.")
                    remediated = True

                    # 1. Log audit record to DynamoDB
                    log_audit_record(
                        group_id=group_id,
                        user_arn=user_arn,
                        event_time=event_time,
                        action="REVOKED_OPEN_SSH_RULE"
                    )

                    # 2. Dispatch alert via Notifier
                    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
                    notifier = IncidentNotifier(webhook_url=webhook_url)
                    notifier.send_alert(
                        title=f"Unauthorized SSH Exposure Auto-Remediated on {group_id}",
                        severity="CRITICAL",
                        details={
                            "action": "REVOKED_OPEN_SSH_RULE",
                            "resource_id": group_id,
                            "user_arn": user_arn,
                            "rule_id": "CS-RT-001",
                            "timestamp": event_time
                        }
                    )
                except ClientError as e:
                    logger.error(f"[-] Boto3 SDK Error revoking rule: {e}")
                    return {"statusCode": 500, "body": str(e)}

    return {
        "statusCode": 200,
        "body": "Remediation complete." if remediated else "No violation found in payload."
    }