# tests/test_remediator.py

import json
import os
import sys

# Add remediation directory to Python import path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../remediation/handlers")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../remediation")))

from sg_remediator import lambda_handler


def test_sg_remediation_handler(mocker):
    """Test that lambda_handler parses CloudTrail JSON payload and revokes rule via boto3 mock."""
    
    # Mock boto3 ec2 client to verify SDK call without modifying real infrastructure
    mock_ec2 = mocker.patch("boto3.client")
    mock_client_instance = mock_ec2.return_value

    # Load mock CloudTrail event
    event_path = os.path.join(os.path.dirname(__file__), "mock_event.json")
    with open(event_path, "r", encoding="utf-8") as f:
        mock_event = json.load(f)

    # Execute Lambda Handler
    response = lambda_handler(mock_event, None)

    # Assertions
    assert response["statusCode"] == 200
    # Verify boto3 SDK method 'revoke_security_group_ingress' was called with exact group ID
    mock_client_instance.revoke_security_group_ingress.assert_called_once_with(
        GroupId="sg-mock12345",
        IpPermissions=[{
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
        }]
    )
    print("\n✅ PASS: Remediation handler correctly identified 0.0.0.0/0 exposure and executed Boto3 revocation!")