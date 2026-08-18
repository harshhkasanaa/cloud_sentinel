# tests/test_sqs_processor.py

import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../remediation")))
from sqs_processor import SQSQueueProcessor


def test_sqs_queue_batch_processing(mocker):
    """Test that SQSQueueProcessor consumes SQS payload and triggers Boto3 revocation."""
    
    # Mock boto3 ec2 client
    mock_ec2 = mocker.patch("boto3.client")
    mock_client_instance = mock_ec2.return_value

    # Load SQS message
    sqs_event_path = os.path.join(os.path.dirname(__file__), "mock_sqs_event.json")
    with open(sqs_event_path, "r", encoding="utf-8") as f:
        sqs_message = json.load(f)

    processor = SQSQueueProcessor()
    result = processor.process_queue_message(sqs_message)

    # Assertions
    assert result["statusCode"] == 200
    mock_client_instance.revoke_security_group_ingress.assert_called_once_with(
        GroupId="sg-sqs-test555",
        IpPermissions=[{
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
        }]
    )
    print("\n✅ PASS: SQS Queue message consumed, unmarshaled, and successfully remediated via Boto3!")