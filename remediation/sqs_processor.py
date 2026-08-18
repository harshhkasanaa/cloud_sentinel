# remediation/sqs_processor.py

import json
import logging
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "handlers")))
from sg_remediator import lambda_handler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SQSBatchProcessor")


class SQSQueueProcessor:
    """Processes batched audit telemetry events from Amazon SQS queues."""

    def __init__(self):
        self.processed_count = 0
        self.remediated_count = 0

    def process_queue_message(self, sqs_message):
        """Extracts CloudTrail JSON payload embedded inside SQS body."""
        try:
            body = sqs_message.get("Body", "{}")
            if isinstance(body, str):
                event_payload = json.loads(body)
            else:
                event_payload = body

            logger.info(f"Processing SQS message ID: {sqs_message.get('MessageId', 'local-id')}")
            
            # Route unmarshaled event to Lambda remediation handler
            result = lambda_handler(event_payload, None)
            
            self.processed_count += 1
            if result.get("statusCode") == 200 and "Remediation complete" in result.get("body", ""):
                self.remediated_count += 1

            return result

        except Exception as e:
            logger.error(f"[-] Failed to parse SQS queue message: {e}")
            raise e