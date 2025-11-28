"""Lambda handler for AWS alerting system."""

import json
import logging
import os
from datetime import datetime
import zoneinfo
import urllib3
import boto3  # pylint: disable=import-error

# Configure logging
logger = logging.getLogger()
logger.setLevel(os.getenv('LOG_LEVEL', 'INFO'))

# Cache for container reuse
SSM = None
NTFY_TOKEN = None

def get_ntfy_token():
    """Get ntfy token from Parameter Store, cached for container reuse."""
    global SSM, NTFY_TOKEN  # pylint: disable=global-statement
    if SSM is None:
        SSM = boto3.client('ssm')
    if NTFY_TOKEN is None:
        parameter_name = os.environ.get('NTFY_TOKEN_PARAMETER', '/alerting/ntfy-token')
        response = SSM.get_parameter(Name=parameter_name, WithDecryption=True)
        NTFY_TOKEN = response['Parameter']['Value']
    return NTFY_TOKEN


def lambda_handler(event, _context):  # pylint: disable=too-many-locals
    """Handle incoming SNS events and forward to notification channels."""
    http = urllib3.PoolManager()

    for record in event['Records']:
        sns_message = record['Sns']['Message']

        try:
            event_data = json.loads(sns_message)

            # Extract basic info
            source = event_data.get('source', 'Unknown')
            detail_type = event_data.get('detail-type', 'Unknown Event')
            detail = event_data.get('detail', {})

            # Build generic message
            service = source.replace('aws.', '').upper() if source.startswith('aws.') else source

            # Format notification with title + minimal body
            title = f"{service}: {detail_type}"
            if 'state' in detail:
                title += f" ({detail['state']})"

            # Convert time to Europe/Amsterdam timezone
            event_time = event_data.get('time', 'Unknown')
            if event_time != 'Unknown':
                utc_time = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
                amsterdam_time = utc_time.astimezone(zoneinfo.ZoneInfo('Europe/Amsterdam'))
                formatted_date = amsterdam_time.strftime('%d-%m-%Y')
                formatted_time = amsterdam_time.strftime('%H:%M:%S')
            else:
                formatted_date = 'Unknown'
                formatted_time = 'Unknown'

            message = f"Date: {formatted_date}\nTime: {formatted_time}\nSource: {source}"

            # Add optional details if available
            if 'state' in detail:
                message += f"\nState: {detail['state']}"
            if 'alarm-name' in detail:
                message += f"\nAlarm: {detail['alarm-name']}"
            if 'reason' in detail:
                message += f"\nReason: {detail['reason']}"

            print(f"Alert message: {message}")

            # Get ntfy token for notifications
            token = get_ntfy_token()
            print(f"Using ntfy token: {token[:8]}...")

            # Send to ntfy
            ntfy_url = os.environ.get('NTFY_URL', 'https://ntfy.sh/alerts')
            headers = {
                'Authorization': f'Bearer {token}',
                'Title': title,
                'Priority': '3',
                'Tags': 'alert'
            }

            response = http.request('POST', ntfy_url, body=message.encode('utf-8'), headers=headers)
            print(f"Ntfy response: {response.status} - {response.data.decode('utf-8')}")

            if response.status != 200:
                error_msg = f"Failed to send notification: {response.status}"
                print(error_msg)
                raise RuntimeError(error_msg)

            print("Notification sent successfully")

        except Exception as exc:
            print(f"Error processing alert: {exc}")
            raise

    return {
        'statusCode': 200,
        'body': json.dumps('Alerts processed successfully')
    }
