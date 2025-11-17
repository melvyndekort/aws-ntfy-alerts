"""Lambda handler for AWS alerting system."""

import json
import os
import urllib3
import boto3

# Cache for container reuse
ssm = None
ntfy_token = None

def get_ntfy_token():
    """Get ntfy token from Parameter Store, cached for container reuse."""
    global ssm, ntfy_token
    if ssm is None:
        ssm = boto3.client('ssm')
    if ntfy_token is None:
        parameter_name = os.environ.get('NTFY_TOKEN_PARAMETER', '/alerting/ntfy-token')
        response = ssm.get_parameter(Name=parameter_name, WithDecryption=True)
        ntfy_token = response['Parameter']['Value']
    return ntfy_token


def lambda_handler(event, context):
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
            region = event_data.get('region', 'Unknown')
            
            # Build generic message
            service = source.replace('aws.', '').upper() if source.startswith('aws.') else source
            
            # Format notification message
            message = f"🚨 **{service} Alert**\n"
            message += f"**Event:** {detail_type}\n"
            message += f"**Region:** {region}\n"
            
            # Add key details in readable format (limit message size)
            if detail:
                important_keys = ['state', 'instance-id', 'status', 'error', 'message', 'reason']
                for key, value in detail.items():
                    if len(message) > 800:  # Prevent overly long messages
                        message += "...(truncated)\n"
                        break
                    
                    if isinstance(value, (dict, list)):
                        if key.lower() in important_keys or len(str(value)) < 100:
                            message += f"**{key}:** {json.dumps(value)}\n"
                        else:
                            message += f"**{key}:** [complex object]\n"
                    else:
                        message += f"**{key}:** {value}\n"
            
            print(f"Alert message: {message}")
            
            # Get ntfy token for notifications
            token = get_ntfy_token()
            print(f"Using ntfy token: {token[:8]}...")
            
            # Send to ntfy
            ntfy_url = os.environ.get('NTFY_URL', 'https://ntfy.sh/alerts')
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'text/plain'
            }
            
            response = http.request('POST', ntfy_url, body=message.encode('utf-8'), headers=headers)
            print(f"Ntfy response: {response.status} - {response.data.decode('utf-8')}")
            
            if response.status != 200:
                error_msg = f"Failed to send notification: {response.status}"
                print(error_msg)
                raise Exception(error_msg)
            else:
                print("Notification sent successfully")
            
        except Exception as e:
            print(f"Error processing alert: {e}")
            raise
    
    return {
        'statusCode': 200,
        'body': json.dumps('Alerts processed successfully')
    }
