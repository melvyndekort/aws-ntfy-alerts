"""Tests for alerting handler."""

import json
import os
import pytest
from moto import mock_aws
import boto3
from unittest.mock import patch, MagicMock
from aws_ntfy_alerts.handler import lambda_handler


@mock_aws
@patch('aws_ntfy_alerts.handler.urllib3.PoolManager')
@patch('aws_ntfy_alerts.handler.SSM')
def test_lambda_handler_success(mock_ssm, mock_pool):
    """Test successful processing of SNS event with HTTP request."""
    # Mock SSM response
    mock_ssm.get_parameter.return_value = {
        'Parameter': {'Value': 'test-token-123'}
    }
    
    # Mock HTTP response
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.data.decode.return_value = '{"id":"test123"}'
    mock_pool.return_value.request.return_value = mock_response
    
    os.environ['NTFY_TOKEN_PARAMETER'] = '/alerting/ntfy-token'
    os.environ['NTFY_URL'] = 'https://ntfy.test/aws'
    
    event = {
        'Records': [
            {
                'Sns': {
                    'Message': json.dumps({
                        'source': 'aws.ec2',
                        'detail-type': 'EC2 Instance State-change Notification',
                        'detail': {
                            'state': 'stopped',
                            'instance-id': 'i-1234567890abcdef0'
                        },
                        'region': 'eu-west-1',
                        'time': '2025-11-26T21:30:00Z'
                    })
                }
            }
        ]
    }
    
    response = lambda_handler(event, {})
    
    assert response['statusCode'] == 200
    assert 'Alerts processed successfully' in response['body']
    
    # Verify HTTP request was made
    mock_pool.return_value.request.assert_called_once()
    call_args = mock_pool.return_value.request.call_args
    assert call_args[0][0] == 'POST'
    assert call_args[0][1] == 'https://ntfy.test/aws'
    assert 'Authorization' in call_args[1]['headers']
    assert call_args[1]['headers']['Authorization'] == 'Bearer test-token-123'


@mock_aws
@patch('aws_ntfy_alerts.handler.urllib3.PoolManager')
@patch('aws_ntfy_alerts.handler.SSM')
def test_lambda_handler_http_error(mock_ssm, mock_pool):
    """Test handling of HTTP error response."""
    mock_ssm.get_parameter.return_value = {
        'Parameter': {'Value': 'test-token-123'}
    }
    
    # Mock HTTP error response
    mock_response = MagicMock()
    mock_response.status = 401
    mock_response.data.decode.return_value = 'Unauthorized'
    mock_pool.return_value.request.return_value = mock_response
    
    os.environ['NTFY_TOKEN_PARAMETER'] = '/alerting/ntfy-token'
    
    event = {
        'Records': [
            {
                'Sns': {
                    'Message': json.dumps({
                        'source': 'aws.lambda',
                        'detail-type': 'Lambda Function Error',
                        'region': 'us-east-1',
                        'time': '2025-11-26T21:30:00Z'
                    })
                }
            }
        ]
    }
    
    with pytest.raises(RuntimeError, match="Failed to send notification: 401"):
        lambda_handler(event, {})
    
    mock_pool.return_value.request.assert_called_once()


def test_lambda_handler_invalid_json():
    """Test handling of invalid JSON in SNS message."""
    event = {
        'Records': [
            {
                'Sns': {
                    'Message': 'invalid json'
                }
            }
        ]
    }
    
    with pytest.raises(Exception):
        lambda_handler(event, {})


def test_lambda_handler_empty_records():
    """Test handling of empty records."""
    event = {'Records': []}
    
    response = lambda_handler(event, {})
    
    assert response['statusCode'] == 200
    assert 'Alerts processed successfully' in response['body']


@mock_aws
@patch('aws_ntfy_alerts.handler.urllib3.PoolManager')
@patch('aws_ntfy_alerts.handler.SSM')
def test_multiple_records(mock_ssm, mock_pool):
    """Test processing multiple SNS records."""
    mock_ssm.get_parameter.return_value = {
        'Parameter': {'Value': 'test-token-123'}
    }
    
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.data.decode.return_value = '{"id":"test123"}'
    mock_pool.return_value.request.return_value = mock_response
    
    os.environ['NTFY_TOKEN_PARAMETER'] = '/alerting/ntfy-token'
    
    event = {
        'Records': [
            {
                'Sns': {
                    'Message': json.dumps({
                        'source': 'aws.ec2',
                        'detail-type': 'EC2 Alert',
                        'region': 'us-east-1',
                        'time': '2025-11-26T21:30:00Z'
                    })
                }
            },
            {
                'Sns': {
                    'Message': json.dumps({
                        'source': 'aws.rds',
                        'detail-type': 'RDS Alert',
                        'region': 'us-west-2',
                        'time': '2025-11-26T21:30:00Z'
                    })
                }
            }
        ]
    }
    
    response = lambda_handler(event, {})
    
@mock_aws
@patch('aws_ntfy_alerts.handler.urllib3.PoolManager')
@patch('aws_ntfy_alerts.handler.SSM')
def test_missing_time_and_optional_fields(mock_ssm, mock_pool):
    """Test handling of missing time and optional detail fields."""
    mock_ssm.get_parameter.return_value = {
        'Parameter': {'Value': 'test-token-123'}
    }
    
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.data.decode.return_value = '{"id":"test123"}'
    mock_pool.return_value.request.return_value = mock_response
    
    os.environ['NTFY_TOKEN_PARAMETER'] = '/alerting/ntfy-token'
    
    event = {
        'Records': [
            {
                'Sns': {
                    'Message': json.dumps({
                        'source': 'aws.cloudwatch',
                        'detail-type': 'CloudWatch Alarm State Change',
                        'detail': {
                            'alarm-name': 'HighCPUUtilization',
                            'reason': 'Threshold Crossed: 1 out of the last 1 datapoints'
                        }
                        # Missing 'time' field
                    })
                }
            }
        ]
    }
    
    response = lambda_handler(event, {})
    
    assert response['statusCode'] == 200
    mock_pool.return_value.request.assert_called_once()
    
    # Check that the message body contains the optional fields
    call_args = mock_pool.return_value.request.call_args
    message_body = call_args[1]['body'].decode('utf-8')
    assert 'Date: Unknown' in message_body
    assert 'Time: Unknown' in message_body
    assert 'Alarm: HighCPUUtilization' in message_body
    assert 'Reason: Threshold Crossed' in message_body


@mock_aws
@patch('aws_ntfy_alerts.handler.urllib3.PoolManager')
@patch('aws_ntfy_alerts.handler.SSM')
def test_missing_time_and_optional_fields(mock_ssm, mock_pool):
    """Test handling of missing time and optional detail fields."""
    mock_ssm.get_parameter.return_value = {
        'Parameter': {'Value': 'test-token-123'}
    }
    
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.data.decode.return_value = '{"id":"test123"}'
    mock_pool.return_value.request.return_value = mock_response
    
    os.environ['NTFY_TOKEN_PARAMETER'] = '/alerting/ntfy-token'
    
    event = {
        'Records': [
            {
                'Sns': {
                    'Message': json.dumps({
                        'source': 'aws.cloudwatch',
                        'detail-type': 'CloudWatch Alarm State Change',
                        'detail': {
                            'alarm-name': 'HighCPUUtilization',
                            'reason': 'Threshold Crossed: 1 out of the last 1 datapoints'
                        }
                        # Missing 'time' field
                    })
                }
            }
        ]
    }
    
    response = lambda_handler(event, {})
    
    assert response['statusCode'] == 200
    mock_pool.return_value.request.assert_called_once()
    
    # Check that the message body contains the optional fields
    call_args = mock_pool.return_value.request.call_args
    message_body = call_args[1]['body'].decode('utf-8')
    assert 'Date: Unknown' in message_body
    assert 'Time: Unknown' in message_body
    assert 'Alarm: HighCPUUtilization' in message_body
    assert 'Reason: Threshold Crossed' in message_body
