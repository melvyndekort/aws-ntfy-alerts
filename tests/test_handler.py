"""Tests for alerting handler."""

import json
import os
import pytest
from moto import mock_aws
import boto3
from unittest.mock import patch, MagicMock
from src.handler import lambda_handler


@mock_aws
@patch('src.handler.urllib3.PoolManager')
@patch('src.handler.ssm')
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
                        'region': 'eu-west-1'
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
@patch('src.handler.urllib3.PoolManager')
@patch('src.handler.ssm')
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
                        'region': 'us-east-1'
                    })
                }
            }
        ]
    }
    
    response = lambda_handler(event, {})
    
    assert response['statusCode'] == 200  # Lambda still succeeds
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
    
    response = lambda_handler(event, {})
    
    assert response['statusCode'] == 200
    assert 'Alerts processed successfully' in response['body']


def test_lambda_handler_empty_records():
    """Test handling of empty records."""
    event = {'Records': []}
    
    response = lambda_handler(event, {})
    
    assert response['statusCode'] == 200
    assert 'Alerts processed successfully' in response['body']


@mock_aws
@patch('src.handler.urllib3.PoolManager')
@patch('src.handler.ssm')
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
                        'region': 'us-east-1'
                    })
                }
            },
            {
                'Sns': {
                    'Message': json.dumps({
                        'source': 'aws.rds',
                        'detail-type': 'RDS Alert',
                        'region': 'us-west-2'
                    })
                }
            }
        ]
    }
    
    response = lambda_handler(event, {})
    
    assert response['statusCode'] == 200
    # Should make 2 HTTP requests
    assert mock_pool.return_value.request.call_count == 2
