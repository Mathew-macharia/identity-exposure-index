import unittest
from unittest.mock import patch, MagicMock
from moto import mock_aws
import json
import boto3
import sys
import os

# Add the project root to the Python path so we can import core module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Import the function we are testing
from collector_handler import assume_customer_role, handler 

# Define a mock ARN that our test will use
MOCK_ROLE_ARN = "arn:aws:iam::123456789012:role/MockCustomerRole"
MOCK_ACCOUNT_ID = "123456789012"

class TestCollectorHandler(unittest.TestCase):
    
    @mock_aws # Use moto to mock AWS services, especially STS
    @patch('collector_handler.collect_iam_data') # Mock the IAM data collection
    @patch('collector_handler.CUSTOMER_ROLE_ARN', MOCK_ROLE_ARN) # Override placeholder
    def test_s1a1_successful_role_assumption(self, mock_collect_iam):
        """
        Tests the core differentiator: successful assumption of the customer role
        and retrieval of the account ID.
        """
        # Mock the collect_iam_data to return empty list (we're testing role assumption, not IAM collection)
        mock_collect_iam.return_value = []
        
        # 1. Setup Mock STS Client
        # The mock client will automatically handle the assume_role call
        sts_client = boto3.client("sts", region_name="us-east-1")
        
        # 2. Execute the handler function
        # We pass None for event/context as we are mocking the input
        response = handler(None, None)
        
        # 3. Assertions based on the Acceptance Criteria
        self.assertEqual(response['statusCode'], 200, "Should return 200 on successful connection")
        
        body = json.loads(response['body'])
        self.assertEqual(body['account_id'], MOCK_ACCOUNT_ID, "Should successfully retrieve the mocked account ID")
        self.assertIn('Role assumption and IAM data collection successful', body['message'], "Should confirm success")

    @patch('collector_handler.boto3.client')
    @patch('collector_handler.CUSTOMER_ROLE_ARN', MOCK_ROLE_ARN)
    def test_s1a1_failed_role_assumption(self, mock_boto_client):
        """
        Tests the failure case where the customer's role assumption is denied.
        """
        # Configure the mock STS client to raise an exception
        mock_sts = MagicMock()
        mock_sts.assume_role.side_effect = Exception("Access Denied: The platform role lacks permissions.")
        
        # Configure the main boto3.client call to return our mock STS client
        mock_boto_client.return_value = mock_sts

        # Execute the handler function
        response = handler(None, None)
        
        # Assertions
        self.assertEqual(response['statusCode'], 500, "Should return 500 on failure to assume role")
        
        body = json.loads(response['body'])
        self.assertIn('Failed to assume customer role', body['message'], "Should report the failure clearly")


if __name__ == '__main__':
    # Run the tests
    unittest.main()

