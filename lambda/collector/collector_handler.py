import json
import boto3

# The ARN of the role our service will assume in the customer's account
CUSTOMER_ROLE_ARN = "arn:aws:iam::[CUSTOMER_ACCOUNT_ID]:role/[ROLE_NAME]" 
# Note: In a real deployment, this would come from an environment variable or input event

def assume_customer_role(role_arn: str):
    """
    Attempts to assume a role in the customer's account using STS, 
    and returns a client session.
    """
    try:
        # 1. Initiate STS client from our (the platform's) account
        sts_client = boto3.client('sts')
        
        # 2. Assume the role in the target customer account
        assumed_role_object = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="IEICollectorSession" # Unique identifier for the session
        )
        
        # 3. Extract temporary credentials
        credentials = assumed_role_object['Credentials']
        
        # 4. Create a new Boto3 session using the temporary credentials
        # We use 'iam' client just to fetch basic account info for validation
        customer_session = boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
        )
        
        return customer_session

    except Exception as e:
        print(f"Error assuming role {role_arn}: {e}")
        return None

def handler(event, context):
    """
    Main Lambda handler for the collector service.
    Validates the connection by getting the account ID.
    """
    # Placeholder for the customer's IAM Role ARN we need to assume
    # In a later sprint, this will be passed via the event payload
    target_role_arn = CUSTOMER_ROLE_ARN 
    
    # 1. Attempt to assume the role
    session = assume_customer_role(target_role_arn)

    if session is None:
        return {
            'statusCode': 500,
            'body': json.dumps({'message': 'Failed to assume customer role.'})
        }

    # 2. Validation: Get the account ID using the assumed session
    try:
        # Fetch Caller Identity to confirm we successfully switched to the customer's account
        sts_client_customer = session.client('sts')
        identity = sts_client_customer.get_caller_identity()
        customer_account_id = identity['Account']

        print(f"Successfully connected to account: {customer_account_id}")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Role assumption successful.',
                'account_id': customer_account_id
            })
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'message': f'Validation failed after assumption: {e}'})
        }

# For local testing (optional)
if __name__ == "__main__":
    # Simulate a run with a placeholder ARN. This will fail if not run in a 
    # context with platform permissions, but the logic is sound.
    # Replace the placeholder with a dummy ARN for syntax checking
    CUSTOMER_ROLE_ARN = "arn:aws:iam::000000000000:role/ReadOnlyRole"
    handler(None, None)

