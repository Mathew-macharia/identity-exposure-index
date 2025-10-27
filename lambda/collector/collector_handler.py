# --- Existing Imports (keep these) ---
import json
import boto3
# --- New Import ---
from datetime import datetime, timedelta, timezone
# We will define this utility module later for graph interactions
from core.graph_util import save_iam_data_to_neptune, save_cloudtrail_data_to_neptune 

CUSTOMER_ROLE_ARN = "arn:aws:iam::[CUSTOMER_ACCOUNT_ID]:role/[ROLE_NAME]"

# Define the lookback window (90 days as per requirement)
LOOKBACK_DAYS = 90

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
        # Do not print error here during expected failure cases; logging handles this
        return None

# --- New Function: Collects and Parses IAM Data ---
def collect_iam_data(session: boto3.Session, account_id: str):
    """
    Connects to the customer's IAM service, lists roles, and aggregates policy data.
    """
    iam_client = session.client('iam')
    
    # 1. Fetch all IAM Roles
    roles = []
    paginator = iam_client.get_paginator('list_roles')
    for response in paginator.paginate():
        roles.extend(response['Roles'])

    iam_data = []

    # 2. Iterate through roles to collect associated policies
    for role in roles:
        role_arn = role['Arn']
        role_name = role['RoleName']
        
        role_details = {
            'arn': role_arn,
            'name': role_name,
            'account_id': account_id,
            'policies': []
        }

        # A. Attached Managed Policies
        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
        for p in attached_policies:
            # Must fetch the full policy document for the version in use
            policy_version = iam_client.get_policy(PolicyArn=p['PolicyArn'])['Policy']['DefaultVersionId']
            policy_doc = iam_client.get_policy_version(
                PolicyArn=p['PolicyArn'],
                VersionId=policy_version
            )['PolicyVersion']['Document']
            
            role_details['policies'].append({
                'arn': p['PolicyArn'],
                'name': p['PolicyName'],
                'type': 'managed',
                'document': policy_doc
            })

        # B. Inline Policies
        inline_policies = iam_client.list_role_policies(RoleName=role_name)['PolicyNames']
        for name in inline_policies:
            policy_doc = iam_client.get_role_policy(RoleName=role_name, PolicyName=name)['PolicyDocument']
            role_details['policies'].append({
                'arn': f"{role_arn}/policy/{name}",
                'name': name,
                'type': 'inline',
                'document': policy_doc
            })
        
        iam_data.append(role_details)
        
    # 3. Write data to the Graph (S4.C1 will implement this utility)
    save_iam_data_to_neptune(iam_data) 
    
    return iam_data

def collect_cloudtrail_usage(session: boto3.Session, account_id: str):
    """
    Connects to the customer's CloudTrail service and iterates through
    recent API calls to determine used actions by IAM roles.
    """
    cloudtrail_client = session.client('cloudtrail')
    
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=LOOKBACK_DAYS)
    
    used_actions_by_role = {}
    
    # We filter by 'ReadOnly' event type to quickly gather API calls. 
    # For MVP, we use the LookupEvents API for simplicity, though a real system 
    # would process S3 logs for scale.
    paginator = cloudtrail_client.get_paginator('lookup_events')
    
    # Filter for successful, role-assumed API calls
    for response in paginator.paginate(
        LookupAttributes=[
            {'AttributeKey': 'EventSource', 'AttributeValue': r'.*\.amazonaws\.com'},
            {'AttributeKey': 'ReadOnly', 'AttributeValue': 'false'} # Look for Write/Config events
        ],
        StartTime=start_time,
        EndTime=end_time
    ):
        for event in response.get('Events', []):
            try:
                # 1. Check for successful event
                event_data = json.loads(event['CloudTrailEvent'])
                if event_data.get('errorCode') or event_data.get('errorMessage'):
                    continue # Skip failed events

                # 2. Extract Identity ARN
                user_identity = event_data.get('userIdentity', {})
                if user_identity.get('type') == 'AssumedRole':
                    role_arn = user_identity['sessionContext']['sessionIssuer']['arn']
                    event_action = event_data.get('eventName')
                    event_source = event_data.get('eventSource')
                    
                    if role_arn and event_action and event_source:
                        action = f"{event_source.split('.')[0]}:{event_action}"
                        
                        if role_arn not in used_actions_by_role:
                            used_actions_by_role[role_arn] = set()
                        
                        used_actions_by_role[role_arn].add(action)

            except Exception as e:
                # Log parsing errors but continue processing other events
                print(f"Error parsing CloudTrail event: {e}")
                continue
    
    # Convert sets to lists for transmission
    used_actions_list = {arn: list(actions) for arn, actions in used_actions_by_role.items()}
    
    # Write usage data to the Graph
    save_cloudtrail_data_to_neptune(used_actions_list, start_time) 
    
    return used_actions_list

# --- Update the Existing handler function ---
def handler(event, context):
    """
    Main Lambda handler (Updated to call collect_cloudtrail_usage).
    """
    target_role_arn = CUSTOMER_ROLE_ARN 
    
    session = assume_customer_role(target_role_arn)

    if session is None:
        return {
            'statusCode': 500,
            'body': json.dumps({'message': 'Failed to assume customer role.'})
        }

    try:
        sts_client_customer = session.client('sts')
        identity = sts_client_customer.get_caller_identity()
        customer_account_id = identity['Account']
        
        # --- Collect IAM Data (S1.A2) ---
        collected_iam_data = collect_iam_data(session, customer_account_id)
        
        # --- NEW CALL: Collect CloudTrail Data (S1.A3) ---
        collected_usage_data = collect_cloudtrail_usage(session, customer_account_id)
        # ------------------------------------------------

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Collection successful. Found {len(collected_iam_data)} roles and {len(collected_usage_data)} roles with recent usage.',
                'account_id': customer_account_id
            })
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'message': f'Fatal error during collection: {e}'})
        }

# For local testing (optional)
if __name__ == "__main__":
    # Simulate a run with a placeholder ARN. This will fail if not run in a 
    # context with platform permissions, but the logic is sound.
    # Replace the placeholder with a dummy ARN for syntax checking
    CUSTOMER_ROLE_ARN = "arn:aws:iam::000000000000:role/ReadOnlyRole"
    handler(None, None)
# --- End of collector_handler.py changes ---

