# core/graph_util.py

from gremlin_python.driver.driver_remote_connection import DriverRemoteConnection
from gremlin_python.process.anonymous_traversal import traversal
from gremlin_python.process.graph_traversal import __
from urllib.parse import urlparse
from datetime import datetime, timezone
import json

# Placeholder for the Neptune endpoint (We will get this from Terraform outputs)
NEPTUNE_ENDPOINT = "wss://[YOUR_NEPTUNE_CLUSTER_ENDPOINT]:8182/gremlin" 

# Initialize the Traversal Source (g)
# This setup assumes the lambda is within the Neptune VPC and can connect.
def get_graph_traversal():
    """Returns a graph traversal source connected to Neptune."""
    # Note: In a real environment, you must handle secure connection configuration.
    try:
        url = urlparse(NEPTUNE_ENDPOINT)
        return traversal().withRemote(
            DriverRemoteConnection(
                f'{url.scheme}://{url.netloc}{url.path}',
                'g'
            )
        )
    except Exception as e:
        print(f"Error connecting to Neptune: {e}")
        return None

def save_iam_data_to_neptune(iam_data: list):
    """
    Writes the collected IAM data (Roles and Policies) to the Neptune Graph.
    This function uses 'upsert' logic to prevent creating duplicate nodes.
    """
    g = get_graph_traversal()
    if g is None:
        print("Cannot save data: Graph connection failed.")
        return

    # Counter for reporting
    roles_processed = 0

    try:
        for role_details in iam_data:
            roles_processed += 1
            role_arn = role_details['arn']
            role_name = role_details['name']
            account_id = role_details['account_id']

            # 1. Upsert the Role Node (V)
            # Find the role by ARN, or add it if it doesn't exist
            role_node = g.V().has('role', 'arn', role_arn).fold().coalesce(
                __.unfold(),
                __.addV('role').property('arn', role_arn).property('name', role_name).property('account_id', account_id)
            ).next()

            for policy_data in role_details['policies']:
                policy_arn = policy_data['arn']
                policy_name = policy_data['name']
                policy_type = policy_data['type']
                policy_doc = json.dumps(policy_data['document'])

                # 2. Upsert the Policy Node (V)
                policy_node = g.V().has('policy', 'arn', policy_arn).fold().coalesce(
                    __.unfold(),
                    __.addV('policy').property('arn', policy_arn).property('name', policy_name).property('type', policy_type).property('document', policy_doc)
                ).next()

                # 3. Create HAS_POLICY Edge (E)
                # Ensure the edge exists between Role and Policy
                g.V(role_node).as_('r').V(policy_node).coalesce(
                    __.inE('HAS_POLICY').where(__.outV().is_('r')),
                    __.addE('HAS_POLICY').from_('r')
                ).iterate()

                # 4. Parse Policy Document to Upsert Action Nodes and PERMITS Edges
                # This is a simplified parser for Statement/Action array
                for statement in policy_data['document'].get('Statement', []):
                    if statement.get('Effect') == 'Allow':
                        actions = statement.get('Action')
                        if isinstance(actions, str):
                            actions = [actions]
                        
                        for action in actions:
                            # Skip wildcard actions for now, focus on specific (for I.E.I. calculation later)
                            if '*' not in action:
                                # Upsert Action Node (V)
                                action_node = g.V().has('action', 'name', action).fold().coalesce(
                                    __.unfold(),
                                    __.addV('action').property('name', action)
                                ).next()
                                
                                # Create PERMITS Edge (E)
                                g.V(policy_node).as_('p').V(action_node).coalesce(
                                    __.inE('PERMITS').where(__.outV().is_('p')),
                                    __.addE('PERMITS').from_('p')
                                ).iterate()
        
        print(f"Successfully processed and wrote {roles_processed} roles and their full policy graph to Neptune.")
        
    except Exception as e:
        print(f"Critical error during graph write: {e}")
        # Re-raise the exception to inform the caller (the Lambda)
        raise

    finally:
        # Important: ensure the connection is closed
        if g:
            g.close()

def save_cloudtrail_data_to_neptune(used_actions_by_role: dict, start_time: datetime):
    """
    Writes CloudTrail usage data by creating USED_ACTION edges 
    between Role nodes and Action nodes.
    """
    g = get_graph_traversal()
    if g is None:
        print("Cannot save usage data: Graph connection failed.")
        return

    try:
        # Loop through each Role ARN that had usage
        for role_arn, used_actions in used_actions_by_role.items():
            
            # 1. Find the Role Node
            role_node = g.V().has('role', 'arn', role_arn).tryNext()
            
            if not role_node.isPresent():
                print(f"Warning: Role {role_arn} not found in graph. Skipping usage data.")
                continue

            # 2. Add USED_ACTION edge for each action
            for action in used_actions:
                
                # Check if the Action node exists (it should, from S1.A2)
                # If it doesn't, we still create it here to link the usage data
                action_node = g.V().has('action', 'name', action).fold().coalesce(
                    __.unfold(),
                    __.addV('action').property('name', action)
                ).next()
                
                # Create USED_ACTION Edge (E)
                # We use properties on the edge to store context
                g.V(role_node.get()).as_('r').V(action_node).coalesce(
                    # Find existing edge, or add a new one
                    __.inE('USED_ACTION').where(__.outV().is_('r')),
                    __.addE('USED_ACTION').from_('r').property('lookback_start', start_time.isoformat())
                ).property('last_seen', datetime.now(timezone.utc).isoformat()).iterate()
                
        print(f"Successfully updated graph with usage data for {len(used_actions_by_role)} roles.")

    except Exception as e:
        print(f"Critical error during CloudTrail usage write: {e}")
        raise

    finally:
        if g:
            g.close()

