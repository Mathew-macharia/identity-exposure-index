# lambda/scoring/scoring_handler.py

import json
import boto3
from gremlin_python.process.traversal import Order
from datetime import datetime, timezone
from core.graph_util import get_graph_traversal, calculate_role_metrics

# Environment constants
DYNAMODB_TABLE_NAME = "IdentityExposureMetrics-mvp"
LOOKBACK_WINDOW = 90
MAX_SCORE = 100

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(DYNAMODB_TABLE_NAME)

def calculate_iei(metrics: dict):
    """
    Calculates the Identity Exposure Index (I.E.I.) score based on the formula.
    """
    taa = metrics['total_allowed_actions']
    ua  = metrics['used_actions']
    dslu = metrics['days_since_last_use']
    
    # --- Privilege Breadth (PB) Calculation ---
    if taa == 0:
        # If no permissions are allowed, risk is minimal
        pb = 0
    elif taa == ua:
        # If all allowed permissions are used, risk is minimal
        pb = 0
    else:
        # Formula: 50 * ( (TAA - UA) / TAA )
        pb = 50 * ((taa - ua) / taa)
    
    # --- Usage Inactivity (UI) Calculation ---
    # Formula: 50 * ( DSLU / 90 )
    ui = 50 * (dslu / LOOKBACK_WINDOW)
    
    # Final I.E.I. Score
    iei_score = round(pb + ui, 2)
    
    return {
        'iei_score': iei_score,
        'pb_score': round(pb, 2),
        'ui_score': round(ui, 2)
    }

def handler(event, context):
    """
    Main Lambda handler for the scoring service.
    Triggers the calculation for all roles in the graph and writes results to DynamoDB.
    """
    g = get_graph_traversal()
    if g is None:
        return {'statusCode': 500, 'body': json.dumps({'message': 'Failed to connect to graph for scoring.'})}

    try:
        # 1. Get all Role ARNs from the graph
        role_arns = g.V().hasLabel('role').values('arn').toList()
        
        results = []
        for arn in role_arns:
            # 2. Calculate metrics
            metrics = calculate_role_metrics(g, arn)
            
            # 3. Calculate I.E.I. Score
            scores = calculate_iei(metrics)
            
            # 4. Write result to DynamoDB (S2.B2 setup)
            table.put_item(
                Item={
                    'arn': arn,
                    'iei_score': scores['iei_score'],
                    'pb_score': scores['pb_score'],
                    'ui_score': scores['ui_score'],
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
            )
            results.append({'arn': arn, 'score': scores['iei_score']})

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Scoring complete for {len(results)} roles.',
                'results': results
            })
        }

    except Exception as e:
        g.close()
        return {'statusCode': 500, 'body': json.dumps({'message': f'Scoring process failed: {e}'})}
    
    finally:
        g.close()

