import os
import json
import urllib3
import hmac
import hashlib

def lambda_handler(event, context):
    try:
        print("Received headers:", event.get('headers', {}))
        print("Received body:", event.get('body', ''))
        
        # Check for webhook signature header
        headers = event.get('headers', {})
        signature = headers.get('X-Hcp-Webhook-Signature')
        
        if not signature:
            return {
                'statusCode': 403,
                'body': json.dumps({'error': 'HMAC signature not provided'}),
                'isBase64Encoded': False
            }

        # Verify HMAC signature
        if not verify_webhook_signature(event, signature):
            return {
                'statusCode': 403,
                'body': json.dumps({'error': 'Unauthorized: HMAC signature mismatch'}),
                'isBase64Encoded': False
            }

        # Parse webhook payload
        body = json.loads(event.get('body', '{}'))
        event_action = body.get('event_action', '')

        # Route to appropriate handler
        if event_action == 'test':
            return handle_verification()
        elif event_action == 'revoke':
            return handle_revocation(body)
        elif event_action == 'complete':
            return handle_completion(body)
        elif event_action == 'delete':
            return handle_deletion(body)
        else:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': f'Unsupported action: {event_action}'}),
                'isBase64Encoded': False
            }
            
    except Exception as e:
        print(f"Error processing webhook: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal server error'}),
            'isBase64Encoded': False
        }

def handle_verification():
    """Handle HCP webhook verification requests"""
    return {
        'statusCode': 200,
        'body': json.dumps({'message': 'verification successful'}),
        'isBase64Encoded': False
    }

def handle_revocation(payload):
    """Handle image revocation events"""
    try:
        github_token = os.environ.get('GITHUB_TOKEN', '')
        if not github_token:
            print("Warning: GitHub token not configured")
            return handle_slack_only(payload, 'revocation')

        # Extract the required data from HCP webhook payload
        event_payload = payload.get('event_payload', {})
        bucket_data = event_payload.get('bucket', {})
        version_data = event_payload.get('version', {})
        
        # Map HCP payload to GitHub workflow expected format
        bucket_slug = bucket_data.get('slug', '')
        iteration_id = version_data.get('id', '')  # In HCP, version.id is the iteration ID
        organization_id = event_payload.get('organization_id', '')
        project_id = event_payload.get('project_id', '')
        
        # Also get image names for reference
        image_names = extract_image_identifiers(payload, "vsphere")
        
        dispatch_payload = {
            'event_type': 'image_revocation',
            'client_payload': {
                'bucket_slug': bucket_slug,
                'iteration_id': iteration_id,
                'organization_id': organization_id,
                'project_id': project_id,
                'image_names': image_names  # Keep for debugging/reference
            }
        }
        
        print(f"Sending GitHub dispatch with payload: {dispatch_payload}")
        
        # Send to GitHub
        github_result = dispatch_to_github(dispatch_payload, github_token)
        
        # Send Slack notification
        version_name = version_data.get('name', 'unknown')
        bucket_name = bucket_data.get('name', 'unknown')
        message = f'Version {version_name} in bucket {bucket_name} has been revoked. Triggering cleanup workflow.'
        send_slack_message(message)
        
        return github_result
        
    except Exception as e:
        print(f"Error handling revocation: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)}),
            'isBase64Encoded': False
        }

def handle_deletion(payload):
    """Handle image deletion events"""
    try:
        github_token = os.environ.get('GITHUB_TOKEN', '')
        if not github_token:
            print("Warning: GitHub token not configured")
            return handle_slack_only(payload, 'deletion')

        # Extract the required data from HCP webhook payload
        event_payload = payload.get('event_payload', {})
        bucket_data = event_payload.get('bucket', {})
        version_data = event_payload.get('version', {})
        
        # Map HCP payload to GitHub workflow expected format
        bucket_slug = bucket_data.get('slug', '')
        iteration_id = version_data.get('id', '')
        organization_id = event_payload.get('organization_id', '')
        project_id = event_payload.get('project_id', '')
        
        # Get image names
        image_names = extract_image_identifiers(payload, "vsphere")
        
        dispatch_payload = {
            'event_type': 'image_deletion',
            'client_payload': {
                'bucket_slug': bucket_slug,
                'iteration_id': iteration_id,
                'organization_id': organization_id,
                'project_id': project_id,
                'image_names': image_names
            }
        }
        
        print(f"Sending GitHub dispatch with payload: {dispatch_payload}")
        
        # Send to GitHub
        github_result = dispatch_to_github(dispatch_payload, github_token)
        
        # Send Slack notification
        message = f'Images have been deleted: {", ".join(image_names)}. Triggering cleanup workflow.'
        send_slack_message(message)
        
        return github_result
        
    except Exception as e:
        print(f"Error handling deletion: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)}),
            'isBase64Encoded': False
        }

def handle_completion(payload):
    """Handle build completion events"""
    try:
        bucket_name = payload.get('event_payload', {}).get('bucket', {}).get('name', 'unknown')
        message = f'A new build in {bucket_name} has completed successfully.'
        return send_slack_message(message)
        
    except Exception as e:
        print(f"Error handling completion: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)}),
            'isBase64Encoded': False
        }

def handle_slack_only(payload, event_type):
    """Handle events with only Slack notification when GitHub token is missing"""
    try:
        if event_type == 'revocation':
            version_name = payload.get('event_payload', {}).get('version', {}).get('name', 'unknown')
            bucket_name = payload.get('event_payload', {}).get('bucket', {}).get('name', 'unknown')
            message = f'Version {version_name} in bucket {bucket_name} has been revoked.'
        elif event_type == 'deletion':
            image_names = extract_image_identifiers(payload, "vsphere")
            message = f'Images have been deleted: {", ".join(image_names)}'
        else:
            message = f'Event {event_type} occurred'
            
        return send_slack_message(message)
        
    except Exception as e:
        print(f"Error in slack-only handler: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)}),
            'isBase64Encoded': False
        }

def verify_webhook_signature(event, signature):
    """Verify the HMAC signature from HCP webhook"""
    try:
        hmac_token = os.environ.get('HMAC_TOKEN', '')
        if not hmac_token:
            print("Warning: HMAC token not configured, skipping signature verification")
            return True
            
        message_body = event.get('body', '')
        expected_hash = hmac.new(
            hmac_token.encode('utf-8'),
            message_body.encode('utf-8'),
            hashlib.sha512
        ).hexdigest()
        
        return hmac.compare_digest(expected_hash, signature)
        
    except Exception as e:
        print(f"Error verifying signature: {str(e)}")
        return False

def dispatch_to_github(payload, token):
    """Send repository dispatch event to GitHub"""
    try:
        dispatch_url = 'https://api.github.com/repos/tfo-apj-demos/powershell-packer-revocation/dispatches'
        
        headers = {
            'Authorization': f'Bearer {token}',
            'X-GitHub-Api-Version': '2022-11-28',
            'Accept': 'application/vnd.github+json',
            'Content-Type': 'application/json'
        }

        http = urllib3.PoolManager()
        json_payload = json.dumps(payload).encode('UTF-8')
        
        response = http.request('POST', dispatch_url, body=json_payload, headers=headers)
        
        return {
            'statusCode': response.status,
            'body': json.dumps({'github_status': response.status}),
            'isBase64Encoded': False
        }
        
    except Exception as e:
        print(f"Error dispatching to GitHub: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'GitHub dispatch failed: {str(e)}'}),
            'isBase64Encoded': False
        }

def send_slack_message(message):
    """Send notification to Slack webhook"""
    try:
        slack_url = os.environ.get('SLACK_URL', '')
        if not slack_url:
            print("Warning: Slack URL not configured, skipping notification")
            return {
                'statusCode': 200,
                'body': json.dumps({'message': 'Processed (no Slack configured)'}),
                'isBase64Encoded': False
            }

        headers = {'Content-type': 'application/json'}
        payload = {'text': message}
        json_payload = json.dumps(payload).encode('UTF-8')
        
        http = urllib3.PoolManager()
        response = http.request('POST', slack_url, headers=headers, body=json_payload)
        
        return {
            'statusCode': response.status,
            'body': json.dumps({'slack_status': response.status}),
            'isBase64Encoded': False
        }
        
    except Exception as e:
        print(f"Error sending Slack message: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'Slack notification failed: {str(e)}'}),
            'isBase64Encoded': False
        }

def extract_image_identifiers(payload, provider):
    """Extract image identifiers for a specific cloud provider"""
    try:
        image_ids = []
        builds = payload.get('event_payload', {}).get('builds', [])
        
        for build in builds:
            if build.get('platform') == provider:
                artifacts = build.get('artifacts', [])
                for artifact in artifacts:
                    external_id = artifact.get('external_identifier')
                    if external_id:
                        image_ids.append(external_id)
        
        return image_ids
        
    except Exception as e:
        print(f"Error extracting image identifiers: {str(e)}")
        return []