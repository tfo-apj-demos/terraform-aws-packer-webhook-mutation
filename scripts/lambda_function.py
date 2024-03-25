# --- 
import os
import json
import urllib3
import hmac
import hashlib

# --- Things we need for GitHub webhook
# https://docs.github.com/en/webhooks/webhook-events-and-payloads#repository_dispatch
# https://docs.github.com/en/rest/repos/repos?apiVersion=2022-11-28#create-a-repository-dispatch-event
# https://docs.github.com/en/webhooks/testing-and-troubleshooting-webhooks/viewing-webhook-deliveries

def lambda_handler(event, context):
    print(event['headers'])
    print(event['body'])
    # --- Check to see if the signature header has been passed.
    try:
        signature = event['headers']['X-Hcp-Webhook-Signature']
    except KeyError:
        return({
                    'statusCode': 403,
                    'body': 'HMAC signature not provided.',
                    'isBase64Encoded': False
                }) 

    # --- Verify the HMAC, then check the event_action value to determine what to do.
    if verify_hmac(event):
        body = json.loads(event['body'])

        match body['event_action']:
            case 'test':
                return verify()
            case 'revoke':
                return revoke(body)
            case 'complete':
                return complete(body)
            case 'delete':
                return delete(body)
            case _:
                return({
                    'statusCode': 400,
                    'body': f'Action {body["event_action"]} found in request has no defined behaviour.',
                    'isBase64Encoded': False
                }) 
    else:
        return({
                    'statusCode': 403,
                    'body': 'Unauthorized: HMAC signature mismatch.',
                    'isBase64Encoded': False
                }) 


# --- Event Action functions
def verify():
    response = {
        'statusCode': '200',
        'body': 'verification successful',
        'isBase64Encoded': False
    }
    return(response)

def revoke(body):
    token = get_secrets(os.environ.get('GITHUB_TOKEN_ARN'))
    image_names = return_image_id(body, provider="vsphere")
    payload = {
            'event_type': 'image_revocation',
            'client_payload': {
                'image_names': image_names
            }
        }
    dispatch_url='https://api.github.com/repos/tfo-apj-demos/powershell-packer-revocation/dispatches'
    jsonPayload = json.dumps(payload).encode('UTF-8')
    
    message = f'Iteration version {body["event_payload"]["version"]["name"]} for bucket {body["event_payload"]["bucket"]["slug"]} has been revoked.'
    send_slack_notification(message)

    return(trigger_github_action(payload=jsonPayload, token=token, dispactch_url=dispatch_url))


def delete(body):
    token = get_secrets(os.environ.get('GITHUB_TOKEN_ARN'))
    image_names = return_image_id(body, provider="vsphere")
    payload = {
            'event_type': 'image_deletion',
            'client_payload': {
                'image_names': image_names
            }
        }
    dispatch_url='https://api.github.com/repos/tfo-apj-demos/powershell-packer-revocation/dispatches'
    jsonPayload = json.dumps(payload).encode('UTF-8')
    
    message = f'The following image(s) have been deleted: {image_names}.'
    send_slack_notification(message)

    return(trigger_github_action(payload=jsonPayload, token=token, dispactch_url=dispatch_url))

def complete(body):
    message = f'A new build in {body["event_payload"]["bucket"]["slug"]} has successfully completed.'
    return(send_slack_notification(message))
    # bucket_slug = body["event_payload"]["bucket"]["slug"]
    # message = f'A new build in {bucket_slug} has successfully completed.'
    
    # send_slack_notification(message)
    
    # hcpToken = get_secrets(os.environ.get('hcpToken'))
    # organization_id = get_secrets(os.environ.get('organization_id'))
    # project_id = get_secrets(os.environ.get('project_id'))
    # channel_slug = get_secrets(os.environ.get('channel_slug'))

    # iterations_data = get_iterations(organization_id, project_id, bucket_slug, hcpToken)
    # if iterations_data:
    #     iterations = iterations_data.get("iterations", [])
    #     iteration_id = get_n_minus_one_iteration_id(iterations)
    #     if iteration_id:
    #         if update_channel(organization_id, project_id, bucket_slug, channel_slug, iteration_id, hcpToken):
    #             # Success - send notification about channel update
    #             update_message = f"Channel '{channel_slug}' was successfully updated for iteration ID {iteration_id} in bucket '{bucket_slug}'."
    #             send_slack_notification(update_message)
    #         else:
    #             # Handle failure to update channel
    #             error_message = f"Failed to update the channel for iteration ID {iteration_id} in bucket '{bucket_slug}'."
    #             send_slack_notification(error_message)
    #     else:
    #         # Handle case where iteration_id is not found
    #         print("N-1 iteration ID not found.")
    # else:
    #     # Handle case where iterations data is not retrieved
    #     print("Failed to retrieve iterations.")
    # return()

# --- Helper functions
def verify_hmac(event):
    signature = event['headers']['X-Hcp-Webhook-Signature']
    secret = bytes(get_secrets(os.environ.get('HMAC_TOKEN_ARN')), 'utf-8')
    message = bytes(event['body'], 'utf-8')
    hash = hmac.new(secret, message, hashlib.sha512)
    compare_digest = hmac.compare_digest(hash.hexdigest(), signature)
    return(compare_digest)

def get_secrets(secret_arn):
    secrets_extension_http_port = os.environ.get('SECRETS_EXTENSION_HTTP_PORT')
    secrets_extension_endpoint = f"http://localhost:{secrets_extension_http_port}/secretsmanager/get?secretId={secret_arn}" 
    
    headers = {  
        'X-Aws-Parameters-Secrets-Token': os.environ.get('AWS_SESSION_TOKEN')
    }

    http = urllib3.PoolManager()
    response = http.request('GET', secrets_extension_endpoint, headers=headers)
    jsonResponse = json.loads(response.data)
    token = jsonResponse["SecretString"]

    return(token)

def trigger_github_action(payload, token, dispactch_url):
    headers = {
        'Authorization': f'Bearer {token}',
        'X-GitHub-Api-Version': '2022-11-28',
        'Accept': 'application/vnd.github+json'
    }

    http = urllib3.PoolManager()
    response = http.request('POST', 
                            dispactch_url, 
                            body = payload, 
                            headers = headers
                            )
    return({ 
        'statusCode': response.status,    
        'body': response.data,
        'isBase64Encoded': False
    })
    
def send_slack_notification(message):
    headers = {
        'Content-type': 'application/json'
    }
    payload = {
        'text': f'{message}'
    }
    jsonPayload = json.dumps(payload).encode('UTF-8')
    http = urllib3.PoolManager()
    slack_url = get_secrets(os.environ.get('SLACK_URL'))
    response = http.request('POST', slack_url, headers=headers, body=jsonPayload)
    return({ 
        'statusCode': response.status,    
        'body': response.data,
        'isBase64Encoded': False
    })
    
def return_image_id(body, provider):
    image_ids = []
    for build in body['event_payload']['builds']:
        if build['platform'] == provider:
            for artifact in build["artifacts"]: 
                image_ids.append(artifact["external_identifier"]) 
    return(image_ids)

def get_iterations(organization_id, project_id, bucket_slug, hcpToken):
    endpoint = f"https://api.cloud.hashicorp.com/packer/2021-04-30/organizations/{organization_id}/projects/{project_id}/images/{bucket_slug}/iterations"
    headers = {
        'Authorization': f'Bearer {hcpToken}'
    }
    http = urllib3.PoolManager()
    response = http.request('GET', endpoint, headers=headers)
    if response.status != 200:
        # Handle error
        return None

    return json.loads(response.data.decode('utf-8'))

def get_n_minus_one_iteration_id(iterations):
    # Assuming iterations are sorted with the latest iteration first
    if len(iterations) >= 2:
        n_minus_one_iteration = iterations[1]  # Second item in the list
        return n_minus_one_iteration.get('id')
    else:
        # Handle case where there are not enough iterations
        return None

def update_channel(organization_id, project_id, bucket_slug, channel_slug, iteration_id, hcpToken):
    endpoint = f"https://api.cloud.hashicorp.com/packer/2021-04-30/organizations/{organization_id}/projects/{project_id}/images/{bucket_slug}/channels/{channel_slug}"
    payload = {
        "iteration_id": iteration_id
    }
    headers = {
        'Authorization': f'Bearer {hcpToken}',
        'Content-Type': 'application/json'
    }
    http = urllib3.PoolManager()
    encoded_payload = json.dumps(payload).encode('UTF-8')
    response = http.request('PATCH', endpoint, body=encoded_payload, headers=headers)

    return response.status == 200
