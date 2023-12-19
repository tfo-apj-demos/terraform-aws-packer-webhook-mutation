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

    # --- Verify the HMAC, then check the eventAction value to determine what to do.
    if verify_hmac(event):
        body = json.loads(event['body'])

        match body['eventAction']:
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
                    'body': f'Action {body["eventAction"]} found in request has no defined behaviour.',
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
    payload = {
            'event_type': 'image_revocation',
            'client_payload': {
                'iteration_id': body['eventPayload']['iteration']['id'],
                'bucket_slug': body['eventPayload']['bucket']['slug'],
                'project_id': body['eventPayload']['project_id'],
                'organization_id': body['eventPayload']['organization_id'],
            }
        }
    dispatch_url='https://api.github.com/repos/tfo-apj-demos/powershell-packer-revocation/dispatches'
    jsonPayload = json.dumps(payload).encode('UTF-8')

    return(trigger_github_action(payload=jsonPayload, token=token, dispactch_url=dispatch_url))


def delete(body):
    token = get_secrets(os.environ.get('GITHUB_TOKEN_ARN'))
    payload = {
            'event_type': 'image_deletion',
            'client_payload': {
                'iteration_id': body['eventPayload']['iteration']['id'],
                'bucket_slug': body['eventPayload']['bucket']['slug'],
                'project_id': body['eventPayload']['project_id'],
                'organization_id': body['eventPayload']['organization_id'],
            }
        }
    dispatch_url='https://api.github.com/repos/tfo-apj-demos/powershell-packer-revocation/dispatches'
    jsonPayload = json.dumps(payload).encode('UTF-8')

    return(trigger_github_action(payload=jsonPayload, token=token, dispactch_url=dispatch_url))

def complete(body):
    headers = {
        'Content-type': 'application/json'
    }
    payload = {
        'text': f'A new build in {body["eventPayload"]["bucket"]["slug"]} has successfully completed.'
    }
    jsonPayload = json.dumps(payload).encode('UTF-8')
    http = urllib3.PoolManager()
    slack_url = json.dumps(get_secrets(os.environ.get('SLACK_URL')))
    response = http.request('POST', slack_url, headers=headers, body=jsonPayload)
    return({ 
        'statusCode': response.status,    
        'body': response.data,
        'isBase64Encoded': False
    })

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