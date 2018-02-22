import boto3
import json
from urllib2 import Request, urlopen, URLError, HTTPError
import os

s3 = boto3.client('s3')
accountnum = boto3.client('sts').get_caller_identity()['Account']
account = boto3.client('iam').list_account_aliases()['AccountAliases'][0]

if 'SLACK_WEBHOOK' in os.environ:
    SLACK=True
    slack_url = os.environ['SLACK_WEBHOOK']               
    slack_channel = os.environ['SLACK_CHANNEL']           
else:
    SLACK=False

if 'DEFAULT_ENCRYPTION_KMS' in os.environ: 
    target_encryption = {
        'Rules': [
            {
                'ApplyServerSideEncryptionByDefault': {
                    'SSEAlgorithm': 'aws:kms',
                    'KMSMasterKeyID': os.environ['DEFAULT_ENCRYPTION_KMS']
                }
            },
        ]
    }
else:
    target_encryption = {
        'Rules': [
            {
                'ApplyServerSideEncryptionByDefault': {
                    'SSEAlgorithm': 'AES256',
                }
            },
        ]
    }

target_inventory_policy = {
    'Id': os.environ['S3_INVENTORY_RULE_NAME'],
    'InventoryConfiguration': {
        'Destination': {
            'S3BucketDestination': {
                'AccountId': os.environ['S3_INVENTORY_ACCOUNT']
                'Prefix': account
                'Format': os.environ['S3_INVENTORY_FORMAT'],
                'Encryption': {
                    'SSES3': {}
                }
            }
        },
        'IsEnabled': True,
        'Id': os.environ['S3_INVENTORY_RULE_NAME'],
        'IncludedObjectVersions': os.environ['S3_INVENTORY_VERSIONING'],
        'OptionalFields': [
            'Size','LastModifiedDate','StorageClass','ETag','IsMultipartUploaded','ReplicationStatus','EncryptionStatus',
        ],
    "Schedule": {"Frequency": os.environ['S3_INVENTORY_FREQUENCY']},
    }
}

monitored_events = [
    'CreateBucket',
    'DeleteBucketEncryption',
    'PutBucketAcl',
    'PutBucketPolicy',
    'DeleteInventoryConfiguration',
    'DeleteBucket',
]

message = ''
message_attachment = {}

def check_default_encryption(bucketname):
    global message
    try:
        default_encryption = s3.get_bucket_encryption(Bucket=bucketname)
    except Exception as e:
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            return False
        elif e.response['Error']['Code'] == 'AccessDenied':
            message += 'Access denied to bucket while trying to check default encryption\n'
            return False
        else:
            print(e)
            return False
    else:
        if 'ServerSideEncryptionConfiguration' in default_encryption and 'Rules' in default_encryption['ServerSideEncryptionConfiguration']:
            if target_encryption == default_encryption['ServerSideEncryptionConfiguration']:
                message += 'Bucket already has default encryption policy of: ' + json.dumps(default_encryption['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']) + '\n'
                return True
            else:
                message += 'Bucket already has a default encryption policy of '+ json.dumps(default_encryption['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault'])
                message += ', but it does not match the target encryption policy this bot enforces of ' + json.dumps(target_encryption['Rules'][0]['ApplyServerSideEncryptionByDefault']) + ', please investigate.'
                return True
        else:
            return False      

def apply_default_encryption(bucketname):
    global message
    try:
        s3.put_bucket_encryption(
            Bucket=bucketname,
            ServerSideEncryptionConfiguration=target_encryption
        )
    except Exception as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            message += 'Access denied to bucket while trying to apply default encryption policy\n'
            print('Access denied to bucket while trying to apply default encryption policy')
        else:
            message += 'Error! Failed to add default encryption policy to bucket\n'
            print(e)
    else:
        message += 'Default encryption policy ' + json.dumps(target_encryption['Rules'][0]['ApplyServerSideEncryptionByDefault']) + ' added to bucket\n'

def check_for_s3_inventory(bucketname, target_policy):
    global message
    try:
        inventories = s3.list_bucket_inventory_configurations(Bucket=bucketname)
    except Exception as e:
        print(e)
        return False
    else:
        if 'InventoryConfigurationList' in inventories:
            for inventory in inventories['InventoryConfigurationList']:
                if inventory == target_policy['InventoryConfiguration']:
                    return True
        return False

def apply_s3_inventory(target_policy):
    global message
    try:
        response = s3.put_bucket_inventory_configuration(**target_policy)
    except Exception as e:
        message += 'Error! Failed to add S3 Inventory Policy to bucket\n'
        print(e)
    else:
        message += 'S3 Inventory Policy added to bucket, delivering inventory reports to ' + target_policy['InventoryConfiguration']['Destination']['S3BucketDestination']['Bucket'] + '\n'

def check_bucket_policy_statement_public(statement):
    global message
    if statement['Effect']=="Allow" and statement['Principal']=="*": #and statement['Action']=="s3:GetObject"
        if 'Condition' in statement:
            if 'StringEquals' in statement['Condition'] and 'aws:SourceVpc' in statement['Condition']['StringEquals']:
                return False
            elif 'IpAddress' in statement['Condition'] and 'aws:SourceIp' in statement['Condition']['IpAddress']:
                return False
            else:
                return True
        else:
            return True                 
    return False

def check_bucket_policy(bucketname):
    global message
    #Check for bucket policy statement
    try:
        bucket_policy = s3.get_bucket_policy(Bucket=bucketname)
    except Exception as e: 
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            return False
        else:
            message += 'An error occured while checking the policy on bucket\n'
            print(e)
            return False
    else:
        bucket_policy = json.loads(bucket_policy['Policy'])
        for statement in bucket_policy["Statement"]:
            if check_bucket_policy_statement_public(statement) == True:
                message += 'Warning! Bucket allows public access via bucket policy.\n'
        return bucket_policy

def check_bucket_ACL_public(bucketname):
    global message
    try:
        bucket_acl = s3.get_bucket_acl(Bucket=bucketname)
    except Exception as e:
        print(e)
    else:   
        bucket_acl_public = []
        if bucket_acl:
            for grant in bucket_acl["Grants"]:
                if 'URI' in grant['Grantee'] and grant['Grantee']['URI'] == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    message += "Bucket allows everyone permission to " + grant['Permission'] + " via the ACL.\n"
                    bucket_acl_public.append(grant)
        return bucket_acl_public

def handler(event, context):
    global message
    global message_attachment
    print(json.dumps(event))
    
    if 'detail' in event:
        eventName = event['detail']['eventName']
        bucketname = event['detail']['requestParameters']['bucketName']

        if eventName in monitored_events:
            if 'userName' in event['detail']['userIdentity']:
                requestor = event['detail']['userIdentity']['userName']
            elif 'sessionContext' in event['detail']['userIdentity']:
                requestor = event['detail']['userIdentity']['sessionContext']['sessionIssuer']['userName']
            else:
                requestor = json.dumps(event['detail']['userIdentity'])

            if 'errorCode' in event['detail']:
                print('Error in request ' + eventName + ' for bucket ' + bucketname + ' in account ' + account + ' , aborting configuration check')
                print(event['detail']['errorCode'])
                print(event['detail']['errorMessage'])
            else:
                if eventName == 'CreateBucket':
                    message += 'New bucket `' + bucketname + '` detected in account `' + account + '`, created by `' + requestor + '`, checking configuration for compliance:\n'

                    if 'CreateBucketConfiguration' in event['detail']['requestParameters'] and 'LocationConstraint' in event['detail']['requestParameters']['CreateBucketConfiguration']:
                        location = event['detail']['requestParameters']['CreateBucketConfiguration']['LocationConstraint']
                        if location != event['detail']['awsRegion']:
                            message += ('Error: bucket location does not match aws region\n')
                    else:
                        location = 'us-east-1'

                    target_policy['Bucket'] = bucketname
                    target_policy['InventoryConfiguration']['Destination']['S3BucketDestination']['Bucket'] = 'arn:aws:s3:::' + os.environ['S3_INVENTORY_BUCKET_PREFIX'] + '-' + location

                    ### Enforce by Default ###
                    if check_default_encryption(bucketname) == False:
                        apply_default_encryption(bucketname)

                    if check_for_s3_inventory(target_policy) == False:
                        apply_s3_inventory(target_policy)

                    ### Check and Alert ###
                    # Check public permissions via ACLs
                    bucket_acl = check_bucket_ACL_public(bucketname)
                    if bucket_acl:
                        message += 'Warning: This bucket is publicly accessible, please review!\n'
                        message += json.dumps(bucket_acl) + '\n\n'

                    # Check bucket policy for non-blank and specifically public permissions
                    bucket_policy = check_bucket_policy(bucketname) # If not False, alert and put policy in
                    if bucket_policy != False:
                        message_attachment = {
                            'pretext':'Warning: There is a bucket policy, please review:',
                            'text':json.dumps(bucket_policy, indent=4, separators=(',', ': '))
                        }

                elif eventName == 'DeleteBucketEncryption':
                    message += 'Warning: `' + requestor + '` has deleted the bucket encryption policy on bucket `' + bucketname +'` in account `' + account + '`, reviewing for compliance:`\n'
                    if check_default_encryption(bucketname) == False:
                        apply_default_encryption(bucketname)

                elif eventName == 'PutBucketAcl':
                    message += 'Warning: `' + requestor + '` has changed the bucket ACL on bucket `' + bucketname +'` in account `' + account + '`, reviewing for compliance:\n'
                    bucket_acl = check_bucket_ACL_public(bucketname)
                    if bucket_acl:
                        message += 'Warning: This bucket is publicly accessible, please review!\n'
                        message += json.dumps(bucket_acl) + '\n\n'

                elif eventName == 'PutBucketPolicy':
                    message += 'Warning: `' + requestor + '` has changed the bucket policy on bucket `' + bucketname +'` in account `' + account + '`, reviewing for compliance:\n'
                    bucket_policy = check_bucket_policy(bucketname) # If not False, alert and put policy in
                    if bucket_policy != False:
                        message_attachment = {
                            'pretext':'Warning: There is a bucket policy, please review:',
                            'text':json.dumps(bucket_policy, indent=4, separators=(',', ': '))
                        }

                elif eventName == 'DeleteInventoryConfiguration':
                    message += 'Warning: `' + requestor + '` has deleted the S3 inventory configuration on bucket `' + bucketname +'` in account `' + account + '`, reviewing for compliance:\n'
                    if check_for_s3_inventory(bucketname) == False:
                        apply_s3_inventory(bucketname, location)

                elif eventName == 'DeleteBucket':
                    message += 'Warning: `' + requestor + '` has deleted the S3 bucket `' + bucketname +'` in account `' + account + '`.\n'

                message += '\n'

                print(message)

                if SLACK==True:
                    slack_message = {
                        'text' : message,
                        'mrkdwn': True,
                        'channel': slack_channel,
                        'username': 'S3 Bucket Configuration Audit Bot',
                        'icon_emoji': ':aws1:'
                    }

                    req = Request(slack_url, json.dumps(slack_message))
                    try:
                        response = urlopen(req)
                        response.read()
                        print('Alerted Slack channel of this S3 Bucket change')
                    except HTTPError as exc:
                        print('Error!  Failed to alert slack channel: %d %s', exc.code, exc.reason)
                    except URLError as exc:
                        print('Error!  Failed to alert slack channel.  Server connection failed: %s', exc.reason)

                    if message_attachment:
                        slack_message.pop('text')
                        slack_message['attachments'] = [message_attachment]
                        slack_message['mrkdwn'] = False
                        req = Request(slack_url, json.dumps(slack_message))
                        try:
                          response = urlopen(req)
                          response.read()
                          print('Alerted Slack channel of this S3 Bucket change')
                        except HTTPError as exc:
                          print('Error!  Failed to alert slack channel: %d %s', exc.code, exc.reason)
                        except URLError as exc:
                          print('Error!  Failed to alert slack channel.  Server connection failed: %s', exc.reason)

