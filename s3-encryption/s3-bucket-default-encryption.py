#!/usr/bin/env python
"""
s3-bucket-default-encryption: checks every bucket in account(s) and applies a specified default encryption policy to each

Usage: 
  s3-bucket-default-encryption audit [--accounts=<accounts>] [--kms=<kmskeyid>] [--filename=<filename>] [<bucket_names>...]
  s3-bucket-default-encryption apply [--force] [--accounts=<accounts>] [--kms=<kmskeyid>] [--filename=<filename>] [<bucket_names>...]
  s3-bucket-default-encryption -h | --help

Audit mode defaults to check all buckets, but will check a subset of buckets if provided in <bucket_names>
Apply mode will attempt to apply the target encryption policy to all buckets by default, or a subset of buckets if specified

Arguments:
  --accounts=<>    # Optionally specify a comma-separated list of accounts to run in by your CLI profile names. Checks AWS_PROFILE env. variable if not set
  --kms=<>         # Optionally specify a KMS key to use for your default encryption policy, otherwise defaults to SSE-AES-256
  --filename=<>.   # Optionally specify a filename to output the results of the audit/remediation effort as a JSON dictionary
  <bucketnames>... # Optional list of space-separated bucket names to specifically target, overrides the default behavior of targeting all buckets in account
  --force          # Optionally force the application of the default encryption policy, even if the bucket already has a different default encryption policy

Examples:
  $ s3-bucket-default-encryption audit --accounts=dev,qa,prd --filename=default-encryption-audit.txt
  $ s3-bucket-default-encryption audit bucket1 bucket2 bucket3 bucket4

"""
from docopt import docopt
args = docopt(__doc__)

import boto3
import botocore
import json
import datetime
import os

if args['-h']==True or args['--help']==True:
    print(__doc__)

ABORT = False
if args['audit']==True:
    mode = 'audit'
elif args['apply']==True:
    mode = 'apply'
else:
    print('No mode specified')
    ABORT = True

if args['--accounts']:
    accounts = args['--accounts'].split(',')
else:
    if 'AWS_PROFILE' in os.environ:
        accounts = os.environ['AWS_PROFILE'].split(',')
    else:
        print('You did not specify --accounts and also do not have AWS_PROFILE exported to environmental variables')
        ABORT = True

if args['<bucket_names>']:
    target_buckets = args['<bucket_names>']
else:
    target_buckets = []

if args['--filename']!=None:
    filename = args['--filename']
else:
    filename = ''

if args['--kms']!=None:
    target_encryption = {
        'Rules': [
            {
                'ApplyServerSideEncryptionByDefault': {
                    'SSEAlgorithm': 'aws:kms',
                    'KMSMasterKeyID': args['--kms']
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

def load_file(filename, purpose):
    try:
        file = open(filename, 'r')
    except Exception as e:
        print(e)
    else:
        try:
            value = json.load(file)
        except Exception as e:
            print('Loading ' + purpose + ' file failed:')
            print(e)
            ABORT = True
        else:
            file.close()
            return value

if mode=='apply':
    lambda_env_var = load_file('lambda-env-variables.txt', 'Lambda Env Variables')
    if args['--kms']!=None:
        lambda_env_var['Variables']['DEFAULT_ENCRYPTION_KMS']=args['--kms']
    lamba_env_var_file = open('lambda-env-variables.txt', 'w')
    lamba_env_var_file.write(json.dumps(lambda_env_var,indent=4,separators=(',', ': ')))
    lamba_env_var_file.close()

def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()

def check_default_encryption(account, bucket):
    try:
        default_encryption = s3.get_bucket_encryption(Bucket=bucket['Name'])
    except Exception as e:
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            return False
        elif e.response['Error']['Code'] == 'AccessDenied':
            print(account + ' ' + bucket['Name'] + ' access denied while trying to check default encryption')
        else:
            print(account + ' ' + bucket['Name'] + ' error while trying to check default encryption:')
            print(e)
        return False
    else:
        if 'ServerSideEncryptionConfiguration' in default_encryption and 'Rules' in default_encryption['ServerSideEncryptionConfiguration']:
            if target_encryption == default_encryption['ServerSideEncryptionConfiguration']:
                return True
            else:
                return default_encryption['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']
        else:
            return False

def fix_default_encryption(account, bucket):
    try:
        s3.put_bucket_encryption(
            Bucket=bucket['Name'],
            ServerSideEncryptionConfiguration=target_encryption
        )
    except Exception as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            print(account + ' ' + bucket['Name'] + ': access denied while trying to apply default encryption policy')
        else:
            print(account + ' ' + bucket['Name'] + ': error while while trying to apply default encryption policy')
            print(e)
        return False
    else:
        print(account + ' ' + bucket['Name'] + ':  default encryption policy ' + json.dumps(target_encryption['Rules'][0]['ApplyServerSideEncryptionByDefault']) + ' successfully added.')
        return True

s3_default_encryption = {}

if ABORT==False:
    for account in accounts:
        session = boto3.session.Session(profile_name=account) #set profile per account
        s3 = session.client('s3')

        if account not in s3_default_encryption:
            s3_default_encryption[account] = { 'Account':account, 'Buckets':[]}

        bucket_count=0
        try:
            bucketlist = s3.list_buckets() #Get list of all buckets in account
        except Exception as e:
            print(e)
        else:
            for bucket in bucketlist["Buckets"]:
                if not target_buckets or bucket['Name'] in target_buckets:
                    s3_default_encryption[account]['Buckets'].append({'Bucket':bucket['Name'],'DefaultEncryption':[]})
                    current_policy = check_default_encryption(account, bucket)
                    if current_policy == False:
                        if mode == 'audit':
                            print(account + ' ' + bucket['Name'] + ' does NOT have any default encryption policy')
                        if mode == 'apply':
                            if fix_default_encryption(account, bucket) == True:
                                s3_default_encryption[account]['Buckets'][bucket_count]['DefaultEncryption'] = target_encryption['Rules'][0]['ApplyServerSideEncryptionByDefault']
                    elif current_policy == True:
                        print(account + ' ' + bucket['Name'] + ' already has the target default encryption policy')
                        s3_default_encryption[account]['Buckets'][bucket_count]['DefaultEncryption'] = target_encryption['Rules'][0]['ApplyServerSideEncryptionByDefault']
                    else:
                        print(account + ' ' + bucket['Name'] + ' already has a default encryption policy of ' + json.dumps(current_policy) + ' but that does not match target policy ' + json.dumps(target_encryption['Rules'][0]['ApplyServerSideEncryptionByDefault']))
                        if mode == 'apply' and args['--force'] == True:
                            if fix_default_encryption(account, bucket) == True:
                                    s3_default_encryption[account]['Buckets'][bucket_count]['DefaultEncryption'] = target_encryption['Rules'][0]['ApplyServerSideEncryptionByDefault']
                            else:
                                s3_default_encryption[account]['Buckets'][bucket_count]['DefaultEncryption'] = current_policy
                        else:
                            s3_default_encryption[account]['Buckets'][bucket_count]['DefaultEncryption'] = current_policy
                    bucket_count += 1
    if filename:
        output_file = open(filename, 'w')
        output_file.write(json.dumps(s3_default_encryption,default=json_serial,indent=4,separators=(',', ': ')))