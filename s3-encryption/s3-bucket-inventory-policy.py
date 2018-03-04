#!/usr/bin/env python
"""
s3-bucket-inventory-policy: checks every bucket in account(s) and applies a S3 inventory policy configuration to each

Usage: 
  s3-bucket-inventory-policy audit [--accounts=<accounts>] [--inventory_account=<>] <inventory_buckets_prefix> <inventory_rule_name> <frequency> [--allversions] [--format=<>'] [--filename=<filename>] [<bucket_names>...]
  s3-bucket-inventory-policy apply [--accounts=<accounts>] [--inventory_account=<>] <inventory_buckets_prefix> <inventory_rule_name> <frequency> [--allversions] [--format=<>'] [--filename=<filename>] [<bucket_names>...]
  s3-bucket-inventory-policy -h | --help

Audit mode checks the current S3 Inventory Configuration rules for all buckets in each account, but will check a subset of buckets if provided in <bucket_names>
Apply mode will attempt to apply the target encryption policy to all buckets in each account by default, or a subset of buckets if specified

Arguments:
  --accounts=<>               # Optionally specify a comma-separated list of accounts to run in by your CLI profile names. Checks AWS_PROFILE env. variable if not set
  --inventory_account=<>      # Optionally, the accountID of the AWS account your S3 buckets live in. Otherwise uses current account    
  <inventory_buckets_prefix>  # the naming convention of your S3 buckets for each region, ie. 'org-s3inventory'
  <inventory_rule_name>       # the name of the S3 Inventory rule you are applying to target buckets    
  <frequency>                 # 'Daily' or 'Weekly', the current two options for S3 Inventory    
  --allversions               # Optionally specify each version of each object be reported for buckets with versioning enabled.  Defaults to only latest version    
  --format=<'CSV'|'ORC'>      # Optionally specify format of S3 Inventory reports, defaults to 'CSV'    
  --filename=<>               # Optionally specify a filename to output the results of the audit/remediation effort as a JSON dictionary
  <bucketnames>...            # Optional list of space-separated bucket names to specifically target, overrides the default behavior of targeting all buckets in account

Examples:
  $ export AWS_PROFILE=dev,qa,prd
  $ s3-bucket-inventory-policy audit uptake-s3inventory uptake-security-audit Daily --filename=inventory-policy-audit.txt
  $ s3-bucket-inventory-policy apply --accounts=dev uptake-s3inventory uptake-security-audit Daily --filename=inventory-policy-audit.txt

"""
from docopt import docopt
args = docopt(__doc__)

import boto3
import botocore
import json
import datetime
import os

if args['-h'] is True or args['--help'] is True:
	print(__doc__)

ABORT = False
if args['audit'] is True:
    mode = 'audit'
elif args['apply'] is True:
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

if args['<frequency>'] not in ['Weekly','Daily']:
	print('Invalid frequency, must be Weekly or Daily')
	ABORT = True

target_policy = {
	'Id': args['<inventory_rule_name>'],
	'InventoryConfiguration': {
		'Destination': {
            'S3BucketDestination': {
                'Format': 'CSV',
                'Encryption': {
                    'SSES3': {}
                }
            }
        },
        'IsEnabled': True,
        'Id': args['<inventory_rule_name>'],
        'IncludedObjectVersions': 'Current',
        'OptionalFields': [
            'Size','LastModifiedDate','StorageClass','ETag','IsMultipartUploaded','ReplicationStatus','EncryptionStatus',
        ],
	"Schedule": {"Frequency": args['<frequency>']},
	}
}

if args['--allversions'] is True:
	target_policy['InventoryConfiguration']['IncludedObjectVersions'] = 'All'

if args['--format'] is not None and args['--format'] in ['ORC', 'CSV']:
	target_policy['InventoryConfiguration']['Destination']['S3BucketDestination']['Format'] = args['--format']


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
        else:
            file.close()
            return value

# Load the specified variables for this set of accounts / regions into the lambda-env-variables.txt for use in bot deployment #
if mode == 'apply':
	lambda_env_var = load_file('lambda-env-variables.txt', 'Lambda Env Variables')
	lambda_env_var['Variables']['S3_INVENTORY_FREQUENCY'] = args['<frequency>']
	lambda_env_var['Variables']['S3_INVENTORY_RULE_NAME'] = args['<inventory_rule_name>']
	lambda_env_var['Variables']['S3_INVENTORY_BUCKET_PREFIX'] = args['<inventory_buckets_prefix>']

	if args['--allversions'] is True:
		lambda_env_var['Variables']['S3_INVENTORY_VERSIONING'] = 'All'
	else:
		lambda_env_var['Variables']['S3_INVENTORY_VERSIONING'] = 'Current'

	if args['--format'] is not None and args['--format'] in ['ORC', 'CSV']:
		lambda_env_var['Variables']['S3_INVENTORY_FORMAT'] = args['--format']
	else:
		lambda_env_var['Variables']['S3_INVENTORY_FORMAT'] = 'CSV'

	if args['--inventory_account'] is not None:
		lambda_env_var['Variables']['S3_INVENTORY_ACCOUNT'] = args['--inventory_account']

	lamba_env_var_file = open('lambda-env-variables.txt', 'w')
	lamba_env_var_file.write(json.dumps(lambda_env_var,indent=4,separators=(',', ': ')))
	lamba_env_var_file.close()


def check_for_s3_inventory():
	try:
		inventories = s3.list_bucket_inventory_configurations(
		    Bucket=bucket['Name'],
		)
	except Exception as e:
		print(e)
		return False
	else:
		if 'InventoryConfigurationList' in inventories:
			for inventory in inventories['InventoryConfigurationList']:
				if inventory == target_policy['InventoryConfiguration']:
					return True
	return False


def apply_s3_inventory():
	try:
		response = s3.put_bucket_inventory_configuration(**target_policy)
	except Exception as e:
		print(account + ' ' + bucket['Name'] + ' Error! S3 Inventory Policy not added:')
		print(e)
		return False
	else:
		print(account + ' ' + bucket['Name'] +  ' S3 Inventory Policy added, delivering inventory reports to ' + target_policy['InventoryConfiguration']['Destination']['S3BucketDestination']['Bucket'])
		return True

inventories = {}

if ABORT is False:
	for account in accounts:
		session = boto3.session.Session(profile_name=account)
		s3 = session.client('s3')
		inventories[account] = []

		if args['--inventory_account'] is not None:
			target_policy['InventoryConfiguration']['Destination']['S3BucketDestination']['AccountId'] = args['--inventory_account']
		else:
			target_policy['InventoryConfiguration']['Destination']['S3BucketDestination']['AccountId'] = session.client('sts').get_caller_identity()['Account']
		
		target_policy['InventoryConfiguration']['Destination']['S3BucketDestination']['Prefix'] = account

		try:
			bucketlist = s3.list_buckets()
		except Exception as e:
			print(e)
		else:
			for bucket in bucketlist["Buckets"]:
				if not target_buckets or bucket['Name'] in target_buckets:
					try:
						location = s3.get_bucket_location(Bucket=bucket['Name'])
					except Exception as e:
						print(e)
					else:
						if location['LocationConstraint'] is None:
							location = 'us-east-1'
						else:
							location = location['LocationConstraint']

						target_policy['Bucket'] = bucket['Name']
						target_policy['InventoryConfiguration']['Destination']['S3BucketDestination']['Bucket'] = 'arn:aws:s3:::' + args['<inventory_buckets_prefix>'] + '-' + location

						S3_inventory = check_for_s3_inventory()
						if S3_inventory == False:
							if mode == 'apply':
								S3_inventory = apply_s3_inventory()
								inventories[account].append({'Bucket':bucket['Name'],'S3 Inventory Enabled':S3_inventory})
							else:
								print(account + ' ' + bucket['Name'] + ' does NOT have S3 Inventory rule matching the desired one.')
						else:
							inventories[account].append({'Bucket':bucket['Name'],'S3 Inventory Enabled':S3_inventory})
							print(account + ' ' + bucket['Name'] + ' has an S3 Inventory rule matching the desired one.')

		if args['--filename'] is not None:
			output_file = open(args['--filename'], 'w')
			output_file.write(json.dumps(inventories,indent=4, separators=(',', ': ')))
