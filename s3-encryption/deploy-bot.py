#!/usr/bin/env python
"""
deploy-bot: lets you deploy a cloudwatch triggered lambda bot to all regions of all accounts with all dependencies

Usage: 
  deploy-bot deploy <botname> [--accounts=<>] [--iampolicy=<>] [--cloudwatchrule=<>] [--multiregion]
  deploy-bot set-env-var [--slackwebhook=<>] [--slackchannel=<>] [--kms=<>] [--inventory_account=<>] [--inventory_buckets_prefix=<>] [--inventory_rule_name=<>] [--frequency=<>] [--allversions] [--format=<>']
  deploy-bot -h | --help

  set-env-var mode lets you optionally edit the lambda environment variables that were stored the last time you applied either default encryption or inventory policies
  Running 'set-env-var' with no parameters will output the current environment variables.  You can also edit them in the 'lambda-env-variables.txt' file
  Any variables not set will be omitted from lambda if not required, otherwise it will fail:
    "SLACK_WEBHOOK", # Optional, will output to CloudWatch logs if not present
    "SLACK_CHANNEL", # Optional, will output to CloudWatch logs if not present.   
    "DEFAULT_ENCRYPTION_KMS", # Optional kmskeyid, defaults to SSE-AES256 if not set
    "S3_INVENTORY_ACCOUNT", # Optional accountID, assumes your inventory buckets are in this account if not set.   
    "S3_INVENTORY_BUCKET_PREFIX", # Required
    "S3_INVENTORY_RULE_NAME", #Required
    "S3_INVENTORY_FREQUENCY", # Required, "Daily" | "Weekly"
    "S3_INVENTORY_FORMAT", #Required, "CSV" | "ORC"
    "S3_INVENTORY_VERSIONING", #Required, "Current" | "All"

Arguments for deploy:
  <botname>           # Name of the bot (assumes name.py for Lambda code file), and names all associated resources in all AWS services associated with it as botname
  --accounts=<>       # Optionally specify a comma-separated list of accounts to run in by your CLI profile names. Checks AWS_PROFILE env. variable if not set
  --iampolicy=<>      # Optionally specify the text file containing the IAM policy you want your Lambda function to use, in valid JSON, defaults to 'iampolicy.txt'
  --cloudwatchrule=<> # Optionally specify the text file containing the pattern you want your Cloudwatch Rule to use, in valid JSON, defaults to 'cloudwatchrule.txt'
  --multiregion       # Optionally specify that you want to deploy the bot to all current regions, defaults to False and uses AWS_REGION env. variable
  
Examples:
  $ deploy-bot s3-bucket-configuration-bot --accounts=dev,qa,prd --multiregion
  $ deploy-bot set-env-var 
  $ deploy-bot set-env-var --slackwebhook=webhookurl --slackchannel=#channelname --kms=kmskeyid --inventory_account=123456789 --inventory_buckets_prefix=myorg-s3inventory --inventory_rule_name=audit --frequency=Daily


"""
from docopt import docopt
args = docopt(__doc__)

if args['-h']==True or args['--help']==True:
    print(__doc__)

import boto3
import json
import zipfile
import datetime
import time
import subprocess
import os

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

def validate_file(filename):
	try:
		results_file = open(filename, 'r')
	except Exception as e:
		print('Loading Lambda code file ' + filename + ' failed, aborted')
		print(e)
		return False
	else:
		results_file.close()
		return True

possible_environment_variables = [
	"SLACK_WEBHOOK", # Optional, will output to CloudWatch logs if not present
	"SLACK_CHANNEL", # Optional, will output to CloudWatch logs if not present
	"DEFAULT_ENCRYPTION_KMS", # Optional kmskeyid, defaults to SSE-AES256 if not set
	"S3_INVENTORY_ACCOUNT", # Optional accountID, assumes your inventory buckets are in this account if not set
	"S3_INVENTORY_BUCKET_PREFIX", # Required
	"S3_INVENTORY_RULE_NAME", #Required
	"S3_INVENTORY_FREQUENCY", # Required, "Daily" | "Weekly"
	"S3_INVENTORY_FORMAT", #Required, "CSV" | "ORC"
	"S3_INVENTORY_VERSIONING", #Required, "Current" | "All"
]

if args['set-env-var'] == True:
	lambda_env_var = load_file('lambda-env-variables.txt', 'Lambda Environment Variables')

	print('Lambda environment variables were: ')
	print(json.dumps(lambda_env_var, indent=4))

	if args['--slackwebhook'] is not None:
		lambda_env_var['Variables']['SLACK_WEBHOOK'] = args['--slackwebhook']

	if args['--slackchannel'] is not None:
		lambda_env_var['Variables']['SLACK_CHANNEL'] = args['--slackchannel']

	if args['--kms'] is not None:
		lambda_env_var['Variables']['DEFAULT_ENCRYPTION_KMS']=args['--kms']

	if args['--allversions']==True:
		lambda_env_var['Variables']['S3_INVENTORY_VERSIONING'] = 'All'
	else:
		lambda_env_var['Variables']['S3_INVENTORY_VERSIONING'] = 'Current'

	if args['--format'] is not None and args['--format'] in ['ORC', 'CSV']:
		lambda_env_var['Variables']['S3_INVENTORY_FORMAT'] = args['--format']
	else:
		lambda_env_var['Variables']['S3_INVENTORY_FORMAT'] = 'CSV'

	if args['--inventory_account'] is not None:
		lambda_env_var['Variables']['S3_INVENTORY_ACCOUNT'] = args['--inventory_account']

	if args['--frequency'] is not None:
		lambda_env_var['Variables']['S3_INVENTORY_FREQUENCY'] = args['--frequency']

	if args['--inventory_rule_name'] is not None:
		lambda_env_var['Variables']['S3_INVENTORY_RULE_NAME'] = args['--inventory_rule_name']

	if args['--inventory_buckets_prefix'] is not None:
		lambda_env_var['Variables']['S3_INVENTORY_BUCKET_PREFIX'] = args['inventory_buckets_prefix']

	print('Lamba environment variables are now: ')
	print(json.dumps(lambda_env_var, indent=4))

	lamba_env_var_file = open('lambda-env-variables.txt', 'w')
	lamba_env_var_file.write(json.dumps(lambda_env_var,indent=4,separators=(',', ': ')))
	lamba_env_var_file.close()

	ABORT = True

if args['deploy'] == True:
	ABORT = False

	if args['--accounts']:
	    accounts = args['--accounts'].split(',')
	else:
	    if 'AWS_PROFILE' in os.environ:
	        accounts = os.environ['AWS_PROFILE'].split(',')
	    else:
	        print('You did not specify --accounts and also do not have AWS_PROFILE exported to environmental variables')
	        ABORT = True

	# Shared variables
	name = args['<botname>']   # 's3_bucket_configuration_audit_bot'

	if args['--multiregion']==True:
		multiregion = True
	else:
		multiregion = False
		region = os.environ['AWS_REGION']

	# Lambda Variables #
	current_code = name +'.py'
	runtime = 'python2.7'
	lambda_filename = name + '.py.zip'
	handler = name + '.handler'
	timeout = 300
	publish = True

	# IAM Variables #
	trust_policy = {
	  "Version": "2012-10-17",
	  "Statement": [
	    {
	      "Effect": "Allow",
	      "Principal": {
	        "Service": "lambda.amazonaws.com"
	      },
	      "Action": "sts:AssumeRole"
	    }
	  ]
	}

	if args['--iampolicy'] is not None:
		iam_filename = args['--iampolicy']
	else:
		iam_filename = 'iampolicy.txt'

	# Cloudwatch Variables #
	if args['--cloudwatchrule']:
		cloudwatch_filename = args['--cloudwatchrule']
	else:
		cloudwatch_filename = 'cloudwatchrule.txt'
	state = 'ENABLED'

	# Test all the input files for validity #
	if validate_file(current_code) == True:
		subprocess.call('zip ' + lambda_filename + ' ' + current_code, shell=True)
	else:
		ABORT = True
	role_policy = load_file(iam_filename, 'IAM Role Policy')
	pattern = load_file(cloudwatch_filename, 'Cloudwatch Rule Pattern')

	lambda_environment_variables = load_file('lambda-env-variables.txt', 'Lambda Environment Variables')
	for key in possible_environment_variables:
		if lambda_environment_variables['Variables'][key] == 'string':
			lambda_environment_variables['Variables'].pop(key, None)

def create_iam_role():
	if role_policy:
		try:
			response = iam.create_role(RoleName=name,Description=name,AssumeRolePolicyDocument=json.dumps(trust_policy))
		except Exception as e:
			if e.response['Error']['Code'] == 'EntityAlreadyExists':
				print('This IAM role already exists in account ' + account)
			else:
				print(e)
		else:
			print('Role ' + name + ' has been created in account ' + account + ', ARN: ' + response['Role']['Arn'])

			# Customer IAM Waiter since one doesn't exist for Roles
			role_exists = False
			while(False):
				try:
					role_details = iam.get_role(RoleName=name)
				except Exception as e:
					pass
				else:
					if role_details['Role']:
						role_exists = True
				time.sleep(1)

		# Add the actual policy to the the role
		try:
			response = iam.put_role_policy(RoleName=name,PolicyName=name,PolicyDocument=json.dumps(role_policy))
		except Exception as e:
			print(e)
		else:
			print('Updated policy for IAM role in account ' + account)

def create_lambda_function():
	try:
		response = aws_lambda.create_function(
			FunctionName=name,
			Runtime=runtime,
			Role=roleArn,
			Handler=handler,
			Code={'ZipFile':open(lambda_filename,'rb').read()},
			Description=name,
			Environment=lambda_environment_variables,
			Timeout=timeout,
			Publish=publish
		)
	except Exception as e:
		if e.response['Error']['Code'] == 'ResourceConflictException':
			print('Lambda function already exists in region ' + region + ' in account ' + account)
			update_lambda_function()
		else:
			print(e)
	else:
		print('Created lambda function in region ' + region + ' in account ' + account + ', ARN: ' + response['FunctionArn'])

def update_lambda_function():
	# Try to update code:
	try:
		aws_lambda.update_function_code(
			FunctionName=name,
			ZipFile=open(lambda_filename,'rb').read(),
			Publish=True
		)
	except Exception as e:
		print(e)
	else:
		print('Updated lambda function to latest code in region ' + region + ' in account ' + account)
	try:
		aws_lambda.update_function_configuration(
			FunctionName=name,
			Handler=handler,
			Environment=lambda_environment_variables,
		)
	except Exception as e:
		print(e)
	else:
		print('Updated lambda function configuration in region ' + region + ' in account ' + account)

	# Update triggers to include the cloudwatch rule
	try:
		permissions_added = aws_lambda.add_permission(
			FunctionName=name,
			StatementId=name,
			Action='lambda:InvokeFunction',
			Principal='events.amazonaws.com',
			SourceArn=cloudwatch_arn
		)
	except Exception as e:
		if 'Code' in e.response['Error'] and e.response['Error']['Code'] == 'ResourceConflictException':
			print('Lambda invoke permissions already exist, did not update')
			# If updates to permissions ever are needed, add here
		else:
			print('Failed to add lambda trigger permissions from CloudWatch to Lambda function in ' + region + ' in ' + account)
			print(e)
	else:
		print('Updated lambda function permissions for in region ' + region + ' in account ' + account + ' to allow CloudWatch triggers')

def create_cloudwatch_targets():
	try:
		targets = cw.put_targets(
			Rule=name,
			Targets=[
				{
					'Id':name,
					'Arn':lambda_arn
				}
			]
		)
	except Exception as e:
		print(e)
	else:
		print('Updated target lambda for cloudwatch rule ' + name + ' in region ' + region + ' in account ' + account)

def create_cloudwatch_rule():
	try:
		new_rule = cw.put_rule(
			Name=name,
			EventPattern=json.dumps(pattern),
			# ScheduleExpression=schedule,
			State=state,
			Description=name,
		)
	except Exception as e:
		print(e)
	else:
		print('Updated cloudwatch rule in region ' + region + ' in account ' + account + ', rule ARN = ' + new_rule['RuleArn'])
		create_cloudwatch_targets()

if ABORT == False: # If everything looks good, try to deploy #
	for account in accounts:
		session = boto3.session.Session(profile_name=account) #set profile per account
		iam = session.client('iam')
		account_num = session.client('sts').get_caller_identity()['Account']

		create_iam_role()
		roleArn = 'arn:aws:iam::' + account_num + ':role/' + name

		if 'S3_INVENTORY_ACCOUNT' not in lambda_environment_variables['Variables']:
			lambda_environment_variables['Variables']['S3_INVENTORY_ACCOUNT'] = account_num

		if multiregion == True:
			regions = boto3.session.Session(profile_name=account).client('ec2').describe_regions()
		else:
			regions = {'Regions':[{'RegionName':region}]}

		for region in regions['Regions']:
			region = region['RegionName']
			session = boto3.session.Session(profile_name=account, region_name=region) #set profile per account

			lambda_arn = 'arn:aws:lambda:' + region + ':' + account_num + ':function:' + name
			cloudwatch_arn = 'arn:aws:events:' + region + ':' + account_num + ':rule/' + name

			# Create Lambda Functions
			aws_lambda = session.client('lambda')
			create_lambda_function()	

			# Create CloudWatch Rules
			cw = session.client('events')		
			create_cloudwatch_rule()

