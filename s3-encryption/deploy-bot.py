#!/usr/bin/env python
"""
deploy-bot: lets you deploy a cloudwatch triggered lambda bot to all regions of all accounts with all dependencies

Usage: 
  deploy-bot deploy <botname> [--accounts=<> --iampolicy=<> --cloudwatchrule=<> --cron --multiregion --govcloud]
  deploy-bot update <botname> [--lambda --iam --cloudwatch --accounts=<> --multiregion --govcloud]
  deploy-bot delete <botname> [--accounts=<> --multiregion --govcloud]
  deploy-bot set-env-var <botname> [--slackwebhook=<> --slackchannel=<>]
  deploy-bot -h | --help

  set-env-var mode lets you optionally edit the lambda environment variables, you can also edit them in <botname>/lambda-env-variables.txt' file 
  Any variables not set will be omitted from lambda if not required, otherwise the deployment will fail.

Arguments for deploy:
  <botname>           # Name of the bot (assumes name.py for Lambda code file), and names all associated resources in all AWS services associated with it as botname
  --accounts=<>       # Optionally specify a comma-separated list of accounts to run in by your CLI profile names. Checks AWS_PROFILE env. variable if not set
  --iampolicy=<>      # Optionally specify the text file containing the IAM policy you want your Lambda function to use, in valid JSON, defaults to 'iampolicy.txt'
  --cloudwatchrule=<> # Optionally specify the text file containing the pattern you want your Cloudwatch Rule to use, in valid JSON, defaults to 'cloudwatchrule.txt'
  --multiregion       # Optionally specify that you want to deploy the bot to all current regions, defaults to False and uses AWS_REGION env. variable
  --cron              # Optional, set the cloudwatch trigger as a cron job instead of the default event pattern
  --lambda            # for update mode, update only the lambda code
  --iam               # for update mode, update only the IAM policy
  --cloudwatch        # for update mode, update only the cloudwatch rule
  --govcloud          # switches the provider in all arns from 'aws' to 'aws-us-gov'

Examples:
  $ deploy-bot s3-bucket-configuration-bot --accounts=dev,qa,prd --multiregion
  $ deploy-bot s3-bucket-configuration-bot set-env-var 

"""

from docopt import docopt
args = docopt(__doc__)

if args['-h'] is True or args['--help'] is True:
    print(__doc__)

import boto3
import json
import zipfile
import datetime
import time
import subprocess
import os
import multiprocessing

path = args['<botname>'] + '/'

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

if args['set-env-var'] is True:
    lambda_env_var = load_file(path+'lambda-env-variables.txt', 'Lambda Environment Variables')

    print('Enter new values for environment variables, press enter to keep current')
    for var in lambda_env_var['Variables']:
        print(var)
        print('\tDescription: ' + lambda_env_var['Help'][var])
        print('\tCurrent value: '+ lambda_env_var['Variables'][var])
        print('\tNew value: (enter to keep current)')
        new_value = raw_input()
        if new_value:
            lambda_env_var['Variables'][var] = new_value

    print('Lamba environment variables are now: ')
    print(json.dumps(lambda_env_var['Variables'], indent=4))

    lamba_env_var_file = open(path+'lambda-env-variables.txt', 'w')
    lamba_env_var_file.write(json.dumps(lambda_env_var,indent=4,separators=(',', ': ')))
    lamba_env_var_file.close()

    ABORT = True

if args['deploy'] is True or args['update'] is True or args['delete'] is True:
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
    name = args['<botname>']

    if args['--multiregion'] is True:
        multiregion = True
    else:
        multiregion = False
        region = os.environ['AWS_REGION']

    # Lambda Variables #
    current_code = path + name +'.py'
    runtime = 'python2.7'
    lambda_filename = path + name + '.py.zip'
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
        iam_filename = path + args['--iampolicy']
    else:
        iam_filename = path + 'iampolicy.txt'

    # Cloudwatch Variables #
    if args['--cloudwatchrule']:
        cloudwatch_filename = path + args['--cloudwatchrule']
    else:
        cloudwatch_filename = path + 'cloudwatchrule.txt'
    state = 'ENABLED'

    if args['deploy'] is True or args['update'] is True:
        # Test all the input files for validity #
        if validate_file(current_code) == True:
            subprocess.call('zip -j ' + lambda_filename + ' ' + current_code, shell=True)
        else:
            ABORT = True
        role_policy = load_file(iam_filename, 'IAM Role Policy')

        if args['--cron'] is not True:
            pattern = load_file(cloudwatch_filename, 'Cloudwatch Rule Pattern')
        else:
            try:
                file = open(cloudwatch_filename, 'r')
            except Exception as e:
                print(e)
            else:
                for rule in file:
                    pattern = rule

        load_variables = load_file(path+'lambda-env-variables.txt', 'Lambda Environment Variables')
        possible_variables = [x for x in load_variables['Variables']]
        if 'Variables' in load_variables:
            for key in possible_variables:
                if load_variables['Variables'][key] == 'string':
                    load_variables['Variables'].pop(key, None)
        lambda_environment_variables = {'Variables':load_variables['Variables']}

def create_iam_role(account):
    iam = boto3.session.Session(profile_name=account).client('iam')

    if role_policy:
        try:
            response = iam.create_role(RoleName=name,Description=name,AssumeRolePolicyDocument=json.dumps(trust_policy))
        except Exception as e:
            if e.response['Error']['Code'] == 'EntityAlreadyExists':
                print(account + ' IAM role already exists')
            else:
                print(e)
        else:
            print(account + ' IAM role created')

            # Customer IAM Waiter since one doesn't exist for Roles
            role_exists = False
            while role_exists==False:
                try:
                    role_details = iam.get_role(RoleName=name)
                except Exception as e:
                    pass
                else:
                    if role_details['Role']:
                        role_exists = True
                time.sleep(15)

        # Add the actual policy to the the role
        try:
            response = iam.put_role_policy(RoleName=name,PolicyName=name,PolicyDocument=json.dumps(role_policy))
        except Exception as e:
            print(e)
        else:
            print(account + ' IAM policy updated')

def delete_iam_role(account):
    iam = boto3.session.Session(profile_name=account).client('iam')

    try:
        response = iam.delete_role_policy(RoleName=name,PolicyName=name)
    except Exception as e:
        print(e)
    else:
        try:
            response = iam.delete_role(RoleName=name)
        except Exception as e:
            print(e)
        else:
            print(account + ' IAM role deleted')


def create_lambda_function(f_args):
    account = f_args[0]
    region = f_args[1]
    roleArn = f_args[4]
    aws_lambda = boto3.session.Session(profile_name=account, region_name=region).client('lambda')

    if 'S3_INVENTORY_ACCOUNT' not in lambda_environment_variables['Variables']:
        lambda_environment_variables['Variables']['S3_INVENTORY_ACCOUNT'] = f_args[5]

    SUCCESS = False
    while SUCCESS is False:
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
                print(account + ' ' + region + ' lambda function already exists')
                update_lambda_function(f_args)
                SUCCESS = True
            else:
                print(e)
                time.sleep(5)
        else:
            print(account + ' ' + region + ' created lambda function ' + response['FunctionArn'])
            add_lambda_permissions(f_args)
            SUCCESS = True
        
def add_lambda_permissions(f_args):
    account = f_args[0]
    region = f_args[1]
    cloudwatch_arn = f_args[3]
    roleArn = f_args[4]
    aws_lambda = boto3.session.Session(profile_name=account, region_name=region).client('lambda')
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
            print(account + ' ' + region + ' lambda invoke permissions already exist, did not update')
            # If updates to permissions ever are needed, add here
        else:
            print(account + ' ' + region + ' failed to add lambda trigger permissions from CloudWatch to Lambda function')
            print(e)
    else:
        print(account + ' ' + region + ' updated lambda function permissions to allow CloudWatch triggers')

def update_lambda_function(f_args):
    account = f_args[0]
    region = f_args[1]
    cloudwatch_arn = f_args[3]
    roleArn = f_args[4]
    
    if 'S3_INVENTORY_ACCOUNT' not in lambda_environment_variables['Variables']:
        lambda_environment_variables['Variables']['S3_INVENTORY_ACCOUNT'] = f_args[5]

    aws_lambda = boto3.session.Session(profile_name=account, region_name=region).client('lambda')

    # Update code:
    try:
        aws_lambda.update_function_code(
            FunctionName=name,
            ZipFile=open(lambda_filename,'rb').read(),
            Publish=True
        )
    except Exception as e:
        print(e)
    else:
        print(account + ' ' + region + ' updated lambda function to latest code')
    
    # Update the configuration including environment variables
    try:
        aws_lambda.update_function_configuration(
            FunctionName=name,
            Handler=handler,
            Environment=lambda_environment_variables,
        )
    except Exception as e:
        print(e)
    else:
        print(account + ' ' + region + ' updated lambda function configuration')

    # Update cloudwatch trigger permissions
    add_lambda_permissions(f_args)
    
def delete_lambda_function(f_args):
    account = f_args[0]
    region = f_args[1]
    aws_lambda = boto3.session.Session(profile_name=account, region_name=region).client('lambda')
    try:
        aws_lambda.delete_function(FunctionName=name)
    except Exception as e:
        print(e)
    else:
        print(account + ' ' + region + ' lambda function deleted')

def create_cloudwatch_targets(f_args):
    account = f_args[0]
    region = f_args[1]
    lambda_arn = f_args[2]
    cw = boto3.session.Session(profile_name=account, region_name=region).client('events')
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
        print(account + ' ' + region + ' cloudwatch rule target lambda updated')

def create_cloudwatch_rule(f_args):
    account = f_args[0]
    region = f_args[1]
    cw = boto3.session.Session(profile_name=account, region_name=region).client('events')

    # set the arguments based on whether the cloudwatch rule is a cron schedule or event pattern
    cloudwatch_args = {
        "Name":name,
        "State":state,
        "Description":name
    }
    if args['--cron'] is True:
        cloudwatch_args["ScheduleExpression"] = pattern
    else:
        cloudwatch_args["EventPattern"] = json.dumps(pattern)

    try:
        new_rule = cw.put_rule(**cloudwatch_args)
    except Exception as e:
        print(e)
    else:
        print(account + ' ' + region + ' cloudwatch rule updated')
        create_cloudwatch_targets(f_args)

def delete_cloudwatch_rule(f_args):
    account = f_args[0]
    region = f_args[1]
    cw = boto3.session.Session(profile_name=account, region_name=region).client('events')

    try:
        cw.remove_targets(Rule=name,Ids=[name])
    except Exception as e:
        print(e)
    else:
        try:
            new_rule = cw.delete_rule(Name=name)
        except Exception as e:
            print(e)
        else:
            print(account + ' ' + region + ' cloudwatch rule targets removed and rule deleted')

if ABORT is False: # If everything looks good, try to deploy #
    pool = multiprocessing.Pool()

    if args['deploy'] is True or args['--iam'] is True:
        pool.map(create_iam_role,accounts)
    if args['delete'] is True:
        pool.map(delete_iam_role,accounts)

    targets = []
    for account in accounts:
        session = boto3.session.Session(profile_name=account) #set profile per account
        account_num = session.client('sts').get_caller_identity()['Account']
        if multiregion == True:
            regions = session.client('ec2').describe_regions()
        else:
            regions = {'Regions':[{'RegionName':region}]}
        for region in regions['Regions']:
            region = region['RegionName']
            if args['--govcloud'] is True:
                provider = 'aws-us-gov'
            else:
                provider = 'aws'

            lambda_arn = 'arn:'+provider+':lambda:' + region + ':' + account_num + ':function:' + name
            cloudwatch_arn = 'arn:'+provider+':events:' + region + ':' + account_num + ':rule/' + name
            roleArn = 'arn:'+provider+':iam::' + account_num + ':role/' + name

            targets.append([account,region,lambda_arn,cloudwatch_arn,roleArn,account_num])

    if args['deploy'] is True or args['--lambda'] is True:
        pool.map(create_lambda_function,targets)        
        subprocess.call('rm '+ lambda_filename, shell=True)

    if args['deploy'] is True or args['--cloudwatch'] is True:
        pool.map(create_cloudwatch_rule,targets)

    if args['delete'] is True:
        pool.map(delete_cloudwatch_rule,targets)
        pool.map(delete_lambda_function,targets)