#!/usr/bin/env python
"""
s3-object-encryption-cleanup: checks a set of inventory buckets in account(s), downloads all inventories present for all buckets, and checks for the encryption state of all objects

Usage: 
  s3-object-encryption-cleanup audit <filename> [--accounts=<accounts>] [--buckets=<>] [--inventory_account=<profile_name>] <inventory_buckets_prefix> <inventory_rule_name> [--kms=<>] [--pedantic]
  s3-object-encryption-cleanup apply <filename> [--accounts=<accounts>] [--kms=<>] [--pedantic]
  s3-object-encryption-cleanup -h | --help

Audit mode lists all buckets (or a subset if specified) in target accounts, checks for a corresponding S3 Inventory manifest/inventory files, downloads them, parses them looking for unencrypted objects,
and builds a dictionary of all unencrypted objects in each account.  
It outputs two files: files_Unencrypted_Objects.txt with the dict of unencrypted objects, and filename_Summary.txt with bucket and account-level summaries.

Apply mode will parse the --filename_Unencrypted_Objects.txt file provided and attempt to encrypt every unencrypted object found, using python multiprocessor parallelization (so ctrl+c interupts don't work)
If you have more than 100,000 objects, I highly recommend doing this on a long-lived, detachable session on a robust EC2 instance with high network connectivity to AWS.  
This does not currently work for customer-provided keys but does for KMS-managed keys or SSE-AES256

Arguments:
  <filename>                  # Specify a filename prefix to output the results of the audit/remediation effort as a JSON dictionary
  --accounts=<>               # Optional list (comma-separated) of accounts to run in by your CLI profile names. Checks AWS_PROFILE env. variable if not set
  --buckets=<>                # Optional list (comma-separated) of bucket names to specifically target, overrides the default behavior of targeting all buckets in account
  --inventory_account=<>      # Optional CLI profile name of the AWS account your S3 Inventory Report buckets live in. Otherwise assumes inventory buckets in current account   
  <inventory_buckets_prefix>  # the naming prefix of your S3 buckets for each region, ie. 'org-s3inventory' becomes 'org-s3inventory-us-east-1', 'org-s3inventory-us-east-2', etc
  <inventory_rule_name>       # the name of the S3 Inventory rule you used when you applied S3 Inventory to target buckets
  --kms=<'kmskeyid'>          # Optional KMS key ID to use for both auditing and apply encryption (note, Inventory does not say which key specifically was used, only SSE vs KMS vs Customer)  
  --pedantic                  # Optional, if enabled, will attempt to re-encrypt anything using an encryption key other than the specified one, even if it's already encrypted at rest

Examples:
  $ s3-object-encryption-cleanup audit dev-audit --accounts=dev --inventory_account=123456789 myorg-s3inventory security-audit
  $ s3-object-encryption-cleanup audit dev-audit myorg-s3inventory security-audit
  $ s3-object-encryption-cleanup audit dev-audit myorg-s3inventory security-audit --buckets=bucket1,bucket2,bucket3,bucket4,bucket5

  $ s3-object-encryption-cleanup apply dev-audit --accounts=dev
  $ s3-object-encryption-cleanup apply dev-audit --accounts=dev --kms=kmskeyid1 --pedantic

"""

# Design:
#   List all buckets in account
#   List location of each bucket
#   If target buckets are set, check membership in target bucket set
#   Retrieve the manifest.json file(s) from the bucket:  region > account > bucketname > 'uptake-security-audit' > manifest.json, select most recent
#   Parse the manifest file to retrieve the filename from the manifest file
#   Download data file .gz, unzip, read .csv into memory, convert to dictionary
#   Check every object for a particular attribute, i.e. encryption, matching against designated keys
#   Build a list of non-compliant objects
#   Remediate as desired

from docopt import docopt
args = docopt(__doc__)

import boto3
import json
import datetime
import gzip
import csv
import urllib
import multiprocessing
import os
from itertools import izip as zip #can use native zip in 3

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

if args['--buckets'] is not None:
    target_buckets = args['--buckets'].split(',')
else:
    target_buckets = []

filename = args['<filename>'] + '_Unencrypted_Objects.txt'
summary_filename = args['<filename>'] + '_Summary.txt'


if args['--kms'] is not None:
    target_encryption = 'SSE-KMS'
    encryption_key = args['--kms']
else:
    target_encryption = 'SSE-S3'


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()


def get_manifest_file(function_args):
	bucketname = function_args[0]
	inventory_bucket = function_args[1]
	bucket_prefix = function_args[2]
	account = function_args[3]

	s3 = boto3.session.Session(profile_name=args['--inventory_account']).client('s3')

	last_modified_manifest = {}
	last_modified = datetime.datetime.today()- datetime.timedelta(days=7)
	try:
		objects = s3.list_objects_v2(
			Bucket=inventory_bucket,
			Prefix=bucket_prefix,
		)
	except Exception as e:
		print(account + ' ' + bucketname + ' Error listing objects: ')
		print(e)
		analyze_no_manifest([bucketname, account])
		return {'bucket':bucketname, 'manifest':'Error'}
	else:
		if 'Contents' in objects:
			for obj in objects['Contents']:
				if obj['Key'][-13:] == 'manifest.json':
					if obj['LastModified'].replace(tzinfo=None) > last_modified.replace(tzinfo=None):
						last_modified = obj['LastModified']
						last_modified_manifest = obj
			if last_modified_manifest:
				manifest_location = last_modified_manifest['Key']

				local_manifest_filename = 'Inventories/'+bucketname+'-manifest.json'
				try:
					manifest = s3.download_file(inventory_bucket, manifest_location, local_manifest_filename)
				except Exception as e:
					print(account + ' ' + bucketname + ' Error downloading manifest')
					print(e)
				else:
					try:
						local_manifest_file = open(local_manifest_filename,'r')
					except Exception as e:
						print(e)
					else:
						try:
							manifest = json.load(local_manifest_file)
						except Exception as e:
							print(account + ' ' + bucketname + 'Error loading manifest')
							print(e)
						else:
							local_manifest_file.close()
							return {'bucket':bucketname, 'manifest':manifest, 'inventory_bucket':inventory_bucket}
			else:
				analyze_no_manifest([bucketname, account])
				return {'bucket':bucketname, 'manifest':'Error'}
		else:
			analyze_no_manifest([bucketname, account])
			return {'bucket':bucketname, 'manifest':'Error'}


def get_bucket_inventory(function_args):
	# parse actual inventory data file name
	bucketname = function_args[0]
	inventory_bucket = function_args[1]
	manifest = function_args[2]
	account = function_args[3]

	if args['--inventory_account'] is not None:
		s3 = boto3.session.Session(profile_name=args['--inventory_account']).client('s3')
	else:
		s3 = boto3.session.Session(profile_name=account).client('s3')

	inventory = []
	counter = 0

	for inventory_file in manifest['files']:
		inventory_s3_filename = inventory_file['key']
		local_inventory_filename = 'Inventories/'+bucketname+'-inventory_'+str(counter)+'.csv.gz'
		try:
			report = s3.download_file(inventory_bucket, inventory_s3_filename, local_inventory_filename)
		except Exception as e:
			print(bucketname + ' Error downloading remote inventory file')
			print(e)
			return {'bucket':bucketname, 'inventory':'Error'}
		else:
			try:
				local_inventory_file = gzip.open(local_inventory_filename,'r')
			except Exception as e:
				print(bucketname + ' Error opening local inventory file')
				print(e)
				return {'bucket':bucketname, 'inventory':'Error'}
			else:
				inventory_csv = csv.reader(local_inventory_file)

				for line in inventory_csv:
					inventory.append(line)
				local_inventory_file.close()
		counter += 1
	return {'bucket':bucketname, 'inventory':inventory, 'schema':manifest['fileSchema']}


def analyze_no_manifest(function_args):
	bucketname = function_args[0]
	account = function_args[1]
	s3_account = boto3.session.Session(profile_name=account).client('s3')

	try:
		objects_in_bucket = s3_account.list_objects_v2(Bucket=bucketname)
	except Exception as e:
		print(account + ' ' + bucketname + ': Error listing the objects:')
		print(e)
	else:
		if 'Contents' not in objects_in_bucket: # Bucket has objects
			print(account + ' ' + bucketname + ' is empty')
		else:
			print('Warning! ' + account + ' ' + bucketname + ' is not empty, but has no S3 inventory file.')


def check_encryption(function_args):
	bucketname = function_args[0] 
	account = function_args[1]
	inventory = function_args[2]
	schema = function_args[3].replace(" ","").split(',')

	bucket = schema.index('Bucket')
	key = schema.index('Key')
	size = schema.index('Size')
	storage_class = schema.index('StorageClass')
	encryption_state = schema.index('EncryptionStatus')
	# s3obj[0] = bucket, s3obj[1] = key, s3obj[2] = size, s3obj[5] = storage_class, s3obj[8]=encryption_state  # only holds for current version

	global summary_string
	num_objects_bucket = float(len(inventory))
	unencrypted_objects_bucket = 0
	unencrypted_objects_in_bucket = []

	for s3obj in inventory:
		if s3obj[encryption_state] == 'NOT-SSE':
			if s3obj[storage_class] != 'GLACIER' and s3obj[size] > 0:
				unencrypted_objects_bucket += 1
				unencrypted_objects_in_bucket.append({k:v for k,v in zip(schema,s3obj)})
		elif s3obj[encryption_state] != target_encryption:
			if args['--pedantic']==True:
				unencrypted_objects_bucket += 1
				unencrypted_objects_in_bucket.append({k:v for k,v in zip(schema,s3obj)})

	if unencrypted_objects_bucket > 0:
		if args['--pedantic']==True:
			print(account + ' ' + bucketname + ' has ' + str(unencrypted_objects_bucket) + ' unencrypted (or wrongly encrypted) objects, representing ' + str(unencrypted_objects_bucket/num_objects_bucket*100) + ' percent of objects in this bucket')
		else:
			print(account + ' ' + bucketname + ' has ' + str(unencrypted_objects_bucket) + ' unencrypted objects, representing ' + str(unencrypted_objects_bucket/num_objects_bucket*100) + ' percent of objects in this bucket')
		return {'account': account, 'unencrypted': unencrypted_objects_in_bucket, 'num_objects':num_objects_bucket}
	else:
		if args['--pedantic']==True:
			print(account + ' ' + bucketname + ' has no unencrypted (or wrongly encrypted) objects')
		else:
			print(account + ' ' + bucketname + ' has no unencrypted objects')
		return {'account': account, 'num_objects':num_objects_bucket}


def parallel_encryption_audit(function_args):
	bucketname = function_args[0]
	inventory_bucket = function_args[1]
	bucket_prefix = function_args[2]
	account = function_args[3]

	manifest = get_manifest_file([bucketname, inventory_bucket, bucket_prefix, account])
	if manifest['manifest'] != 'Error':
		inventory = get_bucket_inventory([bucketname,inventory_bucket, manifest['manifest'], account])
		if inventory['inventory'] != 'Error':
			bucket_results = check_encryption([bucketname, account, inventory['inventory'], inventory['schema']])
			return bucket_results


unencrypted_objects = {}
num_objects = {}

if ABORT is False and mode == 'audit':
	summary_string = ''
	pool = multiprocessing.Pool()
	buckets_to_analyze = []

	for account in accounts:
		s3_account = boto3.session.Session(profile_name=account).client('s3')

		unencrypted_objects[account] = []
		num_objects[account] = 0.0

		try:
			bucketlist = s3_account.list_buckets()
		except Exception as e:
			print(e)
		else:
			for bucket in bucketlist["Buckets"]:
				if not target_buckets or bucket['Name'] in target_buckets:
					try:
						location = s3_account.get_bucket_location(Bucket=bucket['Name'])
					except Exception as e:
						print(e)
					else:
						if location['LocationConstraint'] is None:
							location = 'us-east-1'
						else:
							location = location['LocationConstraint']
						inventory_bucket = args['<inventory_buckets_prefix>'] + '-' + location
						bucket_prefix = account + '/' + bucket['Name'] + '/' + args['<inventory_rule_name>']
						buckets_to_analyze.append([bucket['Name'], inventory_bucket, bucket_prefix, account])

	results = pool.map(parallel_encryption_audit, buckets_to_analyze)
	for result in results:
		if result:
			if 'num_objects' in result:
				num_objects[result['account']] += result['num_objects']
			if 'unencrypted' in result:
				for obj in result['unencrypted']:
					unencrypted_objects[result['account']].append(obj)

	for account in accounts:
		account_unencrypted_objects = len(unencrypted_objects[account])
		if args['--pedantic'] is True:
			if account_unencrypted_objects >0:
				summary_string += account + ' account has ' + str(account_unencrypted_objects) + ' unencrypted (or wrongly encrypted) objects as of ' + str(datetime.date.today().isoformat()) + ', representing ' + str(account_unencrypted_objects/num_objects[account]*100) + ' percent of the ' +  str(num_objects[account]) + ' objects in all S3 buckets in the account\n'
			else:
				summary_string += account + ' account has no unencrypted (or wrongly encrypted) objects as of ' + str(datetime.date.today().isoformat()) + ', representing 0 percent of the ' +  str(num_objects[account]) + ' objects in all S3 buckets in the account\n'
		else:
			if account_unencrypted_objects >0:
				summary_string += account + ' account has ' + str(account_unencrypted_objects) + ' unencrypted objects as of ' + str(datetime.date.today().isoformat()) + ', representing ' + str(account_unencrypted_objects/num_objects[account]*100) + ' percent of the ' +  str(num_objects[account]) + ' objects in all S3 buckets in the account\n'
			else:
				summary_string += account + ' account has no unencrypted objects as of ' + str(datetime.date.today().isoformat()) + ', representing 0 percent of the ' +  str(num_objects[account]) + ' objects in all S3 buckets in the account\n'

	output_file = open(filename, 'w')
	output_file.write(json.dumps(unencrypted_objects))

	print('\n\n'+summary_string)
	summary = open(summary_filename, 'w')
	summary.write(summary_string)


def parallel_encryption_enforcement(function_args):
	account = function_args[0]
	s3object = function_args[1]

	s3_account = boto3.session.Session(profile_name=account).client('s3')
	try:
		object_metadata = s3_account.head_object(Bucket=s3object['Bucket'],Key=s3object['Key'])
	except Exception as e:
		# Figure out how to silence 404 errors for deleted objects
		print('An error occured when trying to retrieve the metadata for ' + s3object['Key'] + ' in bucket ' + s3object['Bucket'])
		print(e)
		return {'s3object':s3object, 'status':'error'}
	else:
		if s3object['Size'] <= 5368709120:
			if check_for_encryption_realtime(object_metadata, s3object['Key'], s3object['Bucket']) is False:		
				if s3object_set_encryption(s3_account, object_metadata, s3object['Key'], s3object['Bucket']) is False:
					return {'s3object':s3object, 'status':'error'}
				else:
					return {'s3object':s3object, 'status':'encrypted'}
			elif check_for_encryption_realtime(object_metadata, s3object['Key'], s3object['Bucket']) == 'pseudo':
				if s3object_set_encryption_large(s3_account, object_metadata, s3object['Key'], s3object['Bucket']) is False:
					return {'s3object':s3object, 'status':'error'}
				else:
					return {'s3object':s3object, 'status':'encrypted'}
			else:
				return {'s3object':s3object, 'status':'encrypted'}
		else:
			if check_for_encryption_realtime(object_metadata, s3object['Key'], s3object['Bucket']) is False:		
				if s3object_set_encryption_large(s3_account, object_metadata, s3object['Key'], s3object['Bucket']) is False:
					return {'s3object':s3object, 'status':'error'}
				else:
					return {'s3object':s3object, 'status':'encrypted'}
			elif check_for_encryption_realtime(object_metadata, s3object['Key'], s3object['Bucket']) == 'pseudo' and args['--pedantic'] is True:
				if s3object_set_encryption_large(s3_account, object_metadata, s3object['Key'], s3object['Bucket']) is False:
					return {'s3object':s3object, 'status':'error'}
				else:
					return {'s3object':s3object, 'status':'encrypted'}
			else:
				return {'s3object':s3object, 'status':'encrypted'}


def check_for_encryption_realtime(object_metadata, s3objectkey, bucketname):
	if 'StorageClass' in object_metadata:
		if object_metadata['StorageClass'] == 'GLACIER':
			return True # All objects in Glacier have SSE by default, even if they didn't when archived
	if 'ContentLength' in object_metadata and object_metadata['ContentLength'] == 0:
		return True # fake navigational objects made prior to default encryption might not be encrypted, but can't be copied
	if 'ServerSideEncryption' not in object_metadata:
		return False
	else:
		if object_metadata['ServerSideEncryption'] == 'AES256' and target_encryption == 'SSE-S3':
			return True
		elif object_metadata['ServerSideEncryption'] == 'aws:kms'  and target_encryption == 'SSE-KMS' and object_metadata['SSEKMSKeyId'] == encryption_key:
			return True
		else:
			return 'pseudo'


def s3object_set_encryption(s3_account, object_metadata, s3objectkey, bucketname):
	# Retain storage class if set
	if 'StorageClass' in object_metadata:
		storageclass = object_metadata['StorageClass']
	else:
		storageclass = 'STANDARD'

	# copy_object does not retain existing object ACL, need to capture + set
	try:
		current_acl = s3_account.get_object_acl(Bucket=bucketname,Key=s3objectkey)
	except Exception as e:
		print(bucketname + ' error getting object ACL on ' + s3objectkey)
		print(e)
	else:
		new_acl = {'Grants':current_acl['Grants'], 'Owner':current_acl['Owner']}

	copy_object_parameters = {
		'Bucket':bucketname,
		'CopySource': { 'Bucket':bucketname, 'Key':s3objectkey },
		'Key':s3objectkey,
		'MetadataDirective':'COPY',
		'TaggingDirective':'COPY',
		'StorageClass':storageclass
	}
	if target_encryption == 'SSE-S3':
		copy_object_parameters['ServerSideEncryption']='AES256'
	elif target_encryption == 'SSE-KMS':
		copy_object_parameters['ServerSideEncryption']='aws:kms'
		copy_object_parameters['SSEKMSKeyId']=encryption_key

	try:
		set_encryption = s3_account.copy_object(**copy_object_parameters)
	except Exception as e:
		print(bucketname + ' error setting encryption on ' + s3objectkey)
		print(e)
		return False
	else:
		# Copy object worked, try to set new ACL:
		try:
			s3_account.put_object_acl(AccessControlPolicy=new_acl, Bucket=bucketname, Key=s3objectkey)
		except Exception as e:
			print(bucketname + ' error putting object ACL on ' + s3objectkey)
			print(e)
		# Regardless of putACL, still return status of encryption
		if 'ServerSideEncryption' in set_encryption: 
			return True
		else:
			return False


def s3object_set_encryption_large(s3_account, object_metadata, s3objectkey, bucketname):
	# Retain storage class if set
	if 'StorageClass' in object_metadata:
		storageclass = object_metadata['StorageClass']
	else:
		storageclass = 'STANDARD'

	# copy_object does not retain existing object ACL, need to capture + set
	try:
		current_acl = s3_account.get_object_acl(Bucket=bucketname,Key=s3objectkey)
	except Exception as e:
		print(bucketname + ' error getting object ACL on ' + s3objectkey)
		print(e)
	else:
		new_acl = {'Grants':current_acl['Grants'], 'Owner':current_acl['Owner']}

	# get tags because S3.copy TaggingDirective doesn't exist
	try:
		tags = s3_account.get_object_tagging(
		    Bucket=bucketname,
		    Key=s3objectkey,
		)
	except Exception as e:
		print(e)

	config = boto3.s3.transfer.TransferConfig(
		multipart_threshold=8388608,
		max_concurrency=10,
		multipart_chunksize=8388608,
		num_download_attempts=5,
		max_io_queue=100,
		io_chunksize=262144,
		use_threads=True
	)

	large_copy_extra_args={
		'MetadataDirective':'COPY',
		'StorageClass':storageclass
	}

	if target_encryption == 'SSE-S3':
		large_copy_extra_args['ServerSideEncryption']='AES256'
	elif target_encryption == 'SSE-KMS':
		large_copy_extra_args['ServerSideEncryption']='aws:kms'
		large_copy_extra_args['SSEKMSKeyId']=encryption_key

	try:
		set_encryption = s3_account.copy(
			Bucket=bucketname,
	    	Key=s3objectkey,
	    	CopySource={ 'Bucket': bucketname, 'Key':s3objectkey },
	    	ExtraArgs=large_copy_extra_args,
	    	Config=config
		)
	except Exception as e:
		print(bucketname + ' error setting encryption on large object ' + s3objectkey)
		print(e)
		return False
	else:				
		# Copy object worked, set new ACL:
		try:
			s3_account.put_object_acl(AccessControlPolicy=new_acl, Bucket=bucketname, Key=s3objectkey)
		except Exception as e:
			print(bucketname + ' error setting object ACL on newly encrypted object ' + s3objectkey)
			print(e)
		else:
			pass

		# No TaggingDirective on S3.copy command, so need to separately capture capture original object tags and store on new one
		if tags['TagSet']:
			try:
				new_tags = s3_account.put_object_tagging(
				    Bucket=bucketname,
				    Key=s3objectkey,
				    Tagging=tags
				)
			except Exception as e:
				print(e)

		try:
			object_metadata = s3_account.head_object(Bucket=bucketname,Key=s3objectkey)
		except Exception as e:
			print(bucketname + ' error occured when trying to retrieve the metadata for ' + s3objectkey)
			print(e)
			return False
		else:
			if check_for_encryption_realtime(object_metadata, s3objectkey, bucketname) is False:
				return False
			else:
				return True


if ABORT is False and mode == 'apply':
	summary_string = ''
	try:
		results = open(filename, 'r')
	except Exception as e:
		print(e)
	else:
		try:
			unencrypted_objects = json.load(results)
		except Exception as e:
			print(e)
		else:
			results.close()

			number_unencrypted = 0
			new_unencrypted_objects = {}
			pool = multiprocessing.Pool()

			for account in unencrypted_objects:
				encrypted_count = 0
				error_count = 0	
				skipped_count = 0

				if account in accounts:
					number_unencrypted_account = len(unencrypted_objects[account])
					number_unencrypted += number_unencrypted_account

					target_objects = []
					for s3object in range(len(unencrypted_objects[account])):
						unencrypted_objects[account][s3object]['Key'] = urllib.unquote_plus(unencrypted_objects[account][s3object]['Key'].encode('utf8'))
						target_objects.append([account, unencrypted_objects[account][s3object]])

					new_unencrypted_objects[account] = []
					results = pool.map(parallel_encryption_enforcement, target_objects)
					
					for result in results:
						if result['status'] == 'encrypted':
							encrypted_count += 1
						elif result['status'] == 'error':
							error_count += 1
							new_unencrypted_objects[account].append(result['s3object'])
						elif result['status'] == 'pseudo':
							if args['--pedantic'] is True:
								error_count += 1
								new_unencrypted_objects[account].append(result['s3object'])

					print('Successfully encrypted ' + str(encrypted_count) + ' objects out of ' + str(number_unencrypted_account) + ' in account ' + account + ', ' + str(error_count) + ' errors, ' + str(skipped_count) + ' skipped.')
					summary_string+='Successfully encrypted ' + str(encrypted_count) + ' objects out of ' + str(number_unencrypted_account) + ' in account ' + account + ', ' + str(error_count) + ' errors, ' + str(skipped_count) + ' skipped.\n'
				else:
					new_unencrypted_objects[account] = unencrypted_objects[account]
					number_unencrypted_account = len(unencrypted_objects[account])
					number_unencrypted += number_unencrypted_account
					skipped += number_unencrypted_account
					if number_unencrypted_account > 0:
						summary_string+='Successfully encrypted ' + str(encrypted_count) + ' objects out of ' + str(number_unencrypted_account) + ' in account ' + account + ', ' + str(error_count) + ' errors, ' + str(skipped_count) + ' skipped.\n'
						
			output_file = open(filename, 'w')
			output_file.write(json.dumps(new_unencrypted_objects))

	print('\n\n' + summary_string)
