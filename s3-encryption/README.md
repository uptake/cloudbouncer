# cloudbouncer/s3-encryption
A series of command line tools to help you get to 100% S3 encryption at rest for an arbitrary number of accounts, buckets, and objects
Written in Python 2.7, using the AWS Python SDK Boto3

## Design
There are two components to ensuring S3 encryption at any time in your environment
1. Ensure all future objects uploaded to S3 are encrypted using default encryption policies applied to every bucket in your account
2. Ensure all current objects are audited, and if unencrypted, encrypt them

Scripts in this repository can you help you bring both your current and future buckets and objects into compliance for any number of accounts.
Scripts are invoked as command line tools using docopts argument parsing, ex `./s3-bucket-default-encryption.py --accounts=dev,qa,prd --kms=kmskeyid`
`--help` for any script will give you a list of the arguments, syntax, assumptions, limitations, and examples

Dependencies are:
- python 2.7
- boto3 `pip install boto3`
- docopts `pip install docopts`

### Assumptions:
You already have CloudTrail set up and configured to write to CloudWatch logs in all accounts/regions you want to monitor
You already have the infrastructure required to configure S3 inventory set up, S3 Inventory buckets in each region you have an S3 bucket you want to audit with bucket policeis that allow S3 Inventory to write to them.  These can either be in one account and receive inventories from all monitored account, or exist in each account
You are running this script with Admin-level credentials in each affected account, or have sufficient privileges to do all underlying operations (IAM role create/modify, cloudwatch rule create/modify, extensive S3, etc)
https://docs.aws.amazon.com/AmazonS3/latest/dev/storage-inventory.html is a great resource if you want to better understand what S3 Inventory is doing
https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html is the same for Default Encryption policies

## Future Objects - Stop the Bleeding
Stopping the bleeding requires having default encryption policies applied to all of your buckets.  This is accomplished in two ways:
1. Run [s3-bucket-default-encryption.py](s3-bucket-default-encryption.py) to apply encryption to all (or a subset of) existing buckets in your account, using a specified KMS key or the default SSE-AES256
2. Implement a Cloudtrail > CloudWatch > Lambda bot [s3-bucket-configuration-bot]((s3-bucket-default-encryption.py) to every region of every account that monitors for any new buckets (or changes to default encryption policies on existing ones) and applies default encryption to them


## Existing Objects - Cleanup
Cleaning up your (potentially large) set of existing buckets and objects that are not encrypted requires the setup of S3 Inventory policies on all of your buckets. Similar to above, this done by:
1. Run [s3-bucket-inventory-policy.py](s3-bucket-inventory-policy.py) to apply inventory policies to all (or a subset of) existing buckets in your account.
2. Implement a Cloudtrail > CloudWatch > Lambda bot [s3-bucket-configuration-bot](s3-bucket-default-encryption.py) to every region of every account that monitors for any new buckets (or changes to to existing ones) and applies the S3 Inventory policy to them
3. Download, analyze, and encrypt any unencrypted objects in your inventory files using [s3-object-encryption-cleanup.py](s3-object-encryption-cleanup.py).  This can take quite a while and some limitations and assumptions are outlined in the --help


## Recommended Implementation
1. Run [s3-bucket-inventory-policy.py](s3-bucket-inventory-policy.py) and [s3-bucket-default-encryption.py](s3-bucket-default-encryption.py) policy for each unique setup you need (for example, we use one set of inventory buckets in one audit account, so can do all buckets in all accounts in one run).  These scripts will store their latest inputs in the lambda-env-variables.txt file to use for deploying the bot.
2. Run [deploy-bot.py](deploy-bot.py) on `s3-bucket-configuration-bot` to bootstrap your Cloudwatch and Lambda deployments.  Make sure the check the environment variables and set any additional ones you want to use, like slack channels for notifications.  This can be done either command line via `./deploy-bot set-env-var` or by editing [lambda-env-variables.txt](lambda-env-variables.txt)
3. Wait for S3 Inventory to start publishing reports (can take up to 24hrs in my experience)
4. Run an audit of unencrypted objects using [s3-object-encryption-cleanup.py](s3-object-encryption-cleanup.py) `audit` to assess how much work you need to do
5. Design a plan for processing (large number of objects may warrant multiple resources processing in parallel) and provision those resources
6. Run an [s3-object-encryption-cleanup.py](s3-object-encryption-cleanup.py) `apply` to start encrypting objects!
7. Wait.  Potentially a long time depending on how many objects
8. Congratulations!  You've encrypted a bunch of objects at rest


