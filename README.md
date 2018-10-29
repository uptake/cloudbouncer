# cloudbouncer
A series of command line tools to used by the Uptake Cloud Security team to scale our security configurations
Written in Python 2.7, using the AWS Python SDK Boto3


## s3-encryption
Get to 100% S3 encryption at rest for an arbitrary number of existing and future accounts, buckets, and objects
Includes:
    s3-bucket-configuration-bot: a cloudwatch-triggered lambda bot that checks every new or changed bucket in your account and ensure it is encrypted, has inventory enabled, and is not public
    s3-bucket-default-encryption: a CLI tool to audit all existing buckets in your accounts to check that they have default encryption policies
    s3-bucket-inventory-policy: a CLI tool to audit all existing buckets in your accounts to check that they have S3 inventory policies
    s3-object-encryption-cleanup: a CLI tool to encrypt existing objects in your buckets

## network-map
Build a logical model of your AWS networks and simulate connectivity to debug / check configurations across the various AWS network configurations
