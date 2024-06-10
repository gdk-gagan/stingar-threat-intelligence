import boto3

s3_resource = boto3.resource('s3')
print(s3_resource)

# code to create a random id for naming buckets
import uuid
def create_bucket_name(bucket_prefix):
    # The generated bucket name must be between 3 and 63 chars long
    return ''.join([bucket_prefix, str(uuid.uuid4())])

# create bucket and pass region using session
def create_bucket(bucket_prefix, s3_connection):
    session = boto3.session.Session()
    current_region = session.region_name
    print(f"Current region : {current_region}")
    bucket_name = create_bucket_name(bucket_prefix)
    bucket_response = s3_connection.create_bucket(
        Bucket=bucket_name,
        CreateBucketConfiguration={
        'LocationConstraint': current_region})
    print(bucket_name, current_region)
    return bucket_name, bucket_response

bucket_name, bucket_response = create_bucket(bucket_prefix='stingar-all-events', 
                                                    s3_connection=s3_resource)
print(bucket_response)

# upload file to bucket


