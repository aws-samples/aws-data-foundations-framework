from aws_cdk import (
    Stack,
    CfnOutput,
    aws_iam as iam,
    aws_glue as glue,
    aws_lakeformation as lakeformation,
    Aws,
    aws_stepfunctions_tasks as stepfn,
    # aws_stepfunctions,
    aws_s3 as s3,
    RemovalPolicy,
    Tags,
    aws_kms as kms,
    Duration
)
from constructs import Construct

class S3DatalakeStorage(Construct):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)


        ############
        ###  S3  ###
        ############

        # create CMK to encrypt data lake buckets
        datalake_cmk = kms.Key(self, "datalakeCMK",
            enable_key_rotation=True,
            alias="datalakeCMK",
            removal_policy=RemovalPolicy.DESTROY       
        )

        # create logs bucket and tag it, then attach a bucket policy to allow logging by the s3 service principal
        datalake_logs_bucket = s3.Bucket(self, "datalakeLogsBucket",
            bucket_name="mda-datalake-logs-bucket-" + Aws.ACCOUNT_ID + "-" + Aws.REGION,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_PREFERRED,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=False,
            enforce_ssl=True
        )

        Tags.of(datalake_logs_bucket).add("datalake_bucket", "datalake_logs")

        datalake_logs_bucket.add_to_resource_policy(iam.PolicyStatement(
            actions=["s3:PutObject"],
            principals=[iam.ServicePrincipal("logging.s3.amazonaws.com")],
            resources=[datalake_logs_bucket.bucket_arn + "/*"]
        ))

        # create each of the data lake buckets --> pass the CMK and logs bucket
        datalake_raw_bucket = s3.Bucket(self, "datalakeRawBucket",
            bucket_name="mda-datalake-raw-bucket-" + Aws.ACCOUNT_ID + "-" + Aws.REGION,
            encryption_key=datalake_cmk,
            encryption=s3.BucketEncryption.KMS,
            bucket_key_enabled=True,
            versioned=True,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=False,
            server_access_logs_bucket=datalake_logs_bucket,
            server_access_logs_prefix="datalake-raw-bucket"
        )
        datalake_raw_bucket.node.add_dependency(datalake_cmk)
        datalake_raw_bucket.node.add_dependency(datalake_logs_bucket)

        datalake_stage_bucket = s3.Bucket(self, "datalakeStageBucket",
            bucket_name="mda-datalake-stage-bucket-" + Aws.ACCOUNT_ID + "-" + Aws.REGION,
            encryption_key=datalake_cmk,
            encryption=s3.BucketEncryption.KMS,
            bucket_key_enabled=True,
            versioned=True,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=False,
            server_access_logs_bucket=datalake_logs_bucket,
            server_access_logs_prefix="datalake-stage-bucket"
        )
        datalake_stage_bucket.node.add_dependency(datalake_cmk)
        datalake_stage_bucket.node.add_dependency(datalake_logs_bucket)

        datalake_analytics_bucket = s3.Bucket(self, "datalakeAnalyticsBucket",
            bucket_name="mda-datalake-analytics-bucket-" + Aws.ACCOUNT_ID + "-" + Aws.REGION,
            encryption_key=datalake_cmk,
            encryption=s3.BucketEncryption.KMS,
            bucket_key_enabled=True,
            versioned=True,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=False,
            server_access_logs_bucket=datalake_logs_bucket,
            server_access_logs_prefix="datalake-analytics-bucket"
        )
        datalake_analytics_bucket.node.add_dependency(datalake_cmk)
        datalake_analytics_bucket.node.add_dependency(datalake_logs_bucket)

        # tag each datalake bucket for cost tracking
        Tags.of(datalake_raw_bucket).add("datalake_bucket", "datalake_raw")
        Tags.of(datalake_stage_bucket).add("datalake_bucket", "datalake_stage")
        Tags.of(datalake_analytics_bucket).add("datalake_bucket", "datalake_analytics")

        # add lifecycle policy to raw bucket only
        datalake_raw_bucket.add_lifecycle_rule(
            transitions=[
                s3.Transition(storage_class=s3.StorageClass.INFREQUENT_ACCESS, transition_after=Duration.days(365)),
                s3.Transition(storage_class=s3.StorageClass.GLACIER, transition_after=Duration.days(365*3))
            ]
        )
        
        # create bucket for athena
        athena_bucket = s3.Bucket(self, "athenaBucket",
            bucket_name="mda-datalake-athena-bucket-" + Aws.ACCOUNT_ID + "-" + Aws.REGION,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.DESTROY,
            server_access_logs_bucket=datalake_logs_bucket,
            server_access_logs_prefix="athenaBucket"
        )
        
        # get bucket and CMK 
        # We assign the ARNs to local variables for the Object
        self._raw_bucket_arn = datalake_raw_bucket.bucket_arn
        self._stage_bucket_arn = datalake_stage_bucket.bucket_arn
        self._analytics_bucket_arn = datalake_analytics_bucket.bucket_arn
        self._athena_bucket_arn = athena_bucket.bucket_arn
        self._cmk_arn = datalake_cmk.key_arn

        self._datalake_raw_bucket = datalake_raw_bucket
        self._datalake_stage_bucket = datalake_stage_bucket
        self._datalake_analytics_bucket = datalake_analytics_bucket
        self._athena_bucket = athena_bucket
    
    # Using the property decorator (To allow other stacks to access the values from the class)
    
    @property
    def datalake_raw_bucket(self) -> s3.IBucket:
        return self._datalake_raw_bucket

    
    @property
    def datalake_stage_bucket(self) -> s3.IBucket:
        return self._datalake_stage_bucket

    @property
    def datalake_analytics_bucket(self) -> s3.IBucket:
        return self._datalake_analytics_bucket

    @property
    def athena_bucket(self) -> s3.IBucket:
        return self._athena_bucket

    @property
    def cmk_arn(self) -> str:
        return self._cmk_arn


