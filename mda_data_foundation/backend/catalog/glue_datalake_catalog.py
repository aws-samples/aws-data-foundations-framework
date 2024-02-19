from aws_cdk import (
    Stack,
    CfnOutput,
    aws_iam as iam,
    aws_glue as glue,
    aws_lakeformation as lakeformation,
    DefaultStackSynthesizer, 
    Fn,
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

class GlueDataLakeCatalog(Construct):

    def __init__(self, scope: Construct, construct_id: str, 
                 datalake_raw_bucket: s3.IBucket, datalake_stage_bucket: s3.IBucket,
                 datalake_analytics_bucket: s3.IBucket, lf_workflow_role_arn: str, cmk_arn: str,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.description = "This stack deploys the CTT MDA Data Foundation asset, which is comprised of a secure data lake on S3, customer-managed key in KMS, predefined IAM groups and users, Glue data catalog, and preconfigured Lake Formation permissions."
        
        ##############
        ###  Glue  ###
        ##############

        # get data lake CMK
        datalake_cmk = kms.Key.from_key_arn(self, "datalakeCMK", cmk_arn)


        # enforce encryption for Glue Catalog
        data_catalog_encryption_settings = glue.CfnDataCatalogEncryptionSettings(self, "DataCatalogEncryption",
            catalog_id=Aws.ACCOUNT_ID,
            data_catalog_encryption_settings=glue.CfnDataCatalogEncryptionSettings.DataCatalogEncryptionSettingsProperty(
                encryption_at_rest=glue.CfnDataCatalogEncryptionSettings.EncryptionAtRestProperty(
                    catalog_encryption_mode="SSE-KMS",
                    sse_aws_kms_key_id=datalake_cmk.key_id
                )
            )
        )


        # enforce encryption on CloudWatch logs and Glue Job bookmarks
        glue_security_config = glue.CfnSecurityConfiguration(self, "datalakeGlueSecurityConfiguration",
            encryption_configuration=glue.CfnSecurityConfiguration.EncryptionConfigurationProperty(
                cloud_watch_encryption=glue.CfnSecurityConfiguration.CloudWatchEncryptionProperty(
                    cloud_watch_encryption_mode="SSE-KMS",
                    kms_key_arn=cmk_arn
                ),
                job_bookmarks_encryption=glue.CfnSecurityConfiguration.JobBookmarksEncryptionProperty(
                    job_bookmarks_encryption_mode="CSE-KMS",
                    kms_key_arn=cmk_arn
                ),
                s3_encryptions=[glue.CfnSecurityConfiguration.S3EncryptionProperty(
                    s3_encryption_mode="DISABLED"
                )]
            ),
            name="datalakeGlueSecurityConfig"
        )
        

        # create glue catalog databases for raw, stage, and analytics
        catalog_raw_db = glue.CfnDatabase(self, "catalogRawDB",
            catalog_id=Aws.ACCOUNT_ID,
            database_input=glue.CfnDatabase.DatabaseInputProperty(
                name="raw",
                description="Data lake Raw bucket",
                location_uri="s3://" + datalake_raw_bucket.bucket_name
            )                                  
        )
        #catalog_raw_db.node.add_dependency(cdk_create_db_perms)

        catalog_stage_db = glue.CfnDatabase(self, "catalogStageDB",
            catalog_id=Aws.ACCOUNT_ID,
            database_input=glue.CfnDatabase.DatabaseInputProperty(
                name="stage",
                description="Data lake Stage bucket",
                location_uri="s3://" + datalake_stage_bucket.bucket_name
            )                                  
        )
        #catalog_stage_db.node.add_dependency(cdk_create_db_perms)
        
        catalog_analytics_db = glue.CfnDatabase(self, "catalogAnalyticsDB",
            catalog_id=Aws.ACCOUNT_ID,
            database_input=glue.CfnDatabase.DatabaseInputProperty(
                name="analytics",
                description="Data lake Analytics bucket",
                location_uri="s3://" + datalake_analytics_bucket.bucket_name
            )                                  
        )
        #catalog_analytics_db.node.add_dependency(cdk_create_db_perms)        
        
        # get glue catalog database names
        raw_db_name = catalog_raw_db.database_input.name
        stage_db_name = catalog_stage_db.database_input.name
        analytics_db_name = catalog_analytics_db.database_input.name
        
        # create glue crawlers for each datalake bucket and attach the glue service role
        raw_bucket_crawler = glue.CfnCrawler (self, "rawBucketCrawler",
            name="lakeFormationRawBucketCrawler",
            description="Crawls the Raw bucket in the Lake Formation data lake",
            role = lf_workflow_role_arn,
            database_name = raw_db_name,
            targets = {
                "s3Targets": [{"path": datalake_raw_bucket.bucket_name}]
            },
            crawler_security_configuration="datalakeGlueSecurityConfig",
            # lake_formation_configuration={
            #     "UseLakeFormationCredentials":True,
            #     "AccountId":Aws.ACCOUNT_ID
            # }
        )

        stage_bucket_crawler = glue.CfnCrawler (self, "stageBucketCrawler",
            name="lakeFormationStageBucketCrawler",
            description="Crawls the Stage bucket in the Lake Formation data lake",
            role = lf_workflow_role_arn,
            database_name = stage_db_name,
            targets = {
                "s3Targets": [{"path": datalake_stage_bucket.bucket_name}]
            },
            crawler_security_configuration="datalakeGlueSecurityConfig",
        )

        analytics_bucket_crawler = glue.CfnCrawler (self, "analyticsBucketCrawler",
            name="lakeFormationAnalyticsBucketCrawler",
            description="Crawls the Analytics bucket in the Lake Formation data lake",
            role = lf_workflow_role_arn,
            database_name = analytics_db_name,
            targets = {
                "s3Targets": [{"path": datalake_analytics_bucket.bucket_name}]
            },
            crawler_security_configuration="datalakeGlueSecurityConfig",
        )

    #     # get group and role ARNs
    #     # We assign the ARNs to local variables for the Object
    #     self._cdk_role_arn = cdk_role_arn

    # # Using the property decorator
    # @property
    # def cdk_role_arn(self) -> str:
    #     return self._cdk_role_arn
    
 