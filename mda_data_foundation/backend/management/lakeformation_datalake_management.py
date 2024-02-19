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

class LakeformationDatalakeManagement(Construct):

    def __init__(self, scope: Construct, construct_id: str, 
                 datalake_raw_bucket: s3.IBucket, datalake_stage_bucket: s3.IBucket,datalake_analytics_bucket: s3.IBucket,
                 data_admin_user_arn:str, data_engineer_user_arn:str, data_analyst_user_arn:str,
                 lf_custom_service_role_arn:str, lf_workflow_role_arn:str,
                   **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.description = "This stack deploys the CTT MDA Data Foundation asset, which is comprised of a secure data lake on S3, customer-managed key in KMS, predefined IAM groups and users, Glue data catalog, and preconfigured Lake Formation permissions."
        
        ########################
        ###  Lake Formation  ###
        ########################
        

        # register each S3 bucket in the datalake
        lakeformation_raw = lakeformation.CfnResource (self, "lakeformationRaw",
            resource_arn=datalake_raw_bucket.bucket_arn, 
            use_service_linked_role=False,
            role_arn=lf_custom_service_role_arn
        )
        
        lakeformation_stage = lakeformation.CfnResource (self, "lakeformationStage",
            resource_arn=datalake_stage_bucket.bucket_arn, 
            use_service_linked_role=False,
            role_arn=lf_custom_service_role_arn
        )
        
        lakeformation_analytics = lakeformation.CfnResource (self, "lakeformationAnalytics",
            resource_arn=datalake_analytics_bucket.bucket_arn, 
            use_service_linked_role=False,
            role_arn=lf_custom_service_role_arn
        )
        
        # create bucket tags
        lakeformation_bucket_tags = lakeformation.CfnTag (self, "lakeformationBucketTags",
            tag_key="bucket",
            tag_values=["raw", "stage", "analytics"]
        )
        #lakeformation_bucket_tags.node.add_dependency(cdk_lf_admin)
        lakeformation_bucket_tags.node.add_dependency(lakeformation_raw)
        lakeformation_bucket_tags.node.add_dependency(lakeformation_stage)
        lakeformation_bucket_tags.node.add_dependency(lakeformation_analytics)
        
        # Associate each datalake bucket with its corresponding tag
        lf_raw_bucket_tag = lakeformation.CfnTagAssociation(self, "lfRawBucketTag",
            lf_tags=[lakeformation.CfnTagAssociation.LFTagPairProperty(
                catalog_id=Aws.ACCOUNT_ID,
                tag_key="bucket",
                tag_values=["raw"]
            )],
            resource=lakeformation.CfnTagAssociation.ResourceProperty(
                database=lakeformation.CfnTagAssociation.DatabaseResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    name="raw"
                )
            )
        )
        lf_raw_bucket_tag.node.add_dependency(self.node.find_child("lakeformationBucketTags"))

        lf_stage_bucket_tag = lakeformation.CfnTagAssociation(self, "lfStageBucketTag",
            lf_tags=[lakeformation.CfnTagAssociation.LFTagPairProperty(
                catalog_id=Aws.ACCOUNT_ID,
                tag_key="bucket",
                tag_values=["stage"]
            )],
            resource=lakeformation.CfnTagAssociation.ResourceProperty(
                database=lakeformation.CfnTagAssociation.DatabaseResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    name="stage"
                )
            )
        )
        lf_stage_bucket_tag.node.add_dependency(self.node.find_child("lakeformationBucketTags"))

        lf_analytics_bucket_tag = lakeformation.CfnTagAssociation(self, "lfAnalyticsBucketTag",
            lf_tags=[lakeformation.CfnTagAssociation.LFTagPairProperty(
                catalog_id=Aws.ACCOUNT_ID,
                tag_key="bucket",
                tag_values=["analytics"]
            )],
            resource=lakeformation.CfnTagAssociation.ResourceProperty(
                database=lakeformation.CfnTagAssociation.DatabaseResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    name="analytics"
                )
            )
        )
        lf_analytics_bucket_tag.node.add_dependency(self.node.find_child("lakeformationBucketTags"))

        # add data_admin_user as database creator with grantable
        data_admin_create_db_perms = lakeformation.CfnPrincipalPermissions(self, "lfDataAdminCreateDbPerms",
            permissions=["CREATE_DATABASE"],
            permissions_with_grant_option=["CREATE_DATABASE"],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=data_admin_user_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                catalog={}
            )
        )
        
        # give data_admin user permissions to Describe and Associate bucket tags + grantable
        data_admin_tag_permissions = lakeformation.CfnPrincipalPermissions(self, "dataAdminBucketTagPerms",
            permissions=["DESCRIBE", "ASSOCIATE"],
            permissions_with_grant_option=["DESCRIBE", "ASSOCIATE"],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=data_admin_user_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                lf_tag=lakeformation.CfnPrincipalPermissions.LFTagKeyResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    tag_key="bucket",
                    tag_values=["raw", "stage", "analytics"]
                )
            )
        )
        data_admin_tag_permissions.node.add_dependency(self.node.find_child("lakeformationBucketTags"))

        # grant permissions to data_admin_user on each data location and database --> only after s3 buckets have been registered
        data_admin_raw_permissions = lakeformation.CfnPrincipalPermissions(self, "dataAdminRawPermissions",
            permissions=["DATA_LOCATION_ACCESS"],
            permissions_with_grant_option=[],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=data_admin_user_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                data_location=lakeformation.CfnPrincipalPermissions.DataLocationResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    resource_arn=datalake_raw_bucket.bucket_arn
                )
            )
        )
        data_admin_raw_permissions.node.add_dependency(lakeformation_raw)
        
        data_admin_stage_permissions = lakeformation.CfnPrincipalPermissions(self, "dataAdminStagePermissions",
            permissions=["DATA_LOCATION_ACCESS"],
            permissions_with_grant_option=[],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=data_admin_user_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                data_location=lakeformation.CfnPrincipalPermissions.DataLocationResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    resource_arn=datalake_stage_bucket.bucket_arn
                )
            )
        )
        data_admin_stage_permissions.node.add_dependency(lakeformation_stage)
        
        data_admin_analytics_permissions = lakeformation.CfnPrincipalPermissions(self, "dataAdminAnalyticsPermissions",
            permissions=["DATA_LOCATION_ACCESS"],
            permissions_with_grant_option=[],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=data_admin_user_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                data_location=lakeformation.CfnPrincipalPermissions.DataLocationResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    resource_arn=datalake_analytics_bucket.bucket_arn
                )
            )
        )
        data_admin_analytics_permissions.node.add_dependency(lakeformation_analytics)
        
        # give data_admin_user TBAC database permissions to all bucket tags
        data_admin_tbac_db_permissions = lakeformation.CfnPrincipalPermissions(self, "dataAdminTbacDbPerms",
            permissions=["DESCRIBE", "ALTER", "CREATE_TABLE"],
            permissions_with_grant_option=["DESCRIBE", "ALTER", "CREATE_TABLE"],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=data_admin_user_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                lf_tag_policy=lakeformation.CfnPrincipalPermissions.LFTagPolicyResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    expression=[lakeformation.CfnPrincipalPermissions.LFTagProperty(
                        tag_key="bucket",
                        tag_values=["raw", "stage", "analytics"]
                    )],
                    resource_type="DATABASE"
                )
            )
        )
        data_admin_tbac_db_permissions.node.add_dependency(self.node.find_child("lakeformationBucketTags"))

        # give data_admin_user TBAC table permissions to bucket tags
        data_admin_tbac_table_permissions = lakeformation.CfnPrincipalPermissions(self, "dataAdminTbacTablePerms",
            permissions=["ALL"],
            permissions_with_grant_option=["ALL"],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=data_admin_user_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                lf_tag_policy=lakeformation.CfnPrincipalPermissions.LFTagPolicyResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    expression=[lakeformation.CfnPrincipalPermissions.LFTagProperty(
                        tag_key="bucket",
                        tag_values=["raw", "stage", "analytics"]
                    )],
                    resource_type="TABLE"
                )
            )
        )
        data_admin_tbac_table_permissions.node.add_dependency(self.node.find_child("lakeformationBucketTags"))
        
        # give data_engineer user permissions to Describe bucket tags
        data_engineer_tag_permissions = lakeformation.CfnPrincipalPermissions(self, "dataEngineerBucketTagPerms",
            permissions=["DESCRIBE"],
            permissions_with_grant_option=[],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=data_engineer_user_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                lf_tag=lakeformation.CfnPrincipalPermissions.LFTagKeyResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    tag_key="bucket",
                    tag_values=["raw", "stage", "analytics"]
                )
            )
        )
        data_engineer_tag_permissions.node.add_dependency(self.node.find_child("lakeformationBucketTags"))

        # grant permissions to data_engineer_user on each data location --> only if write permissions are needed, e.g. create table
        data_engineer_stage_permissions = lakeformation.CfnPrincipalPermissions(self, "dataEngineerStagePermissions",
            permissions=["DATA_LOCATION_ACCESS"],
            permissions_with_grant_option=[],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=data_engineer_user_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                data_location=lakeformation.CfnPrincipalPermissions.DataLocationResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    resource_arn=datalake_stage_bucket.bucket_arn
                )
            )
        )
        data_engineer_stage_permissions.node.add_dependency(lakeformation_stage)
        
        data_engineer_analytics_permissions = lakeformation.CfnPrincipalPermissions(self, "dataEngineerAnalyticsPermissions",
            permissions=["DATA_LOCATION_ACCESS"],
            permissions_with_grant_option=[],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=data_engineer_user_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                data_location=lakeformation.CfnPrincipalPermissions.DataLocationResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    resource_arn=datalake_analytics_bucket.bucket_arn
                )
            )
        )
        data_engineer_analytics_permissions.node.add_dependency(lakeformation_analytics)
        
        # give data_engineer_user TBAC database permissions to bucket tags
        data_engineer_tbac_raw_db_permissions = lakeformation.CfnPrincipalPermissions(self, "dataEngineerTbacRawDbPerms",
            permissions=["DESCRIBE"],
            permissions_with_grant_option=[],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=data_engineer_user_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                lf_tag_policy=lakeformation.CfnPrincipalPermissions.LFTagPolicyResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    expression=[lakeformation.CfnPrincipalPermissions.LFTagProperty(
                        tag_key="bucket",
                        tag_values=["raw"]
                    )],
                    resource_type="DATABASE"
                )
            )
        )
        data_engineer_tbac_raw_db_permissions.node.add_dependency(self.node.find_child("lakeformationBucketTags"))
        
        data_engineer_tbac_db_permissions = lakeformation.CfnPrincipalPermissions(self, "dataEngineerTbacDbPerms",
            permissions=["DESCRIBE", "ALTER", "CREATE_TABLE"],
            permissions_with_grant_option=[],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=data_engineer_user_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                lf_tag_policy=lakeformation.CfnPrincipalPermissions.LFTagPolicyResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    expression=[lakeformation.CfnPrincipalPermissions.LFTagProperty(
                        tag_key="bucket",
                        tag_values=["stage", "analytics"]
                    )],
                    resource_type="DATABASE"
                )
            )
        )
        data_engineer_tbac_db_permissions.node.add_dependency(self.node.find_child("lakeformationBucketTags"))

        # give data_engineer_user TBAC table permissions to bucket tags
        data_engineer_tbac_raw_table_permissions = lakeformation.CfnPrincipalPermissions(self, "dataEngineerTbacRawTablePerms",
            permissions=["SELECT", "DESCRIBE"],
            permissions_with_grant_option=[],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=data_engineer_user_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                lf_tag_policy=lakeformation.CfnPrincipalPermissions.LFTagPolicyResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    expression=[lakeformation.CfnPrincipalPermissions.LFTagProperty(
                        tag_key="bucket",
                        tag_values=["raw"]
                    )],
                    resource_type="TABLE"
                )
            )
        )
        data_engineer_tbac_raw_table_permissions.node.add_dependency(self.node.find_child("lakeformationBucketTags"))

        data_engineer_tbac_table_permissions = lakeformation.CfnPrincipalPermissions(self, "dataEngineerTbacTablePerms",
            permissions=["ALL"],
            permissions_with_grant_option=[],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=data_engineer_user_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                lf_tag_policy=lakeformation.CfnPrincipalPermissions.LFTagPolicyResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    expression=[lakeformation.CfnPrincipalPermissions.LFTagProperty(
                        tag_key="bucket",
                        tag_values=["stage", "analytics"]
                    )],
                    resource_type="TABLE"
                )
            )
        )
        data_engineer_tbac_table_permissions.node.add_dependency(self.node.find_child("lakeformationBucketTags"))
        
        # give data_analyst user permissions to Describe bucket tags
        data_analyst_tag_permissions = lakeformation.CfnPrincipalPermissions(self, "dataAnalystBucketTagPerms",
            permissions=["DESCRIBE"],
            permissions_with_grant_option=[],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=data_analyst_user_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                lf_tag=lakeformation.CfnPrincipalPermissions.LFTagKeyResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    tag_key="bucket",
                    tag_values=["raw", "stage", "analytics"]
                )
            )
        )
        data_analyst_tag_permissions.node.add_dependency(self.node.find_child("lakeformationBucketTags"))

        # grant permissions to data_analyst_user on each data location --> only if write permissions are needed, e.g. create table
        data_analyst_analytics_permissions = lakeformation.CfnPrincipalPermissions(self, "dataAnalystAnalyticsPermissions",
            permissions=["DATA_LOCATION_ACCESS"],
            permissions_with_grant_option=[],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=data_analyst_user_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                data_location=lakeformation.CfnPrincipalPermissions.DataLocationResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    resource_arn=datalake_analytics_bucket.bucket_arn
                )
            )
        )
        data_analyst_analytics_permissions.node.add_dependency(lakeformation_analytics)
        
        # give data_analyst_user TBAC database permissions to bucket tags
        data_analyst_tbac_db_permissions = lakeformation.CfnPrincipalPermissions(self, "dataAnalystTbacDbPerms",
            permissions=["DESCRIBE"],
            permissions_with_grant_option=[],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=data_analyst_user_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                lf_tag_policy=lakeformation.CfnPrincipalPermissions.LFTagPolicyResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    expression=[lakeformation.CfnPrincipalPermissions.LFTagProperty(
                        tag_key="bucket",
                        tag_values=["raw", "stage"]
                    )],
                    resource_type="DATABASE"
                )
            )
        )
        data_analyst_tbac_db_permissions.node.add_dependency(self.node.find_child("lakeformationBucketTags"))
        
        data_analyst_tbac_analytics_db_permissions = lakeformation.CfnPrincipalPermissions(self, "dataAnalystTbacAnalyticsDbPerms",
            permissions=["DESCRIBE", "ALTER", "CREATE_TABLE"],
            permissions_with_grant_option=[],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=data_analyst_user_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                lf_tag_policy=lakeformation.CfnPrincipalPermissions.LFTagPolicyResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    expression=[lakeformation.CfnPrincipalPermissions.LFTagProperty(
                        tag_key="bucket",
                        tag_values=["analytics"]
                    )],
                    resource_type="DATABASE"
                )
            )
        )
        data_analyst_tbac_analytics_db_permissions.node.add_dependency(self.node.find_child("lakeformationBucketTags"))

        # give data_analyst_user TBAC table permissions to bucket tags
        data_analyst_tbac_table_permissions = lakeformation.CfnPrincipalPermissions(self, "dataAnalystTbacTablePerms",
            permissions=["SELECT", "DESCRIBE"],
            permissions_with_grant_option=[],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=data_analyst_user_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                lf_tag_policy=lakeformation.CfnPrincipalPermissions.LFTagPolicyResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    expression=[lakeformation.CfnPrincipalPermissions.LFTagProperty(
                        tag_key="bucket",
                        tag_values=["raw", "stage"]
                    )],
                    resource_type="TABLE"
                )
            )
        )
        data_analyst_tbac_table_permissions.node.add_dependency(self.node.find_child("lakeformationBucketTags"))

        data_analyst_tbac_analytics_table_permissions = lakeformation.CfnPrincipalPermissions(self, "dataEngineerTbacAnalyticsTablePerms",
            permissions=["ALL"],
            permissions_with_grant_option=[],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=data_analyst_user_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                lf_tag_policy=lakeformation.CfnPrincipalPermissions.LFTagPolicyResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    expression=[lakeformation.CfnPrincipalPermissions.LFTagProperty(
                        tag_key="bucket",
                        tag_values=["analytics"]
                    )],
                    resource_type="TABLE"
                )
            )
        )
        data_analyst_tbac_analytics_table_permissions.node.add_dependency(self.node.find_child("lakeformationBucketTags"))

        # grant permissions to glue crawler role on each data location and database --> only after s3 buckets have been registered
        glue_crawler_raw_permissions = lakeformation.CfnPrincipalPermissions(self, "glueCrawlerRawPermissions",
            permissions=["DATA_LOCATION_ACCESS"],
            permissions_with_grant_option=[],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=lf_workflow_role_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                data_location=lakeformation.CfnPrincipalPermissions.DataLocationResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    resource_arn=datalake_raw_bucket.bucket_arn
                )
            )
        )
        glue_crawler_raw_permissions.node.add_dependency(lakeformation_raw)
        
        crawler_raw_db_perms = lakeformation.CfnPrincipalPermissions(self, "crawlerRawDbPerms",
            permissions=["DESCRIBE", "ALTER", "CREATE_TABLE"],
            permissions_with_grant_option=[],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=lf_workflow_role_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                database=lakeformation.CfnPrincipalPermissions.DatabaseResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    name="raw"
                )
            )
        )
        crawler_raw_db_perms.node.add_dependency(lakeformation_raw)
        
        glue_crawler_stage_permissions = lakeformation.CfnPrincipalPermissions(self, "glueCrawlerStagePermissions",
            permissions=["DATA_LOCATION_ACCESS"],
            permissions_with_grant_option=[],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=lf_workflow_role_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                data_location=lakeformation.CfnPrincipalPermissions.DataLocationResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    resource_arn=datalake_stage_bucket.bucket_arn
                )
            )
        )
        glue_crawler_stage_permissions.node.add_dependency(lakeformation_stage)
        
        crawler_stage_db_perms = lakeformation.CfnPrincipalPermissions(self, "crawlerStageDbPerms",
            permissions=["DESCRIBE", "ALTER", "CREATE_TABLE"],
            permissions_with_grant_option=[],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=lf_workflow_role_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                database=lakeformation.CfnPrincipalPermissions.DatabaseResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    name="stage"
                )
            )
        )
        crawler_stage_db_perms.node.add_dependency(lakeformation_stage)
        
        glue_crawler_analytics_permissions = lakeformation.CfnPrincipalPermissions(self, "glueCrawlerAnalyticsPermissions",
            permissions=["DATA_LOCATION_ACCESS"],
            permissions_with_grant_option=[],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=lf_workflow_role_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                data_location=lakeformation.CfnPrincipalPermissions.DataLocationResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    resource_arn=datalake_analytics_bucket.bucket_arn
                )
            )
        )
        glue_crawler_analytics_permissions.node.add_dependency(lakeformation_analytics)
        
        crawler_analytics_db_perms = lakeformation.CfnPrincipalPermissions(self, "crawlerAnalyticsDbPerms",
            permissions=["DESCRIBE", "ALTER", "CREATE_TABLE"],
            permissions_with_grant_option=[],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=lf_workflow_role_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                database=lakeformation.CfnPrincipalPermissions.DatabaseResourceProperty(
                    catalog_id=Aws.ACCOUNT_ID,
                    name="analytics"
                )
            )
        )
        crawler_analytics_db_perms.node.add_dependency(lakeformation_analytics)
        