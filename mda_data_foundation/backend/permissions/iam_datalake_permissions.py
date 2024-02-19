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
    Duration,
    Aspects
)
from constructs import Construct



class IamDatalakePermissions(Construct):

    def __init__(self, scope: Construct, construct_id: str, 
                 datalake_raw_bucket: s3.IBucket, datalake_stage_bucket: s3.IBucket,
                 datalake_analytics_bucket: s3.IBucket, athena_bucket: s3.IBucket, cmk_arn: str,
                   **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.description = "This stack deploys the CTT MDA Data Foundation asset, which is comprised of a secure data lake on S3, customer-managed key in KMS, predefined IAM groups and users, Glue data catalog, and preconfigured Lake Formation permissions."
        
        #############
        ###  IAM  ###
        #############

        # create lakeformation workflow role, then create and attach policies
        lf_workflow_role = iam.Role(self, "lfWorkflowRole",
            role_name="lakeFormationWorkflowRole",
            description="Custom Lake Formation workflow role with read-only access to data lake buckets and CMK",
            assumed_by=iam.ServicePrincipal('glue.amazonaws.com')
        )
        
        # lakeformation workflow role access policy
        lf_workflow_role_access_policy = iam.Policy(self, "lfWorkflowRoleAccessPolicy",
            policy_name="lakeFormationWorkflowRoleAccessPolicy",
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "lakeformation:GetDataAccess",
                        "lakeformation:GrantPermissions"
                    ],
                    resources=["*"]
                )
            ]
        )
        
        # passrole policy for the lakeformation workflow role
        lf_pass_workflow_role_policy = iam.Policy(self, "lfPassWorkflowRolePolicy",
            policy_name="lakeFormationPassWorkflowRolePolicy",
            statements=[
                iam.PolicyStatement(
                    actions=["iam:PassRole"],
                    resources=["arn:aws:iam::" + Aws.ACCOUNT_ID + ":role/" + lf_workflow_role.role_name]
                )
            ]
        )
        
        
        # read-write permissions to the datalake buckets only
        datalake_buckets_read_write_policy = iam.Policy(self, "lfDatalakeBucketsReadWritePolicy",
            policy_name="lakeFormationDatalakeBucketsReadWritePolicy",
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "s3:ListBucket"
                    ],
                    resources=[
                        datalake_raw_bucket.bucket_arn,
                        datalake_stage_bucket.bucket_arn,
                        datalake_analytics_bucket.bucket_arn
                    ]
                ),
                iam.PolicyStatement(
                    actions=[
                        "s3:PutObject",
                        "s3:GetObject",
                        "s3:DeleteObject"
                    ],
                    resources=[
                        datalake_raw_bucket.bucket_arn+"*", 
                        datalake_stage_bucket.bucket_arn+"*", 
                        datalake_analytics_bucket.bucket_arn+"*"
                    ]
                )
            ]
        )


        # permissions for the CMK used by the datalake buckets
        datalake_key_policy = iam.Policy(self, "datalakeBucketsKeyPolicy",
            policy_name="datalakeBucketsKeyPolicy",
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "kms:Encrypt",
                        "kms:Decrypt",
                        "kms:ReEncryptFrom",
                        "kms:ReEncryptTo",
                        "kms:GenerateDataKey",
                        "kms:GenerateDataKeyWithoutPlaintext",
                        "kms:GenerateDataKeyPair",
                        "kms:GenerateDataKeyPairWithoutPlaintext",
                        "kms:DescribeKey"
                    ],
                    resources=[cmk_arn]
                )
            ]
        )
        
        lf_workflow_role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSGlueServiceRole"))
        lf_workflow_role.attach_inline_policy(lf_workflow_role_access_policy)
        lf_workflow_role.attach_inline_policy(lf_pass_workflow_role_policy)
        lf_workflow_role.attach_inline_policy(datalake_buckets_read_write_policy)
        lf_workflow_role.attach_inline_policy(datalake_key_policy)
        
        # create lake formation custom service account role and attach policies
        lf_custom_service_role = iam.Role (self, 'lfCustomServiceRole',
            role_name="lakeFormationCustomServiceRole",
            description="Custom service role used by Lake Formation with permissions to the data lake buckets and CMK",
            assumed_by=iam.ServicePrincipal('lakeformation.amazonaws.com')
        )
        
        # add trusted entities to lf_custom_service_role
        lf_custom_service_role.assume_role_policy.add_statements(iam.PolicyStatement(
            actions=["sts:AssumeRole"],
            principals=[
                iam.ServicePrincipal("lakeformation.amazonaws.com"), 
                iam.ServicePrincipal("glue.amazonaws.com")
            ])
        )
        
        # passrole policy for the lakeformation custom service role
        lf_pass_custom_service_role_policy = iam.Policy(self, "lfPassCustomServiceRolePolicy",
            policy_name="lakeFormationPassCustomServiceRolePolicy",
            statements=[
                iam.PolicyStatement(
                    actions=["iam:PassRole"],
                    resources=["arn:aws:iam::" + Aws.ACCOUNT_ID + ":role/" + lf_custom_service_role.role_name]
                )
            ]
        )
        
        # allow lakeformation to write cloudwatch logs
        lf_write_cloudwatch_logs_policy = iam.Policy(self, "lfWriteCloudWatchLogsPolicy",
            policy_name="lakeFormationWriteCloudWatchLogsPolicy",
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "logs:CreateLogStream",
                        "logs:CreateLogGroup",
                        "logs:PutLogEvents"
                    ],
                    resources=[
                        "arn:aws:logs::" + Aws.REGION + ":" + Aws.ACCOUNT_ID + ":log-group:/aws-lakeformation-acceleration/*",
                        "arn:aws:logs::" + Aws.REGION + ":" + Aws.ACCOUNT_ID + ":log-group:/aws-lakeformation-acceleration/*:log-stream:*"
                    ]
                )
            ]
        )
        
        lf_custom_service_role.attach_inline_policy(datalake_buckets_read_write_policy)
        lf_custom_service_role.attach_inline_policy(lf_pass_custom_service_role_policy)
        lf_custom_service_role.attach_inline_policy(lf_write_cloudwatch_logs_policy)
        lf_custom_service_role.attach_inline_policy(datalake_key_policy)
        

        #Configure CDK permissions 
        # add cdk role as a lakeformation admin
        cdk_role_arn = Fn.sub(DefaultStackSynthesizer().DEFAULT_CLOUDFORMATION_ROLE_ARN,
            variables={"Qualifier":DefaultStackSynthesizer().DEFAULT_QUALIFIER},
        )
        
        cdk_lf_admin = lakeformation.CfnDataLakeSettings (self, "lakeformationCdkAdmin",
            admins=[{"dataLakePrincipalIdentifier": cdk_role_arn}]
        )

        # add cdk role permissions to create db in lakeformation
        cdk_create_db_perms = lakeformation.CfnPrincipalPermissions(self, "cdkCreateDbPerms",
            permissions=["CREATE_DATABASE"],
            permissions_with_grant_option=[],
            principal=lakeformation.CfnPrincipalPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier=cdk_role_arn
            ),
            resource=lakeformation.CfnPrincipalPermissions.ResourceProperty(
                catalog={}
            )
        )
        cdk_create_db_perms.node.add_dependency(cdk_lf_admin)


        # get cdk role from arn, then add pass role policy for the workflow role
        cdk_role = iam.Role.from_role_arn(self, "cdkRole", cdk_role_arn)
        cdk_role.attach_inline_policy(lf_pass_custom_service_role_policy)
        


        # create dataAdmin group, create and add user, then create and attach policies
        data_admin_group = iam.Group(self, "lakeFormationDataAdminGroup", group_name="lakeFormationDataAdminGroup")
        
        # create referenceDataAdmin user
        data_admin_user = iam.User(self, "lfDataAdminUser",
            user_name="lakeFormationDataAdminUser",
            groups=[data_admin_group]
        )

        # add data_admin_user as lake formation admin
        lf_data_admin = lakeformation.CfnDataLakeSettings (self, "lakeformationDataAdminUser",
            admins=[{"dataLakePrincipalIdentifier": data_admin_user.user_arn}]
        )
        
        # policy for creating the lakeformation service-linked role
        create_lf_service_role_policy = iam.Policy(self, "createLfServiceRolePolicy",
            policy_name="createLakeFormationServiceRolePolicy",
            statements=[
                iam.PolicyStatement(
                    actions=["iam:CreateServiceLinkedRole"],
                    resources=["*"],
                    conditions={
                            "StringEquals": {"iam:AWSServiceName": "lakeformation.amazonaws.com"}
                    }
                ),
                iam.PolicyStatement(
                    actions=["iam:PutRolePolicy"],
                    resources=["arn:aws:iam::" + Aws.ACCOUNT_ID + ":role/aws-service-role/lakeformation.amazonaws.com/AWSServiceRoleForLakeFormationDataAccess"]
                )
            ]
        )
        
        # policy for granting or receiving cross-account lakeformation permissions
        lf_cross_account_perms_policy = iam.Policy(self, "lfCrossAccountPermsPolicy",
            policy_name="lakeFormationCrossAccountPermsPolicy",
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "ram:AcceptResourceShareInvitation",
                        "ram:RejectResourceShareInvitation",
                        "ec2:DescribeAvailabilityZones",
                        "ram:EnableSharingWithAwsOrganization"
                    ],
                    resources=["*"]
                )
            ]
        )
        
        # read-write permissions to the athena bucket
        athena_bucket_read_write_policy = iam.Policy(self, "athenaBucketReadWritePolicy",
            policy_name="athenaBucketReadWritePolicy",
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "s3:ListBucket"
                    ],
                    resources=[
                        athena_bucket.bucket_arn
                    ]
                ),
                iam.PolicyStatement(
                    actions=[
                        "s3:PutObject",
                        "s3:GetObject",
                        "s3:DeleteObject"
                    ],
                    resources=[
                        athena_bucket.bucket_arn+"*"
                    ]
                )
            ]
        )
        
        data_admin_group.add_managed_policy (iam.ManagedPolicy.from_aws_managed_policy_name("AWSLakeFormationDataAdmin"))
        data_admin_group.add_managed_policy (iam.ManagedPolicy.from_aws_managed_policy_name("AWSGlueConsoleFullAccess"))
        data_admin_group.add_managed_policy (iam.ManagedPolicy.from_aws_managed_policy_name("CloudWatchLogsReadOnlyAccess"))
        data_admin_group.add_managed_policy (iam.ManagedPolicy.from_aws_managed_policy_name("AWSLakeFormationCrossAccountManager"))
        data_admin_group.add_managed_policy (iam.ManagedPolicy.from_aws_managed_policy_name("AmazonAthenaFullAccess"))
        data_admin_group.add_managed_policy (iam.ManagedPolicy.from_aws_managed_policy_name("IAMReadOnlyAccess"))
        data_admin_group.attach_inline_policy(create_lf_service_role_policy)
        data_admin_group.attach_inline_policy(lf_pass_workflow_role_policy)
        data_admin_group.attach_inline_policy(lf_cross_account_perms_policy)
        data_admin_group.attach_inline_policy(datalake_buckets_read_write_policy)
        data_admin_group.attach_inline_policy(athena_bucket_read_write_policy)
        data_admin_group.attach_inline_policy(datalake_key_policy)
        
        # create dataEngineer group, create and add user, then create and attach policies
        data_engineer_group = iam.Group(self, "lakeFormationDataEngineerGroup", group_name="lakeFormationDataEngineerGroup")
        
        # create referenceDataEngineer user
        data_engineer_user = iam.User(self, "lfDataEngineerUser",
            user_name="lakeFormationDataEngineerUser",
            groups=[data_engineer_group]
        )
        
        # lakeformation data engineer access policy
        lf_data_engineer_access_policy = iam.Policy(self, "lfDataEngineerAccessPolicy",
            policy_name="lakeFormationDataEngineerAccessPolicy",
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "lakeformation:GetDataAccess",
                        "lakeformation:GrantPermissions",
                        "lakeformation:RevokePermissions",
                        "lakeformation:BatchGrantPermissions",
                        "lakeformation:BatchRevokePermissions",
                        "lakeformation:ListPermissions",
                        "lakeformation:AddLFTagsToResource",
                        "lakeformation:RemoveLFTagsFromResource",
                        "lakeformation:GetResourceLFTags",
                        "lakeformation:ListLFTags",
                        "lakeformation:GetLFTag",
                        "lakeformation:SearchTablesByLFTags",
                        "lakeformation:SearchDatabasesByLFTags",
                        "lakeformation:GetWorkUnits",
                        "lakeformation:GetWorkUnitResults",
                        "lakeformation:StartQueryPlanning",
                        "lakeformation:GetQueryState",
                        "lakeformation:GetQueryStatistics"
                    ],
                    resources=["*"]
                )
            ]
        )
        
        # lakeformation policy for operations on governed tables
        lf_governed_tables_policy = iam.Policy(self, "lfGovernedTablesPolicy",
            policy_name="lakeFormationGovernedTablesPolicy",
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "lakeformation:StartTransaction",
                        "lakeformation:CommitTransaction",
                        "lakeformation:CancelTransaction",
                        "lakeformation:ExtendTransaction",
                        "lakeformation:DescribeTransaction",
                        "lakeformation:ListTransactions",
                        "lakeformation:GetTableObjects",
                        "lakeformation:UpdateTableObjects",
                        "lakeformation:DeleteObjectsOnCancel"
                    ],
                    resources=["*"]
                )
            ]
        )
        
        # lakeformation policy for metadata access control using TBAC
        lf_tbac_policy = iam.Policy(self, "lfTbacPolicy",
            policy_name="lakeFormationTbacPolicy",
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "lakeformation:AddLFTagsToResource",
                        "lakeformation:RemoveLFTagsFromResource",
                        "lakeformation:GetResourceLFTags",
                        "lakeformation:ListLFTags",
                        "lakeformation:GetLFTag",
                        "lakeformation:SearchTablesByLFTags",
                        "lakeformation:SearchDatabasesByLFTags"
                    ],
                    resources=["*"]
                )
            ]
        )
        
        # data engineer read/write permissions to the datalake buckets only
        datalake_buckets_data_engineer_policy = iam.Policy(self, "lfDatalakeBucketsDataEngineerPolicy",
            policy_name="lakeFormationDatalakeBucketsDataEngineerPolicy",
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "s3:ListBucket"
                    ],
                    resources=[
                        datalake_raw_bucket.bucket_arn,
                        datalake_stage_bucket.bucket_arn,
                        datalake_analytics_bucket.bucket_arn
                    ]
                ),
                iam.PolicyStatement(
                    actions=[
                        "s3:GetObject",
                        "s3:PutObject",
                        "s3:DeleteObject"
                    ],
                    resources=[
                        datalake_stage_bucket.bucket_arn+"*",
                        datalake_analytics_bucket.bucket_arn+"*"
                    ]
                ),
                iam.PolicyStatement(
                    actions=[
                        "s3:GetObject"
                    ],
                    resources=[datalake_raw_bucket.bucket_arn+"*"]
                )
            ]
        )
        
        data_engineer_group.add_managed_policy (iam.ManagedPolicy.from_aws_managed_policy_name("AmazonAthenaFullAccess"))
        data_engineer_group.add_managed_policy (iam.ManagedPolicy.from_aws_managed_policy_name("AWSGlueConsoleFullAccess"))
        data_engineer_group.add_managed_policy (iam.ManagedPolicy.from_aws_managed_policy_name("IAMReadOnlyAccess"))
        data_engineer_group.attach_inline_policy(lf_data_engineer_access_policy)
        data_engineer_group.attach_inline_policy(lf_governed_tables_policy)
        data_engineer_group.attach_inline_policy(lf_tbac_policy)
        data_engineer_group.attach_inline_policy(lf_pass_workflow_role_policy)
        data_engineer_group.attach_inline_policy(datalake_buckets_data_engineer_policy)
        data_engineer_group.attach_inline_policy(athena_bucket_read_write_policy)
        data_engineer_group.attach_inline_policy(datalake_key_policy)
        
        # create dataAnalyst group, create and add user, then create and attach policies
        data_analyst_group = iam.Group(self, "lakeFormationDataAnalystGroup", group_name="lakeFormationDataAnalystGroup")
        
        # create referenceDataAnalyst user
        data_analyst_user = iam.User(self, "lfDataAnalystUser",
            user_name="lakeFormationDataAnalystUser",
            groups=[data_analyst_group]
        )
        
        # lakeformation data analyst access policy
        lf_data_analyst_access_policy = iam.Policy(self, "lfDataAnalystAccessPolicy",
            policy_name="lakeFormationDataAnalystAccessPolicy",
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "lakeformation:GetDataAccess",
                        "glue:GetTable",
                        "glue:GetTables",
                        "glue:SearchTables",
                        "glue:GetDatabase",
                        "glue:GetDatabases",
                        "glue:GetPartitions",
                        "lakeformation:GetResourceLFTags",
                        "lakeformation:ListLFTags",
                        "lakeformation:GetLFTag",
                        "lakeformation:SearchTablesByLFTags",
                        "lakeformation:SearchDatabasesByLFTags"
                    ],
                    resources=["*"]
                )
            ]
        )
        
        # data analyst read/write permissions to the datalake buckets only
        datalake_buckets_data_analyst_policy = iam.Policy(self, "lfDatalakeBucketsDataAnalystPolicy",
            policy_name="lakeFormationDatalakeBucketsDataAnalystPolicy",
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "s3:ListBucket"
                    ],
                    resources=[
                        datalake_raw_bucket.bucket_arn,
                        datalake_stage_bucket.bucket_arn,
                        datalake_analytics_bucket.bucket_arn
                    ]
                ),
                iam.PolicyStatement(
                    actions=[
                        "s3:GetObject",
                        "s3:PutObject",
                        "s3:DeleteObject"
                    ],
                    resources=[
                        datalake_analytics_bucket.bucket_arn+"*"
                    ]
                ),
                iam.PolicyStatement(
                    actions=[
                        "s3:GetObject"
                    ],
                    resources=[
                        datalake_raw_bucket.bucket_arn+"*",
                        datalake_stage_bucket.bucket_arn+"*"
                    ]
                )
            ]
        )
        
        data_analyst_group.add_managed_policy (iam.ManagedPolicy.from_aws_managed_policy_name("AmazonAthenaFullAccess"))
        data_analyst_group.add_managed_policy (iam.ManagedPolicy.from_aws_managed_policy_name("IAMReadOnlyAccess"))
        data_analyst_group.attach_inline_policy(lf_data_analyst_access_policy)
        data_analyst_group.attach_inline_policy(lf_governed_tables_policy)
        data_analyst_group.attach_inline_policy(datalake_buckets_data_analyst_policy)
        data_analyst_group.attach_inline_policy(athena_bucket_read_write_policy)
        data_analyst_group.attach_inline_policy(datalake_key_policy)

        # get group and role ARNs
        # We assign the ARNs to local variables for the Object
        self._data_admin_group_arn = data_admin_group.group_arn
        self._data_admin_user_arn = data_admin_user.user_arn
        self._data_engineer_group_arn = data_engineer_group.group_arn
        self._data_engineer_user_arn = data_engineer_user.user_arn
        self._data_analyst_group_arn = data_analyst_group.group_arn
        self._data_analyst_user_arn = data_analyst_user.user_arn
        self._lf_workflow_role_arn = lf_workflow_role.role_arn
        self._lf_custom_service_role_arn = lf_custom_service_role.role_arn
        self._lf_pass_custom_service_role_policy = lf_pass_custom_service_role_policy

        

    # Using the property decorator
    @property
    def data_admin_user_arn(self) -> str:
        return self._data_admin_user_arn
    
    @property
    def data_engineer_user(self) -> str:
        return self._data_engineer_user_arn

    @property
    def data_analyst_user_arn(self) -> str:
        return self._data_analyst_user_arn

    @property
    def lf_workflow_role_arn(self) -> str:
        return self._lf_workflow_role_arn

    @property
    def lf_custom_service_role_arn(self) -> str:
        return self._lf_custom_service_role_arn

    @property
    def lf_pass_custom_service_role_policy(self) -> iam.IPolicy:
        return self._lf_pass_custom_service_role_policy

    