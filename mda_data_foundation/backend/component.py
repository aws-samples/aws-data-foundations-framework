from typing import Any

import aws_cdk as cdk
from aws_cdk import (
    Aspects,
)
from constructs import Construct, DependencyGroup
import cdk_nag
from cdk_nag import NagSuppressions


from mda_data_foundation.backend.catalog.glue_datalake_catalog import GlueDataLakeCatalog
from mda_data_foundation.backend.storage.s3_datalake_storage import S3DatalakeStorage
from mda_data_foundation.backend.permissions.iam_datalake_permissions import IamDatalakePermissions
from mda_data_foundation.backend.management.lakeformation_datalake_management import LakeformationDatalakeManagement


class DataFoundation(cdk.Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)


        storage = S3DatalakeStorage(self, "MdaDataFoundationStorageStack")
        permissions = IamDatalakePermissions(self,"MdaDataFoundationPermissionsStack", 
                                            datalake_raw_bucket = storage.datalake_raw_bucket, 
                                            datalake_stage_bucket = storage.datalake_stage_bucket,
                                            datalake_analytics_bucket = storage.datalake_analytics_bucket,
                                            athena_bucket = storage.athena_bucket,
                                            cmk_arn = storage.cmk_arn,
                                            )
        catalog = GlueDataLakeCatalog(self,"MdaDataFoundationCatalogStack", 
                                            datalake_raw_bucket = storage.datalake_raw_bucket, 
                                            datalake_stage_bucket = storage.datalake_stage_bucket,
                                            datalake_analytics_bucket = storage.datalake_analytics_bucket,
                                            lf_workflow_role_arn = permissions.lf_workflow_role_arn,
                                            cmk_arn = storage.cmk_arn
                                            )

        management = LakeformationDatalakeManagement(self,"MdaDataFoundationManagementStack", 
                                            datalake_raw_bucket = storage.datalake_raw_bucket, 
                                            datalake_stage_bucket = storage.datalake_stage_bucket,
                                            datalake_analytics_bucket = storage.datalake_analytics_bucket,
                                            data_admin_user_arn = permissions.data_admin_user_arn,
                                            data_engineer_user_arn = permissions._data_engineer_user_arn,
                                            data_analyst_user_arn = permissions. data_analyst_user_arn,
                                            lf_custom_service_role_arn = permissions.lf_custom_service_role_arn,
                                            lf_workflow_role_arn = permissions.lf_workflow_role_arn,
                                            )
        dependencies_for_catalog = DependencyGroup()
        dependencies_for_catalog.add(storage)
        dependencies_for_catalog.add(permissions)
        catalog.node.add_dependency(dependencies_for_catalog)

        management.node.add_dependency(permissions)

        Aspects.of(self).add(cdk_nag.AwsSolutionsChecks())
        # Add Suppression
        NagSuppressions.add_stack_suppressions(
            stack=self, 
            suppressions=
                [
                    {"id": "AwsSolutions-IAM5", "reason": "Demo Purpose"},
                    {"id": "AwsSolutions-IAM4", "reason": "Demo Purpose"}
                ]
        )
        