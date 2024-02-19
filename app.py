#!/usr/bin/env python3
import constants
import aws_cdk as cdk


from mda_data_foundation.backend.component import DataFoundation

env_NAME = cdk.Environment(account="Account_Number", region="ap-northeast-1")


app = cdk.App()

DataFoundation(app,constants.APP_NAME +"DataFoundationsStack", env=env_NAME)


app.synth()
