May 9, 2023
- added console list and read permissions to Data Engineer and Analyst Groups

May 8, 2023
- updated README to include instructions on setting up the current user as a trusted entity to the cdk...deploy role

May 24, 2023
- Refactored the mda_data_foundation_stack into 4 different stacks for readability and maintainability

May 25, 2023
- removed the CDK role permissions from the Glue stack into the Iam permissions stack (Add cdk role as LF admin, & Add cek role permissions to create db in LF) 
- Moved the  cdk role pass role policy for the workflow role from LakeFormation stack to the IAM permissions stack
- Moved adding the data admin role as a LF admin from the LakeFormation stack to the Iam permission stack  