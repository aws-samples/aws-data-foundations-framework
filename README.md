# Data Foundation Framework Accelerator
The Data Foundation Framework Accelerator uses [AWS CDK](https://github.com/aws/aws-cdk/) to deploy the architecture. It consists of a secure data lake built on S3, augmented with security through KMS and IAM, and fine-grained data governance through Glue and Lake Formation. Once deployed, this data foundation allows a functional data system to be built on top of it, with the flexibility to customize the system to the customer’s needs. 

## Description
The Data Foundation asset builds the foundational components of a data system, following published AWS best practices.

- A customer-managed key (CMK) is created in **KMS** to encrypt the data lake buckets.
- In **S3**, three data lake buckets are created, with server access logs written to a fourth bucket. Furthermore, a fifth bucket is created for use with Athena.
- **IAM** Groups, Users, and Roles are created with least privilege access to the S3 data lake buckets, CMK, and other essential services such as Lake Formation and Glue.
- In **Glue**, three Databases are created in the Glue Data Catalog, each pointing to their respective data lake buckets in S3. Crawlers are also created to crawl each of the data lake buckets and update the corresponding Database in Glue Data Catalog.
- Lastly, **Lake Formation** is pre-configured to register the S3 data lake locations, create and associate tags to each Database, grant least privilege access permissions to each IAM User and Role, and also assign Lake Formation Admins.

## Contributing
See [CONTRIBUTING](CONTRIBUTING.md) for more information.

## Security
See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License
This project is licensed under the Apache-2.0 License.




