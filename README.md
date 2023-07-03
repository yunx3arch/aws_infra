# aws-infra

* Install and Configure AWS Command Line Interface

* Install Terraform

##Getting Started##
Clone the repository to your local machine

To initialize the project as terraform project, run
```
terraform init
```
##Select the AWS CLI profile##
To use Dev Environment, run
```
export AWS_PROFILE=dev
```
To use Prod Environment, run
```
export AWS_PROFILE=demo
```
##To deploy infrastructure with Terraform##
Run the following commands in order:
```
terraform plan - Preview the changes Terraform will make to match your configuration.
terraform apply -  Make the planned changes.

##To destroy infrastructure with Terraform##
terraform destroy - Delete all the resources
```

##To import SSL certificate##
```
aws acm import-certificate --certificate fileb://prod_makeentryleveljobsentrylevel_me.crt --certificate-chain fileb://prod_makeentryleveljobsentrylevel_me.ca-bundle --private-key fileb://private.pem
```
