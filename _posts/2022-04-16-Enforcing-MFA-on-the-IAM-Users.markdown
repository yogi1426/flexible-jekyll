---
layout: post
title: Enforcing MFA Policy on the IAM Users in an AWS Account
date: 2022-04-16
description: AWS Security
img: cloud.jpg # Add image post (optional)
fig-caption: # Add figcaption (optional)
tags: [Cloud Security,Security,AWS Security]
---

For the most IT Industry it is a common miss that nowadays every Security team is having to get engineers use MFA on the cloud accounts. Hence, leading to an easy attack surface for hackers around the globe.
Why is MFA important you may ask? If you have already not gone through this [Blog](https://www.yogendra-swaroop.tech/save-your-social-media/), I would request you to go through this once.

### Main Objective
Problem Statement came when we saw that there are many users in our AWS infrastructure that are not using MFA and because of which our Security Hub Score was also getting impacted.
I had just started to learn cloud and I thought of solving the problem statement using some level of automations and enforcing policies.
This blogpost will help you understand the approach which I followed to enforce MFA on every IAM user.

But before I dig deeper, First things first, Let me brief you about few services/resources of AWS I have used in order to achieve the goal.

### Lambda: 
AWS Lambda is a serverless, event-driven compute service that lets you run code for virtually any type of application or backend service without provisioning or managing servers. By Serverless we mean you don't need to maintain your own servers to run lambda functions. It is a compute service that lets you run the code without provisioning or managing the server. 
You can trigger Lambda from over 200 AWS services and software as a service (SaaS) applications, and only pay for what you use. 
Our Lambda function will get the IAM Users on which MFA is not enabled, create our custom made mfa policy and attach it to the IAM User. We will be scheduling event which will run our Lambda code everyday on defined interval of time. 

> [Learn more about AWS Lambda](https://www.serverless.com/aws-lambda) 

### Cloudformation:
AWS CloudFormation is a Infrastructure as a Code(IAC) service that helps you model and set up your AWS resources so that you can spend less time managing those resources and more time focusing on your applications that run in AWS. Cloudformation is defining the template which will automatically provision and setup the infrastructure for you. 

Classic Example: Defining the stack which will create EC2 Instance, Install Wordpress, Setup Security Groups, RDS for you, and getting your static website up and running in minutes.

How cloudformation works?
For Cloudformation service to work, you create a template that describes all the AWS resources that you want (like Amazon EC2 instances or Amazon RDS DB instances), and CloudFormation takes care of provisioning and configuring those resources for you. You don't need to individually create and configure AWS resources and figure out what's dependent on what, CloudFormation handles that for you.

> [Read more about Cloudformation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/Welcome.html)

### AWS Eventbridge: 
Amazon EventBridge is a serverless event bus that makes it easier to build event-driven applications at scale using events generated from your applications, integrated Software-as-a-Service (SaaS) applications, and AWS services.
For our use case, we used AWS Eventbridge to schedule an event. We will be using AWS Eventbridge to trigger our Lambda at our desired time.

> [More about Eventbridge](https://aws.amazon.com/eventbridge/)

### Slack: 
We will be using slack to send notification whenever there is any Enforce MFA policy attached to an IAM User.

Before we dig deeper, In nutshell to understand our methodology, whenever we deploy our stack using Cloudformation template, a lambda function is created which makes a JSON Policy so that whenever there is a violation of our MFA, it automatically attaches the Enforce MFA Policy to an IAM User. As a result of which, IAM user is forced to setup Multi factor authentication. Once the policy is attached, our lambda triggers slack notification.

First things first, since our entire exercise is dependend on our Lambda function, Let's start with that. Below attached is the Lambda code template.

```
import json
import boto3
import os, math
import requests
import datetime, time
from botocore.exceptions import ClientError

policyJson = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowViewAccountInfo",
            "Effect": "Allow",
            "Action": [
                "iam:GetAccountPasswordPolicy",
                "iam:GetAccountSummary",
                "iam:ListVirtualMFADevices"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AllowManageOwnPasswords",
            "Effect": "Allow",
            "Action": [
                "iam:ChangePassword",
                "iam:GetUser"
            ],
            "Resource": "arn:aws:iam::*:user/${aws:username}"
        },
        {
            "Sid": "AllowManageOwnAccessKeys",
            "Effect": "Allow",
            "Action": [
                "iam:CreateAccessKey",
                "iam:DeleteAccessKey",
                "iam:ListAccessKeys",
                "iam:UpdateAccessKey"
            ],
            "Resource": "arn:aws:iam::*:user/${aws:username}"
        },
        {
            "Sid": "AllowManageOwnSigningCertificates",
            "Effect": "Allow",
            "Action": [
                "iam:DeleteSigningCertificate",
                "iam:ListSigningCertificates",
                "iam:UpdateSigningCertificate",
                "iam:UploadSigningCertificate"
            ],
            "Resource": "arn:aws:iam::*:user/${aws:username}"
        },
        {
            "Sid": "AllowManageOwnSSHPublicKeys",
            "Effect": "Allow",
            "Action": [
                "iam:DeleteSSHPublicKey",
                "iam:GetSSHPublicKey",
                "iam:ListSSHPublicKeys",
                "iam:UpdateSSHPublicKey",
                "iam:UploadSSHPublicKey"
            ],
            "Resource": "arn:aws:iam::*:user/${aws:username}"
        },
        {
            "Sid": "AllowManageOwnGitCredentials",
            "Effect": "Allow",
            "Action": [
                "iam:CreateServiceSpecificCredential",
                "iam:DeleteServiceSpecificCredential",
                "iam:ListServiceSpecificCredentials",
                "iam:ResetServiceSpecificCredential",
                "iam:UpdateServiceSpecificCredential"
            ],
            "Resource": "arn:aws:iam::*:user/${aws:username}"
        },
        {
            "Sid": "AllowManageOwnVirtualMFADevice",
            "Effect": "Allow",
            "Action": [
                "iam:CreateVirtualMFADevice",
                "iam:DeleteVirtualMFADevice"
            ],
            "Resource": "arn:aws:iam::*:mfa/${aws:username}"
        },
        {
            "Sid": "AllowManageOwnUserMFA",
            "Effect": "Allow",
            "Action": [
                "iam:DeactivateMFADevice",
                "iam:EnableMFADevice",
                "iam:ListMFADevices",
                "iam:ResyncMFADevice"
            ],
            "Resource": "arn:aws:iam::*:user/${aws:username}"
        },
        {
            "Sid": "DenyAllExceptListedIfNoMFA",
            "Effect": "Deny",
            "NotAction": [
                "iam:CreateVirtualMFADevice",
                "iam:EnableMFADevice",
                "iam:GetUser",
                "iam:ListUsers",
                "iam:ListMFADevices",
                "iam:ListVirtualMFADevices",
                "iam:ResyncMFADevice",
                "iam:DeleteVirtualMFADevice",
                "iam:ChangePassword",
                "iam:CreateLoginProfile",
                "sts:GetSessionToken"
            ],
            "Resource": "*",
            "Condition": {
                "BoolIfExists": {
                    "aws:MultiFactorAuthPresent": "false"
                }
            }
        }
    ]
}

headers = {
    'Content-Type': "application/json",
    'User-Agent': "PostmanRuntime/7.19.0",
    'Accept': "*/*",
    'Cache-Control': "no-cache",
    'Postman-Token': "56df98df-XXXX-XXXX-XXXX-9a2k5q56b8gf,458sadwa-XXXX-XXXX-XXXX-p456z4564a45",
    'Host': "hooks.slack.com",
    'Accept-Encoding': "gzip, deflate",
    'Content-Length': "497",
    'Connection': "keep-alive",
    'cache-control': "no-cache"
    }


client=boto3.client('iam')
sns=boto3.client('sns')
sts = boto3.client('sts')
iam_resource = boto3.resource('iam')
paginator = client.get_paginator('list_account_aliases')
whitelist_tags = os.environ['WHITELIST_TAG']
response = client.list_users()
url = os.environ['WEBHOOK_URL']
MFA_POLICY_NAME = "ForceMFA"
slack_emoji = ":aws-iam:" 



# Get number of managed Policies attached to the user
def get_attached_policy_count(username):
 # iam_client = get_iam_client()
  managed_user_policies = client.list_attached_user_policies(UserName=username)
  deny_policy_name = 'ForceMFA'
  attached_policies = managed_user_policies['AttachedPolicies']
  policy_count = len(attached_policies)
  for policy in attached_policies:
    # This is to make sure we don't count our very own attached policy. Because that can be deleted and attached again after updating
      if policy['PolicyName'] == deny_policy_name:
          policy_count = policy_count - 1
  return policy_count


def lambda_handler(event,context):
    # Check if the policy exist in this account. If not create one.
    if not is_policy_exist(MFA_POLICY_NAME):
        policyStr = json.dumps(policyJson)
        client.create_policy(PolicyName=MFA_POLICY_NAME,PolicyDocument=policyStr,Description="Policy Creation from Lambda function - Enforcing MFA")

    for user in response['Users']:
        username = user['UserName']
        userPolicyList = client.list_attached_user_policies(UserName=username)
        account_id = sts.get_caller_identity()['Account']
        
        if get_attached_policy_count(username) == 10:
            slack_response = requests.request("POST", url, data=send_slack_notification(2,username,account_id), headers=headers)
            
        elif not is_user_whitelisted(username) and not is_policy_attached(username,userPolicyList) and not is_mfa_enabled(username):
            
            policy_arn = f'arn:aws:iam::{account_id}:policy/{MFA_POLICY_NAME}'
            response2 = client.attach_user_policy(PolicyArn=policy_arn,UserName=username)
            print("Attaching ForceMFA policy to the user {}".format(username))
            slack_response = requests.request("POST", url, data=send_slack_notification(1,username,account_id), headers=headers)
        
            
        
        

def is_user_whitelisted(username):
    iam_user = iam_resource.User(username)
    key = 'userType'
    value = 'Service'
  # If user has no tags, return False
    print("is_user_whitelisted",iam_user.tags)
    if iam_user.tags == None:
        return False
    for tag in iam_user.tags:
        if tag["Key"] == key and tag["Value"].lower() == value.lower():
            print("Ignoring user {}. Whitelisted using Tag".format(username))
            return True
    return False


def is_mfa_enabled(username):
    userMfa = client.list_mfa_devices(UserName=username)
    print("UserName " + username, userMfa)
    if len(userMfa['MFADevices']) == 0:
        return False 
    else:
        print("Ignoring user {}. MFA is already enabled".format(username))
        return True 

def is_policy_exist(policy_name):
    policy_exist = True
    account_id = sts.get_caller_identity()['Account']
    policy_arn = f'arn:aws:iam::{account_id}:policy/{policy_name}'
    try:
     # Check if policy exist Fast and direct
      _ = client.get_policy(PolicyArn=policy_arn)['Policy']
    except client.exceptions.NoSuchEntityException as error:
      print("Creating a new ForceMFA Policy")
      policy_exist = False
    return policy_exist
         
def get_account_alias():
    for response2 in paginator.paginate():
        return response2['AccountAliases']

def is_policy_attached(user,userPolicyList):
    polList = []
    userPolicies = userPolicyList['AttachedPolicies']
    print("is Policy Attached for + " + user, userPolicies)
    
    for policy in userPolicies:
        if policy['PolicyName'] == MFA_POLICY_NAME:
            print("Ignoring user {}. MFA Policy already exist".format(user))
            return True
    return False
    

def send_slack_notification(status_code,user,account_id):
    account_alias = get_account_alias()[0]
    payload = ""
    if status_code == 1:
        payload = """{
              \n\t\"channel\": \"aws-custom-alerts\",
              \n\t\"username\": \"Enforce MFA\",
              \n\t\"icon_emoji\": \"""" + slack_emoji + """\",
              \n\t\"attachments\":[\n
                                   {\n
                                     \"fallback\":\"MFA Enabled\",\n
                                     \"pretext\":\"MFA Enabled\",\n
                                     \"color\":\"#34bb13\",\n
                                     \"fields\":[\n
                                                 {\n
                                                   \"value\":\"*User:* """ + user + """\n*AccountId:* """ + account_id + """\n*Account Alias:* """ + account_alias + """ \"\n
                                                 }\n
                                               ]\n
                                     }\n
                                  ]\n
        }"""
    elif status_code == 2:
        payload = """{
              \n\t\"channel\": \"aws-custom-alerts\",
              \n\t\"username\": \"Enforce MFA\",
              \n\t\"icon_emoji\": \"""" + slack_emoji + """\",
              \n\t\"attachments\":[\n
                                   {\n
                                     \"fallback\":\"MFA Enabled\",\n
                                     \"pretext\":\"MFA Enabled\",\n
                                     \"color\":\"#34bb13\",\n
                                     \"fields\":[\n
                                                 {\n
                                                   \"value\":\":x: Could not attach ForceMFA Policy to the user :x:\n*Reason*: Cannot exceed quota for PoliciesPerUser: 10\n*Account:* """ + account_alias + """\n*User:* """ + user + """\n*AccountId:* """ + account_id + """\",\n
                                                }\n
                                               ]\n
                                     }\n
                                  ]\n
        }"""
    time.sleep(3) # To avoid slack api collusion.
    return payload
```

We have defined two environment variables in Lambda's Configuration section which we have used in our Lambda function
* **WEBHOOK_URL**: This Environment variable we have used to define Webhook url for slack in order to trigger slack notification from our Lambda.
* **WHITELIST_TAG**: At times, there are service accounts which are created as an IAM User(Though not a good practice). Instead, We should consider using IAM Roles for Service Accounts.

**Line 34 - 39:** 

We have imported various Libraries which we will be using to achieve the objective.

**Line 41 - 153:**

We have defined policy which will be created in every account wherever our lambda runs. For policy we have used Deny all approach i.e We have just allowed user to setup MFA and perform basic tasks.

**Line 169-178:** 

We have defined global variables, Global Variable in coding world means that the variable can be used by all the functions and they can directly perform actions on that.

When Lambda is triggered, **lambda_handler** is the first function which is executed. Our lambda will make sure of the following on every run:-

* If the Policy JSON already exist in the account, if not it will create the IAM policy so that it can attach to the users. The reason to check and create policy in the lambda function itself is to scale our lambda function and reduce the manual efforts of creating IAM policy for every account. Nowadays, most companies use multiple accounts for there various use case, it becomes inefficient for us to create IAM policy for every account.
     > **Function used:** is_policy_exist()

* Check whether the user already whitelisted: We are whitelisting users if it is a service account or any other account which is defined in WHITELIST_TAG environment variable.
     > **Function used:** is_user_whitelisted()

* We will not attach the policy if Enforce MFA policy is already attached to the user. This may have happened in the old run. 
     > **Function used:** is_policy_attached()

* Our Lambda will not attach policy if the user has already setup MFA.
     > **Function used:** is_mfa_enabled()

* **get_account_alias():** 

     > This main objective of this function is to get the Alias Name so that it becomes easy for us to recognise the account whenever we recieve notification. As we all know, it is easy to remember name than numbers.

* **send_slack_notification():**

     > As the name suggests, we have used this function to send notification to our slack channel if MFA policy is attached to any user or our lambda failed in someway or the other. 
     
![Macbook]({{site.baseurl}}/assets/img/slack.jpg){: .center-image max-width="100" }

The classic use case which we encountered because of which our Lambda didn't work was that AWS constraints on how many policies(AWS Managed + Customer Managed) can be attached to an IAM User. We found that only 10 policies in total can be attached. So in case, there are 10 policies already attached, our objective to enforce MFA on IAM user who have not enabled MFA would fail badly. 

![Macbook]({{site.baseurl}}/assets/img/slack1.jpg){: .center-image max-width="100" }

In order to get this resolved, we have used **get_attached_policy_count()**(Line 183-193) function which will do the heavy lifting for us.

Since we now understand the flow of our lambda function , Let's get our hands rolling on the Cloudformation template.

Let's look at our CFT-:
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description" : "Deploy Lambda Function to attach Force MFA policy to the user who had not enabled Physical/Virtual MFA.",
  "Parameters" : {
    "SlackWebhookParameter" : {
      "Type" : "String",
      "Default" : "",
      "Description" : "Webhook for Slack Channel"
    },
    "SlackChannelName" : {
        "Type" : "String",
        "Default" : "",
        "Description" : "Name of the slack channel where you want alerts"
      },
      "WhitelistTag" : {
        "Type" : "String",
        "Default" : "userType:Service",
        "Description" : "List of tags that will be whitelisted."
      },
      "S3Bucket" : {
          "Type" : "String",
          "Default" : "",
          "Description" : "Name of the S3 bucket where the lambda is stored"
      },
      "S3Key" : {
          "Type" : "String",
          "Default" : "",
          "Description" : "Key name of the S3 object"
      },
      "LambdaHandler" : {
          "Type" : "String",
          "Default" : "",
          "Description" : "Lambda Handler name E.g: <file_name>.lambda_handler"
      }
    },
  "Resources": {
    "EnforceMFALambda": {
      "Type": "AWS::Lambda::Function",
      "Properties": {
        "FunctionName": "EnforceMFA",
        "Tags": [
          {
            "Key": "CreatedBy",
            "Value": "Security Team"
          }
        ],
        "Handler": { "Ref": "LambdaHandler" },
        "Environment" : {
            "Variables": { 
            "WEBHOOK_URL": { "Ref": "SlackWebhookParameter" }, 
            "SLACK_CHANNEL_NAME": { "Ref": "SlackChannelName" },
            "WHITELIST_TAG": { "Ref": "WhitelistTag" }
        }
        },
        "Role": {
          "Fn::GetAtt": [
            "mfaEnforceLambdaRole",
            "Arn"
          ]
        },
        "Code": {
          "S3Bucket": { "Ref": "S3Bucket" },
          "S3Key": { "Ref": "S3Key" }
        },
        "Runtime": "python3.7",
        "Timeout": 900
      }
    },
    "mfaEnforceLambdaRole": {
        "Type": "AWS::IAM::Role",
        "Properties": {
          "RoleName": "mfaEnforceLambdaRole",
          "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
              "Effect": "Allow",
              "Principal": {
                "Service": [ "lambda.amazonaws.com" ]
              },
              "Action": [ "sts:AssumeRole" ]
            }]
          },
          "Path": "/",
          "Policies": [{
            "PolicyName": "EnforceMFALambdaPolicy",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "iam:CreatePolicy",
                                        "iam:ListPolicies",
                                        "iam:ListAttachedUserPolicies",
                                        "iam:AttachUserPolicy",
                                        "iam:ListAccountAliases",
                                        "iam:ListUsers",
                                        "iam:ListUserPolicies",
                                        "iam:ListMFADevices",
                                        "iam:ListVirtualMFADevices",
                                        "iam:GetLoginProfile",
                                        "iam:ListUserTags",
                                        "iam:GetAccountSummary",
                                        "iam:GetPolicy",
                                        "iam:GetUser",
                                        "logs:CreateLogStream",
                                        "logs:PutLogEvents",
                                        "logs:CreateLogGroup"
                        ],
                        "Resource": "*"
                    }
                ]
            }
          }]
        }
      },
      "ScheduledRule": {
        "Type": "AWS::Events::Rule",
        "Properties": {
          "Description": "Rule to trigger EnforceMFA Lambda",
          "Name" : "enforeMFALambdaRule",
          "ScheduleExpression": "cron(0 12 * * ? *)",
          "State": "ENABLED",
          "Targets": [{
            "Arn": { "Fn::GetAtt": ["EnforceMFALambda", "Arn"] },
            "Id": "TargetFunctionV1"
          }]
        }
      },
      "PermissionForEventsToInvokeLambda": {
        "Type": "AWS::Lambda::Permission",
        "Properties": {
          "FunctionName": { "Ref": "EnforceMFALambda" },
          "Action": "lambda:InvokeFunction",
          "Principal": "events.amazonaws.com",
          "SourceArn": { "Fn::GetAtt": ["ScheduledRule", "Arn"] }
        }
      }
  }
}
```
**Line 354 - 385:**

> We have defined Parameters in `Parameters` section of Stacks. Our CFT is expecting following parameters:
> * LambdaHandler : This executes lambda_handler() function of our lambda code.
> * S3Bucket: Where our Lambda code is stored.
> * S3Key: The file name
> * SlackChannelName: Slack channel where we want to receive notification.
> * SlackWebhookParameter: Slack Web hook url
> * WhitelistTag: The key:value pair against which we want to whitelist IAM Users(Eg: userType:Service).

**Line 435-465:**

   > We have created IAM Policy for our lambda function in order to authorise our Lambda to make changes to an IAM user or make changes in our AWS account.

**Line 467-479:** 

   > ScheduleRule block is the rule used to trigger EventBridge Service of AWS which helps us to run our EnforceMFALambda every 12PM(UTC).

### Conclusion

By Combining all the above blocks, we were able to achieve our main objective of getting our IAM users to setup Multi-factor authentication. Using Cloudformation stacksets helped us to Scale so that whenever new account is spin up, the same stack will be created, hence giving us better AWS security.
