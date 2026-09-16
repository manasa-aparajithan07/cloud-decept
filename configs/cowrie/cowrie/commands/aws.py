# AWS CLI command emulation for Cowrie
# Place this in /cowrie/cowrie/commands/aws.py

from __future__ import annotations

import json
import random
from datetime import datetime, timezone
from typing import Dict, List, Any

import urllib.request
import urllib.error

from cowrie.shell.command import HoneyPotCommand

commands = {}


class CommandAWS(HoneyPotCommand):
    """
    AWS CLI command emulator for Cowrie honeypot.
    Provides fake AWS CLI responses via cloud-api-mock service or local fallback.
    """

    # Define which commands we will handle via the cloud-api-mock service
    API_MOCK_ENDPOINTS = {
        ('ec2', 'describe-instances'): ('/aws/ec2/describe-instances', 'GET'),
        ('ec2', 'describe-volumes'): ('/aws/ec2/describe-volumes', 'GET'),
        ('ec2', 'describe-vpcs'): ('/aws/ec2/describe-vpcs', 'GET'),
        ('ec2', 'describe-subnets'): ('/aws/ec2/describe-subnets', 'GET'),
        ('ec2', 'describe-security-groups'): ('/aws/ec2/describe-security-groups', 'GET'),
        ('s3', 'ls'): ('/aws/s3/list-buckets', 'GET'),
        ('s3', 'list-buckets'): ('/aws/s3/list-buckets', 'GET'),
        ('iam', 'list-users'): ('/aws/iam/list-users', 'GET'),
        ('iam', 'list-roles'): ('/aws/iam/list-roles', 'GET'),
    }

    def __init__(self, protocol, *args):
        super().__init__(protocol, *args)
        self.profile = "default"
        self.region = "us-east-1"
        self.output = "json"

    def _call_api_mock(self, endpoint, method='GET', body=None):
        """Make a request to the cloud-api-mock service"""
        try:
            # Use the Cowrie session ID for consistency
            session_id = getattr(self.protocol, 'id', 'unknown')
            url = f"http://cloud-api-mock:8080{endpoint}"
            headers = {
                "Content-Type": "application/json",
                "x-session-id": str(session_id)
            }
            data = None
            if body is not None:
                data = json.dumps(body).encode('utf-8')

            req = urllib.request.Request(url, data=data, headers=headers, method=method)

            with urllib.request.urlopen(req) as response:
                return json.loads(response.read().decode())
        except Exception as e:
            # If the API mock is unavailable, fall back to local implementation
            self.errorWrite(f"Failed to connect to cloud API mock: {e}")
            return None

    def get_fake_instances(self) -> List[Dict]:
        return [
            {
                "InstanceId": f"i-{''.join(random.choices('0123456789abcdef', k=17))}",
                "InstanceType": random.choice(["t3.micro", "t3.small", "t3.medium", "m5.large"]),
                "State": {"Name": random.choice(["running", "running", "running", "stopped"])},
                "PrivateIpAddress": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                "PublicIpAddress": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,254)}" if random.random() > 0.3 else None,
                "VpcId": f"vpc-{''.join(random.choices('0123456789abcdef', k=17))}",
                "SubnetId": f"subnet-{''.join(random.choices('0123456789abcdef', k=17))}",
                "SecurityGroups": [{"GroupId": f"sg-{''.join(random.choices('0123456789abcdef', k=17))}", "GroupName": f"{self.naming_convention.format(env='prod', role='web', num=i+1)}"}],
                "Tags": [
                    {"Key": "Name", "Value": self.naming_convention.format(env="prod", role=random.choice(["web", "api", "db", "worker"]), num=i+1)},
                    {"Key": "Environment", "Value": "production"},
                    {"Key": "ManagedBy", "Value": "terraform"},
                ],
                "LaunchTime": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "Placement": {"AvailabilityZone": f"{self.region}{random.choice(['a','b','c'])}"},
                "Architecture": "x86_64",
                "RootDeviceType": "ebs",
                "VirtualizationType": "hvm"
            }
            for _ in range(random.randint(3, 8))
        ]

    def get_fake_buckets(self) -> List[Dict]:
        return [
            {"Name": f"company-{name}", "CreationDate": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
            for name in ["data-lake", "logs", "backups", "assets", "ml-models", "terraform-state"]
        ]

    def get_fake_users(self) -> List[Dict]:
        roles = ["admin", "developer", "ci-cd", "monitoring", "backup"]
        return [
            {
                "UserName": role,
                "UserId": f"AIDA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}",
                "Arn": f"arn:aws:iam::123456789012:user/{role}",
                "CreateDate": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "PasswordLastUsed": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z") if random.random() > 0.2 else None,
                "Tags": [{"Key": "Role", "Value": role}],
            }
            for role in roles
        ]

    def get_fake_roles(self) -> List[Dict]:
        return [
            {
                "RoleName": f"{self.naming_convention.format(env='prod', role='ec2-role', num=1)}",
                "RoleId": f"AROA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}",
                "Arn": f"arn:aws:iam::123456789012:role/ec2-role",
                "CreateDate": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole"
                    }]
                },
            },
            {
                "RoleName": f"{self.naming_convention.format(env='prod', role='lambda-role', num=1)}",
                "RoleId": f"AROA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}",
                "Arn": f"arn:aws:iam::123456789012:role/lambda-role",
                "CreateDate": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole"
                    }]
                },
            }
        ]

    def get_fake_access_keys(self) -> List[Dict]:
        return [
            {
                "AccessKeyId": f"AKIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}",
                "Status": "Active",
                "UserName": "admin"
            }
        ]

    def naming_convention(self, env='prod', role='web', num=1):
        """Simple naming convention for resources"""
        return f"{env}-{role}-{num}"

    def call(self) -> None:
        """Execute AWS CLI command"""
        if len(self.args) < 1:
            self.errorWrite("usage: aws <service> <operation> [params]\n")
            return

        service = self.args[0]

        # Handle version flag
        if "--version" in self.args or "-v" in self.args:
            self.write("aws-cli/2.15.0 Python/3.11.6 Linux/5.15.0-1057-aws exe/x86_64.ubuntu.22\n")
            return

        if len(self.args) < 2:
            self.errorWrite("usage: aws <service> <operation> [params]\n")
            return

        operation = self.args[1]

        # First, try to handle via cloud-api-mock for supported commands
        if (service, operation) in self.API_MOCK_ENDPOINTS:
            endpoint, method = self.API_MOCK_ENDPOINTS[(service, operation)]
            result = self._call_api_mock(endpoint, method)
            if result is not None:
                self.write(json.dumps(result, indent=2) + "\n")
                return
            # If API mock fails, fall back to local implementation below

        # EC2 commands
        if service == "ec2":
            if operation == "describe-instances":
                self.write(json.dumps({"Reservations": [{"Instances": self.get_fake_instances()}]}, indent=2) + "\n")
                return
            elif operation == "describe-volumes":
                self.write(json.dumps({"Volumes": [
                    {"VolumeId": f"vol-{''.join(random.choices('0123456789abcdef', k=17))}", "Size": random.choice([20, 50, 100, 200]), "VolumeType": "gp3", "State": "available"}
                    for _ in range(5)
                ]}, indent=2) + "\n")
                return
            elif operation == "describe-vpcs":
                self.write(json.dumps({"Vpcs": [{"VpcId": f"vpc-{''.join(random.choices('0123456789abcdef', k=17))}", "CidrBlock": f"10.{random.randint(0,255)}.0.0/16", "State": "available", "IsDefault": False}]}, indent=2) + "\n")
                return
            elif operation == "describe-subnets":
                subnets = [{"SubnetId": f"subnet-{''.join(random.choices('0123456789abcdef', k=17))}", "VpcId": f"vpc-{''.join(random.choices('0123456789abcdef', k=17))}", "CidrBlock": f"10.{random.randint(0,255)}.{random.randint(0,255)}.0/24", "AvailabilityZone": f"{self.region}{random.choice(['a','b','c'])}", "State": "available", "AvailableIpAddressCount": random.randint(100, 250)} for _ in range(6)]
                self.write(json.dumps({"Subnets": subnets}, indent=2) + "\n")
                return
            elif operation == "describe-security-groups":
                self.write(json.dumps({"SecurityGroups": [{"GroupId": f"sg-{''.join(random.choices('0123456789abcdef', k=17))}", "GroupName": f"default", "Description": "Default security group", "VpcId": f"vpc-{''.join(random.choices('0123456789abcdef', k=17))}"}]}, indent=2) + "\n")
                return
            elif operation == "run-instances":
                self.write(json.dumps({"Instances": [self.get_fake_instances()[0]]}, indent=2) + "\n")
                return
            elif operation == "terminate-instances":
                instance_id = self.args[self.args.index("--instance-ids")+1] if "--instance-ids" in self.args else "i-12345678"
                self.write(json.dumps({"TerminatingInstances": [{"InstanceId": instance_id, "CurrentState": {"Name": "shutting-down"}}]}, indent=2) + "\n")
                return

        # S3 commands
        elif service == "s3":
            if operation == "ls" or operation == "list-buckets":
                self.write(json.dumps({"Buckets": self.get_fake_buckets()}, indent=2) + "\n")
                return
            elif operation == "cp":
                etag = f"\"{''.join(random.choices('0123456789abcdef', k=32))}\""
                self.write(json.dumps({"ETag": etag}, indent=2) + "\n")
                return

        # IAM commands
        elif service == "iam":
            if operation == "list-users":
                self.write(json.dumps({"Users": self.get_fake_users()}, indent=2) + "\n")
                return
            elif operation == "list-roles":
                self.write(json.dumps({"Roles": self.get_fake_roles()}, indent=2) + "\n")
                return
            elif operation == "list-access-keys":
                self.write(json.dumps({"AccessKeyMetadata": self.get_fake_access_keys()}, indent=2) + "\n")
                return
            elif operation == "create-access-key":
                access_key = {
                    "AccessKeyId": f"AKIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}",
                    "SecretAccessKey": f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+', k=40))}",
                    "Status": "Active"
                }
                self.write(json.dumps({"AccessKey": access_key}, indent=2) + "\n")
                return

        # STS commands
        elif service == "sts":
            if operation == "get-caller-identity":
                self.write(json.dumps({"Account": "123456789012", "UserId": f"AIDA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}", "Arn": f"arn:aws:iam::123456789012:user/admin"}, indent=2) + "\n")
                return
            elif operation == "assume-role":
                # Parse arguments for role ARN and session name
                role_arn = ""
                role_session_name = "honeypot-session"
                i = 0
                while i < len(self.args):
                    if self.args[i] == "--role-arn" and i+1 < len(self.args):
                        role_arn = self.args[i+1]
                        i += 2
                    elif self.args[i] == "--role-session-name" and i+1 < len(self.args):
                        role_session_name = self.args[i+1]
                        i += 2
                    else:
                        i += 1
                if not role_arn:
                    role_arn = f"arn:aws:iam::123456789012:role/EC2Role"

                credentials = {
                    "AccessKeyId": f"ASIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}",
                    "SecretAccessKey": f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+', k=40))}",
                    "SessionToken": f"IQoJb3JpZ2luX2VjE...{''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=200))}",
                    "Expiration": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                }

                assumed_role_user = {
                    "AssumedRoleId": f"AROA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}:{role_session_name}",
                    "Arn": role_arn
                }

                response = {
                    "Credentials": credentials,
                    "AssumedRoleUser": assumed_role_user,
                    "PackedPolicySize": 0
                }
                self.write(json.dumps(response, indent=2) + "\n")
                return

        self.errorWrite(f"Unknown service/operation: {service} {operation}\n")


# Register the command
commands["/usr/bin/aws"] = CommandAWS
commands["aws"] = CommandAWS