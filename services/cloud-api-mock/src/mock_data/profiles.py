import json
import random
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class OrgProfile:
    """Organization profile for consistent deception"""
    name: str
    industry: str
    cloud_provider: str  # aws, azure, gcp
    regions: List[str]
    account_id: str
    tags: Dict[str, str]
    naming_convention: str
    instance_types: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_name(cls, name: str) -> "OrgProfile":
        profiles = {
            "tech-startup-aws": cls(
                name="TechStart Inc",
                industry="technology",
                cloud_provider="aws",
                regions=["us-east-1", "us-west-2"],
                account_id="123456789012",
                tags={"Environment": "production", "Team": "platform", "Project": "core"},
                naming_convention="ts-{env}-{role}-{num}",
                instance_types=["t3.micro", "t3.small", "t3.medium", "m5.large"],
                metadata={"size": "small", "employee_count": 50}
            ),
            "northbridge-healthcare": cls(
                name="Northbridge Healthcare",
                industry="healthcare",
                cloud_provider="aws",
                regions=["us-east-1"],
                account_id="987654321098",
                tags={"Environment": "production", "Compliance": "HIPAA", "DataClassification": "PHI"},
                naming_convention="nbh-{env}-{role}-{num:03d}",
                instance_types=["m5.large", "m5.xlarge", "r5.large", "r5.xlarge"],
                metadata={"size": "medium", "employee_count": 500}
            ),
            "azure-enterprise": cls(
                name="Azure Enterprise Corp",
                industry="financial-services",
                cloud_provider="azure",
                regions=["eastus", "westus2"],
                account_id="sub-12345678-1234-1234-1234-123456789012",
                tags={"Environment": "prod", "CostCenter": "IT-100", "SecurityZone": "high"},
                naming_convention="aec-{env}-{role}{num}",
                instance_types=["Standard_D2s_v3", "Standard_D4s_v3", "Standard_E4s_v3"],
                metadata={"size": "large", "employee_count": 5000}
            ),
            "gcp-media": cls(
                name="GCP Media Studios",
                industry="media",
                cloud_provider="gcp",
                regions=["us-central1", "us-east1"],
                account_id="gcp-media-studios-prod",
                tags={"env": "prod", "team": "infra", "project": "streaming"},
                naming_convention="gms-{env}-{role}-{num}",
                instance_types=["n2-standard-2", "n2-standard-4", "c2-standard-8"],
                metadata={"size": "medium", "employee_count": 200}
            ),
        }
        return profiles.get(name, profiles["tech-startup-aws"])


# Predefined profiles
PROFILES: Dict[str, OrgProfile] = {
    name: OrgProfile.from_name(name) for name in [
        "tech-startup-aws", "northbridge-healthcare",
        "azure-enterprise", "gcp-media"
    ]
}


def get_profile(name: str) -> OrgProfile:
    return PROFILES.get(name, PROFILES["tech-startup-aws"])


# AWS Resource ID generators
def generate_instance_id() -> str:
    return f"i-{''.join(random.choices('0123456789abcdef', k=17))}"


def generate_volume_id() -> str:
    return f"vol-{''.join(random.choices('0123456789abcdef', k=17))}"


def generate_vpc_id() -> str:
    return f"vpc-{''.join(random.choices('0123456789abcdef', k=17))}"


def generate_subnet_id() -> str:
    return f"subnet-{''.join(random.choices('0123456789abcdef', k=17))}"


def generate_sg_id() -> str:
    return f"sg-{''.join(random.choices('0123456789abcdef', k=17))}"


def generate_key_name() -> str:
    return f"key-{''.join(random.choices('0123456789abcdef', k=8))}"


def generate_bucket_name(profile: OrgProfile) -> str:
    prefix = profile.name.lower().replace(" ", "-").replace(".", "")
    return f"{prefix}-{random.choice(['data', 'logs', 'backups', 'assets', 'ml'])}"


# Fake data generators
def generate_fake_instances(profile: OrgProfile, count: int = 5) -> List[Dict]:
    instances = []
    for i in range(count):
        region = random.choice(profile.regions)
        instance = {
            "InstanceId": generate_instance_id(),
            "InstanceType": random.choice(profile.instance_types),
            "State": {"Name": random.choice(["running", "running", "running", "stopped"])},
            "PrivateIpAddress": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "PublicIpAddress": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,254)}" if random.random() > 0.3 else None,
            "VpcId": generate_vpc_id(),
            "SubnetId": generate_subnet_id(),
            "SecurityGroups": [{"GroupId": generate_sg_id(), "GroupName": f"{profile.naming_convention.format(env='prod', role='web', num=i+1)}"}],
            "Tags": [
                {"Key": "Name", "Value": profile.naming_convention.format(env="prod", role=random.choice(["web", "api", "db", "worker"]), num=i+1)},
                {"Key": "Environment", "Value": "production"},
                {"Key": "ManagedBy", "Value": "terraform"},
            ],
            "LaunchTime": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "Placement": {"AvailabilityZone": f"{region}{random.choice(['a','b','c'])}"},
            "Architecture": "x86_64",
            "RootDeviceType": "ebs",
            "VirtualizationType": "hvm",
        }
        instances.append(instance)
    return instances


def generate_fake_volumes(profile: OrgProfile, count: int = 3) -> List[Dict]:
    volumes = []
    for i in range(count):
        region = random.choice(profile.regions)
        volumes.append({
            "VolumeId": generate_volume_id(),
            "Size": random.choice([20, 50, 100, 200, 500]),
            "VolumeType": random.choice(["gp3", "gp2", "io1", "io2"]),
            "State": "available",
            "AvailabilityZone": f"{region}{random.choice(['a','b','c'])}",
            "CreateTime": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "Tags": [{"Key": "Name", "Value": f"{profile.naming_convention.format(env='prod', role='data', num=i+1)}"}],
        })
    return volumes


def generate_fake_vpcs(profile: OrgProfile) -> List[Dict]:
    return [{
        "VpcId": generate_vpc_id(),
        "CidrBlock": f"10.{random.randint(0,255)}.0.0/16",
        "State": "available",
        "IsDefault": False,
        "Tags": [{"Key": "Name", "Value": f"{profile.name.replace(' ', '-')}-vpc"}],
        "OwnerId": profile.account_id,
    }]


def generate_fake_subnets(profile: OrgProfile) -> List[Dict]:
    subnets = []
    vpc_id = generate_vpc_id()
    for region in profile.regions:
        for az_suffix in ['a', 'b', 'c']:
            subnets.append({
                "SubnetId": generate_subnet_id(),
                "VpcId": vpc_id,
                "CidrBlock": f"10.{random.randint(0,255)}.{random.randint(0,255)}.0/24",
                "AvailabilityZone": f"{region}{az_suffix}",
                "State": "available",
                "AvailableIpAddressCount": random.randint(100, 250),
                "Tags": [{"Key": "Name", "Value": f"{profile.naming_convention.format(env='prod', role='subnet', num=len(subnets)+1)}"}],
            })
    return subnets


def generate_fake_security_groups(profile: OrgProfile) -> List[Dict]:
    sgs = []
    sg_names = ["web-sg", "db-sg", "api-sg", "lb-sg", "bastion-sg"]
    for name in sg_names:
        sgs.append({
            "GroupId": generate_sg_id(),
            "GroupName": f"{profile.naming_convention.format(env='prod', role=name, num=1)}",
            "Description": f"Security group for {name}",
            "VpcId": generate_vpc_id(),
            "IpPermissions": [
                {"FromPort": 22, "ToPort": 22, "IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                {"FromPort": 80, "ToPort": 80, "IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                {"FromPort": 443, "ToPort": 443, "IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            ],
            "Tags": [{"Key": "Name", "Value": name}],
        })
    return sgs


def generate_fake_buckets(profile: OrgProfile, count: int = 4) -> List[Dict]:
    buckets = []
    for i in range(count):
        bucket_name = generate_bucket_name(profile)
        buckets.append({
            "Name": bucket_name,
            "CreationDate": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        })
    return buckets


def generate_fake_iam_users(profile: OrgProfile) -> List[Dict]:
    roles = ["admin", "developer", "ci-cd", "monitoring", "backup"]
    users = []
    for role in roles:
        users.append({
            "UserName": f"{profile.naming_convention.format(env='prod', role=role, num=1)}",
            "UserId": f"AIDA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}",
            "Arn": f"arn:aws:iam::{profile.account_id}:user/{role}",
            "CreateDate": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "PasswordLastUsed": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z") if random.random() > 0.2 else None,
            "Tags": [{"Key": "Role", "Value": role}],
        })
    return users


def generate_fake_iam_roles(profile: OrgProfile) -> List[Dict]:
    return [
        {
            "RoleName": f"{profile.naming_convention.format(env='prod', role='ec2-role', num=1)}",
            "RoleId": f"AROA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}",
            "Arn": f"arn:aws:iam::{profile.account_id}:role/ec2-role",
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
            "RoleName": f"{profile.naming_convention.format(env='prod', role='lambda-role', num=1)}",
            "RoleId": f"AROA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}",
            "Arn": f"arn:aws:iam::{profile.account_id}:role/lambda-role",
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


# Mock cloud metadata (for 169.254.169.254 simulation)
def generate_aws_metadata(profile: OrgProfile) -> Dict:
    instance_id = generate_instance_id()
    region = random.choice(profile.regions)
    az = f"{region}{random.choice(['a','b','c'])}"

    return {
        "instance-id": instance_id,
        "instance-type": random.choice(profile.instance_types),
        "placement": {"availability-zone": az},
        "local-ipv4": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "public-ipv4": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,254)}",
        "ami-id": f"ami-{''.join(random.choices('0123456789abcdef', k=8))}",
        "ami-launch-index": "0",
        "ami-manifest-path": "(unknown)",
        "ancestor-ami-ids": "[]",
        "block-device-mapping": {
            "ephemeral0": "sdb",
            "root": f"/dev/sda1={generate_volume_id()}:true"
        },
        "instance-action": "none",
        "instance-life-cycle": "on-demand",
        "local-hostname": f"ip-10-{random.randint(0,255)}-{random.randint(0,255)}-{random.randint(1,254)}.{az}.compute.internal",
        "mac": f"02:{':'.join([''.join(random.choices('0123456789abcdef', k=2)) for _ in range(5)])}",
        "network": {
            "interfaces": {
                "macs": {
                    f"02:{':'.join([''.join(random.choices('0123456789abcdef', k=2)) for _ in range(5)])}": {
                        "interface-id": f"eni-{''.join(random.choices('0123456789abcdef', k=17))}",
                        "subnet-id": generate_subnet_id(),
                        "vpc-id": generate_vpc_id(),
                        "local-ipv4s": [f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"],
                        "ipv6s": [],
                        "owner-id": profile.account_id,
                        "security-groups": [generate_sg_id()],
                        "subnet-ipv4-cidr-block": "10.0.1.0/24",
                        "vpc-ipv4-cidr-block": "10.0.0.0/16",
                    }
                }
            }
        },
        "profile": "default",
        "public-keys": {
            f"key-{random.randint(1,3)}": f"ssh-rsa AAAAB3NzaC1yc2E...{generate_key_name()}"
        },
        "reservation-id": f"r-{''.join(random.choices('0123456789abcdef', k=17))}",
        "security-groups": [f"{profile.naming_convention.format(env='prod', role='web', num=1)}"],
        "services": {"domain": "amazonaws.com", "partition": "aws"},
    }


# Cloud provider profiles
CLOUD_PROFILES = {
    "aws": {
        "metadata_base": "http://169.254.169.254/latest",
        "identity_endpoint": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "generators": {
            "instances": generate_fake_instances,
            "volumes": generate_fake_volumes,
            "vpcs": generate_fake_vpcs,
            "subnets": generate_fake_subnets,
            "security_groups": generate_fake_security_groups,
            "buckets": generate_fake_buckets,
            "iam_users": generate_fake_iam_users,
            "iam_roles": generate_fake_iam_roles,
            "metadata": generate_aws_metadata,
        }
    },
    "azure": {
        "metadata_base": "http://169.254.169.254/metadata/instance",
        "generators": {
            "vms": lambda p, c=5: [{
                "vmId": f"{''.join(random.choices('0123456789abcdef', k=32))}",
                "name": f"{p.naming_convention.format(env='prod', role=random.choice(['web','db','api']), num=i+1)}",
                "location": random.choice(p.regions),
                "vmSize": random.choice(p.instance_types),
                "osType": "Linux",
            } for i in range(c)],
            "resource_groups": lambda p: [{
                "id": f"/subscriptions/{p.account_id}/resourceGroups/{p.name.lower().replace(' ', '-')}-rg",
                "name": f"{p.name.lower().replace(' ', '-')}-rg",
                "location": p.regions[0],
            }],
            "storage": lambda p, c=3: [{
                "name": f"{p.name.lower().replace(' ', '')}storage{i}",
                "id": f"/subscriptions/{p.account_id}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/{p.name.lower().replace(' ', '')}storage{i}",
                "location": p.regions[0],
                "sku": {"name": "Standard_LRS"},
            } for i in range(c)],
        }
    },
    "gcp": {
        "metadata_base": "http://metadata.google.internal/computeMetadata/v1",
        "generators": {
            "instances": lambda p, c=5: [{
                "id": f"{''.join(random.choices('0123456789', k=19))}",
                "name": f"{p.naming_convention.format(env='prod', role=random.choice(['web','db','api']), num=i+1)}",
                "zone": f"projects/{p.account_id}/zones/{random.choice(p.regions)}-a",
                "machineType": f"projects/{p.account_id}/zones/{random.choice(p.regions)}-a/machineTypes/{random.choice(p.instance_types)}",
                "status": "RUNNING",
            } for i in range(c)],
            "disks": lambda p, c=3: [{
                "id": f"{''.join(random.choices('0123456789', k=19))}",
                "name": f"{p.name.lower().replace(' ', '-')}-disk-{i}",
                "zone": f"projects/{p.account_id}/zones/{p.regions[0]}-a",
                "type": f"projects/{p.account_id}/zones/{p.regions[0]}-a/diskTypes/pd-standard",
                "sizeGb": str(random.choice([50, 100, 200, 500])),
            } for i in range(c)],
        }
    }
}