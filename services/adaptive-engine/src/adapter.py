"""Adaptive Response Engine - Modifies honeypot responses based on predicted intent"""

import random
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timezone
from faker import Faker

logger = logging.getLogger(__name__)
fake = Faker()

# Intent category to adaptation strategy mapping
ADAPTATION_STRATEGIES = {
    "cloud_recon": {
        "name": "Enrich Responses",
        "description": "Provide rich, detailed resource listings to encourage deeper enumeration",
        "actions": ["add_fake_resources", "add_detailed_metadata", "add_cross_region_resources"]
    },
    "credential_hunting": {
        "name": "Plant Credentials",
        "description": "Inject fake but convincing credentials at strategic moments",
        "actions": ["plant_aws_keys", "plant_ssh_keys", "plant_env_vars", "plant_config_files"]
    },
    "privilege_escalation": {
        "name": "Delayed Success",
        "description": "Fail initial attempts, then grant fake elevated access to encourage exploration",
        "actions": ["fail_first_attempts", "grant_fake_admin", "create_fake_privileged_role"]
    },
    "data_access": {
        "name": "Create Tempting Data",
        "description": "Generate fake sensitive data files and database entries",
        "actions": ["create_fake_secrets", "create_fake_database", "create_fake_api_keys"]
    },
    "persistence": {
        "name": "Allow & Monitor",
        "description": "Let attacker create backdoors, but track everything",
        "actions": ["allow_key_creation", "allow_user_creation", "allow_scheduled_tasks"]
    },
    "lateral_movement": {
        "name": "Fabricate Topology",
        "description": "Create convincing internal network with attractive targets",
        "actions": ["add_internal_hosts", "add_vpc_peering", "add_vpn_connections", "add_bastion_hosts"]
    },
    "unknown": {
        "name": "Default",
        "description": "Standard response without adaptation",
        "actions": []
    }
}

# Cloud-specific fake data generators
class CredentialGenerator:
    """Generate convincing fake credentials"""

    @staticmethod
    def aws_access_key():
        prefix = random.choice(["AKIA", "ASIA", "AROA", "AIDA"])
        return f"{prefix}{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}"

    @staticmethod
    def aws_secret_key():
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+'
        return ''.join(random.choices(chars, k=40))

    @staticmethod
    def aws_session_token():
        return f"IQoJb3JpZ2luX2VjE{''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=200))}"

    @staticmethod
    def ssh_private_key():
        return f"""-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA{fake.sha256()[:40]}
{fake.sha256()[:64]}
{fake.sha256()[:64]}
{fake.sha256()[:32]}
-----END RSA PRIVATE KEY-----"""

    @staticmethod
    def azure_client_secret():
        return fake.password(length=40, special_chars=True)

    @staticmethod
    def gcp_service_account_key():
        return {
            "type": "service_account",
            "project_id": "fake-project-12345",
            "private_key_id": fake.sha256()[:32],
            "private_key": CredentialGenerator.ssh_private_key(),
            "client_email": f"service-account@{fake.domain_name()}",
            "client_id": str(random.randint(100000000000000000000, 999999999999999999999)),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": f"https://www.googleapis.com/robot/v1/metadata/x509/service-account%40{fake.domain_name()}"
        }


class FakeResourceGenerator:
    """Generate fake cloud resources"""

    INSTANCE_NAMES = ["web-server", "api-gateway", "database", "worker", "cache", "lb", "vpn", "bastion", "monitoring", "ci-runner"]
    INSTANCE_TYPES = {
        "aws": ["t3.micro", "t3.small", "t3.medium", "m5.large", "m5.xlarge", "r5.large", "c5.large"],
        "azure": ["Standard_B2s", "Standard_D2s_v3", "Standard_D4s_v3", "Standard_E4s_v3"],
        "gcp": ["e2-micro", "e2-small", "e2-medium", "n2-standard-2", "n2-standard-4"]
    }

    @staticmethod
    def generate_instances(cloud: str, count: int = 10, profile: str = "tech-startup-aws") -> List[Dict]:
        instances = []
        for i in range(count):
            if cloud == "aws":
                instances.append({
                    "InstanceId": f"i-{''.join(random.choices('0123456789abcdef', k=17))}",
                    "InstanceType": random.choice(FakeResourceGenerator.INSTANCE_TYPES["aws"]),
                    "State": {"Name": "running"},
                    "PrivateIpAddress": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                    "PublicIpAddress": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,254)}",
                    "Tags": [
                        {"Key": "Name", "Value": f"{profile[:3]}-{random.choice(FakeResourceGenerator.INSTANCE_NAMES)}-{i+1:03d}"},
                        {"Key": "Environment", "Value": "production"}
                    ],
                    "Placement": {"AvailabilityZone": f"us-east-1{random.choice(['a','b','c'])}"}
                })
            elif cloud == "azure":
                instances.append({
                    "name": f"{profile[:3]}-{random.choice(FakeResourceGenerator.INSTANCE_NAMES)}-{i+1:03d}",
                    "location": random.choice(["eastus", "westus2", "centralus"]),
                    "properties": {
                        "hardwareProfile": {"vmSize": random.choice(FakeResourceGenerator.INSTANCE_TYPES["azure"])},
                        "storageProfile": {"osDisk": {"osType": "Linux"}},
                        "provisioningState": "Succeeded"
                    }
                })
            elif cloud == "gcp":
                instances.append({
                    "name": f"{profile[:3]}-{random.choice(FakeResourceGenerator.INSTANCE_NAMES)}-{i+1:03d}",
                    "zone": f"us-central1-{random.choice(['a','b','c'])}",
                    "machineType": f"projects/fake-project/zones/us-central1-a/machineTypes/{random.choice(FakeResourceGenerator.INSTANCE_TYPES['gcp'])}",
                    "status": "RUNNING",
                    "networkInterfaces": [{
                        "networkIP": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                    }]
                })
        return instances


def adapt_response(
    intent: str,
    original_response: Dict[str, Any],
    session_context: Dict[str, Any],
    endpoint: str = "",
    cloud_provider: str = "aws",
    org_profile: str = "tech-startup-aws"
) -> Dict[str, Any]:
    """
    Main adaptation function - modifies response based on predicted intent
    """
    if intent == "unknown" or intent not in ADAPTATION_STRATEGIES:
        return original_response

    strategy = ADAPTATION_STRATEGIES[intent]
    adapted = original_response.copy()

    # Track adaptation attempts for progressive disclosure
    cred_attempts = session_context.get("credential_attempts", 0)
    priv_esc_attempts = session_context.get("privilege_escalation_attempts", 0)
    session_context["credential_attempts"] = cred_attempts + 1
    session_context["privilege_escalation_attempts"] = priv_esc_attempts + 1

    # Apply strategy-specific adaptations
    if intent == "cloud_recon":
        adapted = _adapt_cloud_recon(adapted, cloud_provider, org_profile, session_context)

    elif intent == "credential_hunting":
        adapted = _adapt_credential_hunting(adapted, session_context, endpoint, cloud_provider)

    elif intent == "privilege_escalation":
        adapted = _adapt_privilege_escalation(adapted, session_context, endpoint, cloud_provider)

    elif intent == "data_access":
        adapted = _adapt_data_access(adapted, cloud_provider, session_context)

    elif intent == "persistence":
        adapted = _adapt_persistence(adapted, cloud_provider, session_context)

    elif intent == "lateral_movement":
        adapted = _adapt_lateral_movement(adapted, cloud_provider, session_context)

    # Add adaptation metadata
    adapted["_adaptation"] = {
        "intent": intent,
        "strategy": strategy["name"],
        "applied_at": datetime.now(timezone.utc).isoformat(),
        "session_credential_attempts": cred_attempts + 1
    }

    return adapted


def _adapt_cloud_recon(response: Dict, cloud: str, profile: str, context: Dict) -> Dict:
    """Enrich responses with more fake resources"""
    if "Reservations" in response:
        # Add more fake instances
        extra = FakeResourceGenerator.generate_instances(cloud, random.randint(3, 8), profile)
        for res in response["Reservations"]:
            if "Instances" in res:
                res["Instances"].extend(extra[:random.randint(1, 3)])

    if "Buckets" in response or "buckets" in response:
        # Add more buckets
        key = "Buckets" if "Buckets" in response else "buckets"
        extra_buckets = [
            {"Name": f"{profile}-{name}", "CreationDate": datetime.now(timezone.utc).isoformat()}
            for name in ["ml-data", "analytics", "terraform-state", "cdn-cache", "backups-2024"]
        ]
        response[key].extend(random.sample(extra_buckets, random.randint(1, 3)))

    if "Users" in response:
        # Add more IAM users
        extra_users = [
            {"UserName": name, "UserId": f"AIDA{fake.sha256()[:16]}", "Arn": f"arn:aws:iam::123456789012:user/{name}"}
            for name in ["data-engineer", "security-audit", "backup-service", "k8s-admin"]
        ]
        response["Users"].extend(random.sample(extra_users, random.randint(1, 2)))

    return response


def _adapt_credential_hunting(response: Dict, context: Dict, endpoint: str, cloud: str) -> Dict:
    """Plant fake credentials in responses"""
    attempts = context.get("credential_attempts", 0)

    # Plant credentials after 3+ attempts or on specific endpoints
    should_plant = attempts >= 3 or any(x in endpoint for x in ["credentials", "keys", "assume-role", "access-key"])

    if should_plant:
        if "Credentials" in response:
            # STS AssumeRole response - make credentials look realistic
            response["Credentials"] = {
                "AccessKeyId": CredentialGenerator.aws_access_key(),
                "SecretAccessKey": CredentialGenerator.aws_secret_key(),
                "SessionToken": CredentialGenerator.aws_session_token(),
                "Expiration": datetime.now(timezone.utc).isoformat()
            }
        elif "AccessKey" in response:
            # CreateAccessKey response
            response["AccessKey"] = {
                "UserName": "admin",
                "AccessKeyId": CredentialGenerator.aws_access_key(),
                "SecretAccessKey": CredentialGenerator.aws_secret_key(),
                "Status": "Active",
                "CreateDate": datetime.now(timezone.utc).isoformat()
            }
        elif "AccessKeyMetadata" in response:
            # ListAccessKeys - add a fake active key
            response["AccessKeyMetadata"].append({
                "UserName": "admin",
                "AccessKeyId": CredentialGenerator.aws_access_key(),
                "Status": "Active",
                "CreateDate": datetime.now(timezone.utc).isoformat()
            })

    return response


def _adapt_privilege_escalation(response: Dict, context: Dict, endpoint: str, cloud: str) -> Dict:
    """Grant fake elevated privileges after failed attempts"""
    attempts = context.get("privilege_escalation_attempts", 0)

    # Fail first 2 attempts, then succeed
    if "assume-role" in endpoint and attempts < 2:
        # Return error for first attempts
        raise AdaptationError("AccessDenied", "User is not authorized to perform: sts:AssumeRole")

    if "attach-user-policy" in endpoint and attempts < 2:
        raise AdaptationError("AccessDenied", "User is not authorized to perform: iam:AttachUserPolicy")

    if attempts >= 2:
        # Grant fake admin access
        if "assume-role" in endpoint:
            response["Credentials"] = {
                "AccessKeyId": CredentialGenerator.aws_access_key(),
                "SecretAccessKey": CredentialGenerator.aws_secret_key(),
                "SessionToken": CredentialGenerator.aws_session_token(),
                "Expiration": datetime.now(timezone.utc).isoformat()
            }
            response["AssumedRoleUser"] = {
                "Arn": f"arn:aws:iam::123456789012:role/AdminRole/fake-session",
                "AssumedRoleId": f"AROA{fake.sha256()[:16]}:fake-session"
            }

    return response


def _adapt_data_access(response: Dict, cloud: str, context: Dict) -> Dict:
    """Create tempting fake data files"""
    if "Contents" in response or "Objects" in response:
        # S3/GCS list response - add tempting file names
        key = "Contents" if "Contents" in response else "Objects"
        tempting_files = [
            {"Key": "backups/production-db-2024-01-15.sql.gz", "Size": 2048576000, "LastModified": datetime.now(timezone.utc).isoformat()},
            {"Key": "secrets/api-keys.json", "Size": 1024, "LastModified": datetime.now(timezone.utc).isoformat()},
            {"Key": "config/production.env", "Size": 2048, "LastModified": datetime.now(timezone.utc).isoformat()},
            {"Key": "data/customers.csv", "Size": 52428800, "LastModified": datetime.now(timezone.utc).isoformat()},
            {"Key": "ml-models/model-weights.pkl", "Size": 1073741824, "LastModified": datetime.now(timezone.utc).isoformat()},
            {"Key": "ssh-keys/authorized_keys", "Size": 4096, "LastModified": datetime.now(timezone.utc).isoformat()},
        ]
        response[key].extend(random.sample(tempting_files, random.randint(2, 4)))

    return response


def _adapt_persistence(response: Dict, cloud: str, context: Dict) -> Dict:
    """Allow persistence mechanisms and track them"""
    # Allow key pair creation, user creation, etc.
    if "KeyPair" in response:
        # Return a convincing key pair
        response["KeyPair"] = {
            "KeyPairId": f"key-{''.join(random.choices('0123456789abcdef', k=17))}",
            "KeyName": f"{cloud}-deploy-key-{random.randint(100,999)}",
            "KeyFingerprint": f"{':'.join(random.choices('0123456789abcdef', k=20))}",
            "KeyMaterial": CredentialGenerator.ssh_private_key()
        }
    return response


def _adapt_lateral_movement(response: Dict, cloud: str, context: Dict) -> Dict:
    """Fabricate internal network topology"""
    if "Reservations" in response:
        # Add internal-only instances (no public IP)
        internal_instances = []
        for i in range(random.randint(2, 5)):
            internal_instances.append({
                "InstanceId": f"i-{''.join(random.choices('0123456789abcdef', k=17))}",
                "InstanceType": "t3.medium",
                "State": {"Name": "running"},
                "PrivateIpAddress": f"10.0.{random.randint(10,20)}.{random.randint(1,254)}",
                "PublicIpAddress": None,  # No public IP - internal only
                "Tags": [
                    {"Key": "Name", "Value": f"internal-{random.choice(['db', 'cache', 'worker', 'app'])}-{i+1:03d}"},
                    {"Key": "Role", "Value": "internal"}
                ],
                "Placement": {"AvailabilityZone": f"us-east-1{random.choice(['a','b','c'])}"},
                "NetworkInterfaces": [{
                    "PrivateIpAddresses": [{
                        "PrivateIpAddress": f"10.0.{random.randint(10,20)}.{random.randint(1,254)}",
                        "Primary": True
                    }],
                    "Groups": [{"GroupId": f"sg-internal-{random.randint(100,999)}", "GroupName": "internal-sg"}]
                }]
            })
        for res in response["Reservations"]:
            if "Instances" in res:
                res["Instances"].extend(internal_instances)
    return response


class AdaptationError(Exception):
    """Exception to signal adaptation should return an error response"""
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


# Session usage tracking
def should_adapt(intent: str, context: Dict, endpoint: str) -> bool:
    """Determine if adaptation should be applied"""
    if intent == "unknown":
        return False

    # Credential hunting: adapt after 3+ credential-related commands
    if intent == "credential_hunting":
        cred_cmds = context.get("credential_commands", 0)
        return cred_cmds >= 3

    # Privilege escalation: adapt after 2+ attempts
    if intent == "privilege_escalation":
        attempts = context.get("privilege_escalation_attempts", 0)
        return attempts >= 2

    # Cloud recon: always enrich
    if intent == "cloud_recon":
        return True

    # Data access: adapt when listing storage
    if intent == "data_access":
        return "list" in endpoint.lower() or "ls" in endpoint.lower()

    # Persistence and lateral movement: always adapt
    if intent in ["persistence", "lateral_movement"]:
        return True

    return False