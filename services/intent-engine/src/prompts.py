"""Intent classification prompts and templates"""

# Intent categories with descriptions
INTENT_CATEGORIES = {
    "cloud_recon": {
        "name": "Cloud Reconnaissance",
        "description": "Enumerating cloud resources, services, and configurations",
        "indicators": [
            "aws ec2 describe", "aws s3 ls", "aws iam list",
            "az vm list", "az storage account list", "az ad user list",
            "gcloud compute instances list", "gsutil ls", "gcloud iam service-accounts list",
            "describe-instances", "list-buckets", "list-users", "list-vms"
        ],
        "examples": [
            "aws ec2 describe-instances --region us-east-1",
            "az vm list --resource-group rg-prod",
            "gcloud compute instances list --project my-project"
        ]
    },
    "credential_hunting": {
        "name": "Credential Hunting",
        "description": "Searching for API keys, access tokens, passwords, and secrets",
        "indicators": [
            "cat ~/.aws/credentials", "cat ~/.ssh/id_rsa", "env | grep -i aws",
            "env | grep -i secret", "find / -name '*.pem'", "grep -r 'AKIA'",
            "aws sts get-caller-identity", "aws iam list-access-keys",
            "az keyvault secret list", "gcloud auth list"
        ],
        "examples": [
            "cat ~/.aws/credentials",
            "env | grep AWS_ACCESS_KEY_ID",
            "az keyvault secret show --name db-password --vault-name my-vault"
        ]
    },
    "privilege_escalation": {
        "name": "Privilege Escalation",
        "description": "Attempting to gain higher permissions or administrative access",
        "indicators": [
            "aws iam attach-user-policy", "aws iam put-user-policy",
            "aws sts assume-role", "aws iam create-policy",
            "az role assignment create", "az ad group member add",
            "gcloud projects add-iam-policy-binding", "gcloud iam roles create",
            "sudo", "su -", "chmod 777", "chown root"
        ],
        "examples": [
            "aws iam attach-user-policy --user-name developer --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
            "az role assignment create --assignee user@domain.com --role Owner",
            "gcloud projects add-iam-policy-binding my-project --member=user:attacker@evil.com --role=roles/owner"
        ]
    },
    "data_access": {
        "name": "Data Access",
        "description": "Attempting to access storage, databases, or sensitive data",
        "indicators": [
            "aws s3 cp", "aws s3 sync", "aws s3api get-object",
            "aws rds describe-db-instances", "aws dynamodb scan",
            "az storage blob download", "az storage blob list",
            "gsutil cp", "gsutil rsync", "gcloud sql instances list",
            "mysqldump", "pg_dump", "mongodump"
        ],
        "examples": [
            "aws s3 cp s3://company-secrets/database.sql .",
            "az storage blob download --container-name backups --name prod-db.dump",
            "gsutil cp gs://company-data/pii.csv ."
        ]
    },
    "persistence": {
        "name": "Persistence",
        "description": "Establishing long-term access mechanisms",
        "indicators": [
            "aws iam create-access-key", "aws iam create-user",
            "aws ec2 create-key-pair", "aws lambda create-function",
            "az ad sp create-for-rbac", "az keyvault set-policy",
            "gcloud iam service-accounts create", "gcloud compute ssh",
            "ssh-keygen", "crontab -e", "systemctl enable"
        ],
        "examples": [
            "aws iam create-access-key --user-name admin",
            "az ad sp create-for-rbac --name backdoor --role Owner",
            "gcloud iam service-accounts create backdoor --display-name='Backdoor Account'"
        ]
    },
    "lateral_movement": {
        "name": "Lateral Movement",
        "description": "Moving between cloud resources or to on-premise systems",
        "indicators": [
            "ssh", "scp", "rsync", "aws ec2 run-instances",
            "aws ssm start-session", "az vm run-command invoke",
            "gcloud compute ssh", "gcloud compute scp",
            "kubectl exec", "docker exec", "psExec"
        ],
        "examples": [
            "ssh -i key.pem ubuntu@10.0.1.50",
            "aws ssm start-session --target i-1234567890abcdef0",
            "gcloud compute ssh --zone=us-central1-a instance-1"
        ]
    }
}


# Main classification prompt template
CLASSIFICATION_PROMPT = """
You are a cybersecurity analyst classifying attacker intent in a cloud honeypot environment.

ORGANIZATION PROFILE:
- Name: {org_name}
- Industry: {industry}
- Cloud Provider: {cloud_provider}
- Environment: Production cloud simulation

ATTACKER CONTEXT:
- Source IP: {attacker_ip}
- Country: {attacker_country}
- Session Duration: {session_duration} seconds
- Commands in Session: {command_count}

RECENT COMMANDS (last {max_commands}):
{command_sequence}

INTENT CATEGORIES:
{intent_definitions}

TASK: Classify the PRIMARY intent of this attacker based on their command sequence.
Consider:
1. What is the attacker trying to achieve?
2. What cloud resources are they targeting?
3. What is the progression of their actions?
4. Are they exploring, stealing credentials, escalating privileges, accessing data, establishing persistence, or moving laterally?

RESPOND IN VALID JSON FORMAT ONLY:
{{
    "intent": "<one of: cloud_recon, credential_hunting, privilege_escalation, data_access, persistence, lateral_movement, unknown>",
    "confidence": <float 0.0-1.0>,
    "skill_level": <int 1-10>,
    "reasoning": "<one sentence explaining your classification>",
    "secondary_intents": ["<other possible intents>"],
    "adaptation_hint": "<suggestion for how to adapt the honeypot response>"
}}
"""


# Simplified prompt for faster inference
SIMPLIFIED_PROMPT = """
Classify attacker intent from these cloud commands:

ORG: {org_name} ({cloud_provider})
ATTACKER: {attacker_ip} ({attacker_country})
SESSION: {session_duration}s, {command_count} commands

COMMANDS:
{command_sequence}

CATEGORIES:
- cloud_recon: Enumerating cloud resources (describe-instances, list-buckets, list-vms)
- credential_hunting: Finding keys/secrets (cat ~/.aws/credentials, env|grep AWS, sts assume-role)
- privilege_escalation: Gaining admin access (attach-policy, assume-role, create-user, role assignment)
- data_access: Accessing storage/data (s3 cp, storage blob download, gsutil cp, rds describe)
- persistence: Long-term access (create-access-key, create-user, create-sp, service-account)
- lateral_movement: Moving between systems (ssh, scp, ssm, run-command, compute ssh)

JSON ONLY:
{{"intent": "...", "confidence": 0.0, "skill_level": 1, "reasoning": "...", "adaptation_hint": "..."}}
"""


def build_classification_prompt(
    org_profile: dict,
    attacker_ip: str,
    attacker_country: str,
    session_duration: float,
    command_count: int,
    commands: list,
    max_commands: int = 10
) -> str:
    """Build the classification prompt with context"""

    # Format command sequence
    formatted_commands = []
    for i, cmd in enumerate(commands[-max_commands:]):
        timestamp = cmd.get("timestamp", "unknown")
        command = cmd.get("cmd", cmd.get("command", ""))
        output_summary = cmd.get("output_summary", "")[:100] if cmd.get("output_summary") else ""
        formatted_commands.append(f"[{timestamp}] {command} {output_summary}")

    command_sequence = "\n".join(formatted_commands) if formatted_commands else "No commands yet"

    # Build intent definitions
    intent_defs = []
    for key, info in INTENT_CATEGORIES.items():
        indicators = ", ".join(info["indicators"][:5])
        intent_defs.append(f"- {key}: {info['description']}. Indicators: {indicators}")

    intent_definitions = "\n".join(intent_defs)

    return CLASSIFICATION_PROMPT.format(
        org_name=org_profile.get("name", "Unknown"),
        industry=org_profile.get("industry", "technology"),
        cloud_provider=org_profile.get("cloud_provider", "aws"),
        attacker_ip=attacker_ip,
        attacker_country=attacker_country or "Unknown",
        session_duration=int(session_duration),
        command_count=command_count,
        max_commands=max_commands,
        command_sequence=command_sequence,
        intent_definitions=intent_definitions
    )


def build_simplified_prompt(
    org_profile: dict,
    attacker_ip: str,
    attacker_country: str,
    session_duration: float,
    command_count: int,
    commands: list,
    max_commands: int = 5
) -> str:
    """Build simplified prompt for faster inference"""

    formatted_commands = []
    for cmd in commands[-max_commands:]:
        command = cmd.get("cmd", cmd.get("command", ""))
        formatted_commands.append(f"- {command}")

    command_sequence = "\n".join(formatted_commands) if formatted_commands else "No commands yet"

    return SIMPLIFIED_PROMPT.format(
        org_name=org_profile.get("name", "Unknown"),
        cloud_provider=org_profile.get("cloud_provider", "aws"),
        attacker_ip=attacker_ip,
        attacker_country=attacker_country or "Unknown",
        session_duration=int(session_duration),
        command_count=command_count,
        command_sequence=command_sequence
    )


# Few-shot examples for better classification
FEW_SHOT_EXAMPLES = """
EXAMPLE 1:
Commands: whoami, uname -a, aws ec2 describe-instances, aws s3 ls, aws iam list-users
Intent: cloud_recon
Confidence: 0.95
Reasoning: Attacker systematically enumerated EC2, S3, and IAM resources using AWS CLI.

EXAMPLE 2:
Commands: aws sts get-caller-identity, cat ~/.aws/credentials, env | grep AWS, aws iam list-access-keys
Intent: credential_hunting
Confidence: 0.92
Reasoning: Attacker checked caller identity then immediately searched for credential files and environment variables.

EXAMPLE 3:
Commands: aws iam attach-user-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess, aws sts assume-role --role-arn arn:aws:iam::123456789012:role/Admin
Intent: privilege_escalation
Confidence: 0.88
Reasoning: Attacker attempted to attach administrator policy and assume admin role.

EXAMPLE 4:
Commands: aws s3 ls, aws s3 cp s3://company-secrets/prod.db ., aws rds describe-db-instances
Intent: data_access
Confidence: 0.90
Reasoning: Attacker listed buckets then downloaded a database file and enumerated RDS instances.

EXAMPLE 5:
Commands: aws iam create-access-key --user-name admin, aws ec2 create-key-pair --key-name backdoor, aws lambda create-function --function-name persist
Intent: persistence
Confidence: 0.85
Reasoning: Attacker created access keys, key pair, and Lambda function for persistent access.

EXAMPLE 6:
Commands: aws ec2 describe-instances, ssh -i key.pem ubuntu@10.0.1.50, aws ssm start-session --target i-1234567890
Intent: lateral_movement
Confidence: 0.87
Reasoning: Attacker enumerated instances then attempted SSH and SSM connections to other hosts.
"""