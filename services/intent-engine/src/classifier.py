"""Deterministic rule-based intent classifier"""

import logging
import time
from typing import Dict, List, Any
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ClassificationResult(BaseModel):
    """Result of intent classification"""
    intent: str = Field(..., description="Primary intent category")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score")
    skill_level: int = Field(..., ge=1, le=10, description="Attacker skill level")
    reasoning: str = Field(..., description="Explanation for classification")
    secondary_intents: List[str] = Field(default_factory=list)
    adaptation_hint: str = Field(default="", description="Suggestion for response adaptation")
    processing_time_ms: float = Field(default=0.0, description="Classification latency")


class RuleBasedClassifier:
    """Deterministic rule-based intent classifier for cloud honeypot"""

    # Comprehensive command patterns for each MITRE ATT&CK objective
    PATTERNS = {
        "system_discovery": [
            "whoami", "uname", "uname -a", "uname -s -m", "hostname", "uptime",
            "cat /proc/cpuinfo", "cat /proc/version", "cat /proc/meminfo",
            "cat /etc/issue", "cat /etc/os-release", "cat /etc/lsb-release",
            "which", "whereis", "lscpu", "arch"
        ],
        "account_discovery": [
            "id", "cat /etc/passwd", "cat /etc/shadow", "cat /etc/group",
            "users", "groups", "w", "who", "last", "lastlog", "cat /etc/sudoers"
        ],
        "file_discovery": [
            "ls", "ls -la", "ls -l", "ls -al", "dir", "find", "find /", "find .",
            "pwd", "tree", "locate", "cat /root", "ls /home", "ls /root"
        ],
        "network_discovery": [
            "ifconfig", "ip a", "ip addr", "ip route", "route", "route -n",
            "netstat", "netstat -antp", "ss", "ss -antp", "arp", "arp -a",
            "ping", "traceroute", "cat /etc/resolv.conf", "cat /etc/hosts"
        ],
        "process_discovery": [
            "ps", "ps aux", "ps -ef", "top", "htop", "pstree"
        ],
        "cloud_recon": [
            "describe-instances", "describe-volumes", "describe-vpcs", "describe-subnets",
            "describe-security-groups", "list-buckets", "list-users", "list-roles",
            "list-vms", "list-storage", "compute instances list", "iam service-accounts list",
            "describe-images", "describe-key-pairs", "describe-addresses",
            "aws ec2 describe", "aws s3 ls", "aws iam list", "az resource list", "az storage account list",
            "gcloud compute instances list", "gsutil ls", "gcloud storage buckets list",
            "aws ec2", "aws s3", "aws iam"
        ],
        "credential_hunting": [
            "cat ~/.aws/credentials", "cat ~/.ssh/", "env | grep", "printenv",
            "get-caller-identity", "list-access-keys", "assume-role",
            "keyvault secret", "auth list", "gcloud auth",
            "env | grep AWS", "env | grep AZURE", "env | grep GOOGLE",
            "find / -name *.pem", "find / -name *.key", "grep -r AKIA",
            "aws sts get-caller-identity", "aws iam list-access-keys", "aws secretsmanager list-secrets",
            "az keyvault secret list", "az keyvault certificate list", "gcloud secrets list",
            "gcloud iam service-accounts list", "sts", "credentials", "id_rsa", "authorized_keys"
        ],
        "privilege_escalation": [
            "attach-user-policy", "put-user-policy", "create-policy",
            "role assignment create", "add-iam-policy-binding",
            "create-role", "attach-role-policy",
            "sts assume-role", "iam create-policy", "iam put-user-policy",
            "az role assignment create", "az ad user add", "az ad group member add",
            "gcloud projects add-iam-policy-binding", "gcloud iam roles create",
            "sudo", "su -", "su root", "chmod 777", "chmod +s", "chown root", "usermod -aG",
            "aws iam attach-user-policy", "aws iam put-user-policy", "aws iam create-policy"
        ],
        "data_access": [
            "s3 cp", "s3 sync", "s3api get-object", "storage blob download",
            "storage blob list", "gsutil cp", "gsutil rsync",
            "describe-db-instances", "dynamodb scan", "sql instances",
            "aws s3 cp", "aws s3 sync", "aws s3api get-object", "aws s3api copy-object",
            "aws rds describe-db-instances", "aws dynamodb scan", "aws dynamodb query",
            "az storage blob download", "az storage blob list", "az storage blob upload",
            "az cosmosdb sql query", "az postgres flexible-server execute",
            "gsutil cp", "gsutil rsync", "gsutil mb", "gcloud storage cp",
            "gcloud sql instances list", "gcloud firestore export",
            "mysqldump", "pg_dump", "mongodump", "mongodb export", "tar -czf", "zip"
        ],
        "persistence": [
            "create-access-key", "create-user", "create-key-pair",
            "create-function", "ad sp create", "keyvault set-policy",
            "service-accounts create", "compute ssh",
            "aws iam create-access-key", "aws iam create-user", "aws iam create-login-profile",
            "aws ec2 create-key-pair", "aws lambda create-function", "aws iam create-role",
            "az ad sp create-for-rbac", "az keyvault set-policy", "az keyvault certificate import",
            "gcloud iam service-accounts create", "gcloud compute ssh", "gcloud functions deploy",
            "ssh-keygen", "crontab -e", "crontab -l", "systemctl enable", "launchctl load", "schtasks /create",
            "aws autoscaling create-auto-scaling-group", "aws ec2 launch-template",
            "echo >> ~/.bashrc", "echo >> /etc/crontab"
        ],
        "lateral_movement": [
            "ssh ", "scp ", "rsync ", "run-instances",
            "ssm start-session", "vm run-command",
            "compute ssh", "compute scp", "kubectl exec",
            "aws ssm start-session", "aws ec2 run-instances", "aws ec2 terminate-instances",
            "az vm run-command invoke", "az vm start", "az vm stop",
            "gcloud compute ssh", "gcloud compute scp", "gcloud compute instances start",
            "kubectl exec", "kubectl attach", "docker exec",
            "pscopy", "psexec", "winrs", "enter-pssession"
        ],
        "defense_evasion": [
            "iptables -F", "history -c", "unset HISTFILE", "rm -f ~/.bash_history",
            "set +o history", "killall", "pkill"
        ],
        "ingress_tool_transfer": [
            "curl ", "wget ", "tftp ", "ftp ", "nc -l", "ncat", "netcat"
        ]
    }

    @classmethod
    def classify(cls, commands: List[Dict]) -> ClassificationResult:
        """Fast deterministic rule-based classification with token and pattern matching"""
        command_strings = []
        for cmd in commands:
            if isinstance(cmd, str):
                c = cmd.strip().lower()
            elif isinstance(cmd, dict):
                c = cmd.get("cmd", cmd.get("command", "")).strip().lower()
            else:
                c = str(cmd).strip().lower()
            if c:
                command_strings.append(c)

        all_commands = " ".join(command_strings)

        scores: Dict[str, int] = {}
        for intent, patterns in cls.PATTERNS.items():
            score = 0
            for p in patterns:
                if " " in p:
                    if p in all_commands:
                        score += 1
                else:
                    # Match exact command, command start, or bounded token
                    if any(c == p or c.startswith(p + " ") or f" {p} " in f" {c} " for c in command_strings):
                        score += 1
            if score > 0:
                scores[intent] = score

        if not scores:
            return ClassificationResult(
                intent="unknown",
                confidence=0.1,
                skill_level=1,
                reasoning="No matching patterns found",
                adaptation_hint="No adaptation needed",
                processing_time_ms=0.5,
            )

        # Priority weighting for high-risk intents when scores are tied
        priority_weights = {
            "credential_hunting": 3,
            "privilege_escalation": 3,
            "defense_evasion": 2,
            "persistence": 2,
            "data_access": 2,
            "lateral_movement": 2,
            "cloud_recon": 2,
            "ingress_tool_transfer": 1,
            "network_discovery": 1,
            "account_discovery": 1,
            "process_discovery": 1,
            "file_discovery": 1,
            "system_discovery": 1,
        }

        best_intent = max(
            scores.keys(),
            key=lambda k: (scores[k], priority_weights.get(k, 0))
        )

        confidence = min(0.95, 0.4 + (scores[best_intent] * 0.15))
        # Skill level estimation based on pattern complexity
        base_skill = {
            "system_discovery": 1,
            "file_discovery": 1,
            "account_discovery": 2,
            "process_discovery": 2,
            "network_discovery": 3,
            "ingress_tool_transfer": 3,
            "cloud_recon": 4,
            "defense_evasion": 4,
            "credential_hunting": 5,
            "data_access": 5,
            "persistence": 6,
            "privilege_escalation": 7,
            "lateral_movement": 8,
        }.get(best_intent, 2)

        skill_level = min(10, base_skill + min(2, scores[best_intent] - 1))

        # Identify secondary intents
        secondary = [k for k in sorted(scores, key=scores.get, reverse=True) if k != best_intent]

        return ClassificationResult(
            intent=best_intent,
            confidence=confidence,
            skill_level=skill_level,
            reasoning=f"Rule-based: matched {scores[best_intent]} patterns for {best_intent}",
            secondary_intents=secondary[:3],
            adaptation_hint=cls._get_adaptation_hint(best_intent),
            processing_time_ms=0.5,
        )

    @staticmethod
    def _get_adaptation_hint(intent: str) -> str:
        hints = {
            "system_discovery": "Return deceptive host and OS specifications",
            "account_discovery": "Expose decoy users and synthetic service accounts",
            "file_discovery": "Present realistic deceptive filesystem directory trees",
            "network_discovery": "Simulate segmented cloud virtual network topology",
            "process_discovery": "Return synthetic background processes and daemons",
            "cloud_recon": "Provide rich, detailed decoy cloud resource listings",
            "credential_hunting": "Plant fake canary credentials in expected locations",
            "privilege_escalation": "Fail first, then grant fake restricted elevation",
            "data_access": "Create tempting decoy data storage targets",
            "persistence": "Allow and monitor backdoor insertion attempts",
            "lateral_movement": "Fabricate internal network pivots and nodes",
            "defense_evasion": "Log evasion attempts and simulate log clearance",
            "ingress_tool_transfer": "Quarantine and inspect downloaded payload hashes",
        }
        return hints.get(intent, "No specific adaptation")