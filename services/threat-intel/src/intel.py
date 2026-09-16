"""Threat Intelligence Engine - MITRE ATT&CK mapping, IOC extraction, session summarization"""

import re
import json
import logging
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field

import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# MITRE ATT&CK Cloud Technique Mappings
MITRE_CLOUD_TECHNIQUES = {
    # Initial Access
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "triggers": ["exploit", "vulnerability", "cve-", "shellshock", "struts"],
        "severity": "high"
    },
    "T1199": {
        "name": "Trusted Relationship",
        "tactic": "Initial Access",
        "triggers": ["vpc peering", "cross-account", "assume-role", "service account"],
        "severity": "medium"
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "triggers": ["ssh ", "rdp", "login", "password", "credential", "access key"],
        "severity": "critical"
    },

    # Execution
    "T1059.009": {
        "name": "Command and Scripting Interpreter: Cloud API",
        "tactic": "Execution",
        "triggers": ["aws ", "az ", "gcloud ", "cli ", "cloud shell", "run command"],
        "severity": "medium"
    },
    "T1059.008": {
        "name": "Command and Scripting Interpreter: Cloud API",
        "tactic": "Execution",
        "triggers": ["aws ", "az ", "gcloud ", "cli ", "cloud shell", "run command"],
        "severity": "medium"
    },
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "triggers": ["powershell", "pwsh", "invoke-expression", "iex"],
        "severity": "high"
    },
    "T1059.004": {
        "name": "Command and Scripting Interpreter: Unix Shell",
        "tactic": "Execution",
        "triggers": ["bash", "sh ", "zsh", "/bin/sh", "curl | bash", "wget | bash"],
        "severity": "medium"
    },
    "T1059.006": {
        "name": "Command and Scripting Interpreter: Python",
        "tactic": "Execution",
        "triggers": ["python", "python3", "pip install", "virtualenv"],
        "severity": "low"
    },

    # Persistence
    "T1098": {
        "name": "Account Manipulation",
        "tactic": "Persistence",
        "triggers": ["create-user", "create-access-key", "attach-policy", "add-user-to-group", "create-service-account", "create-sp", "add-iam-policy-binding"],
        "severity": "high"
    },
    "T1505.003": {
        "name": "Server Software Component: Web Shell",
        "tactic": "Persistence",
        "triggers": ["webshell", "php shell", "jsp shell", "asp shell", "c99", "r57"],
        "severity": "critical"
    },
    "T1556.002": {
        "name": "Modify Authentication Process: Password Filter",
        "tactic": "Persistence",
        "triggers": ["password filter", "authentication package"],
        "severity": "high"
    },

    # Privilege Escalation
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "triggers": ["sudo ", "su ", "privilege escalation", "kernel exploit", "dirty cow", "cve-2021"],
        "severity": "critical"
    },
    "T1484.002": {
        "name": "Domain Policy Modification: Domain Trust Modification",
        "tactic": "Privilege Escalation",
        "triggers": ["trust relationship", "federation", "identity provider"],
        "severity": "high"
    },

    # Defense Evasion
    "T1562.001": {
        "name": "Disable or Modify Tools: Disable Security Tools",
        "tactic": "Defense Evasion",
        "triggers": ["disable logging", "disable guardduty", "disable security hub", "disable defender", "disable monitor"],
        "severity": "high"
    },
    "T1070.004": {
        "name": "Indicator Removal: File Deletion",
        "tactic": "Defense Evasion",
        "triggers": ["rm -rf", "shred", "wipe", "secure delete", "history -c", "unset HISTFILE"],
        "severity": "medium"
    },

    # Credential Access
    "T1552.001": {
        "name": "Unsecured Credentials: Credentials In Files",
        "tactic": "Credential Access",
        "triggers": [".aws/credentials", ".ssh/id_rsa", "id_rsa", "id_ed25519", "config.json", "gcp-credentials.json", "service-account.json", "env | grep"],
        "severity": "critical"
    },
    "T1552.004": {
        "name": "Unsecured Credentials: Private Keys",
        "tactic": "Credential Access",
        "triggers": ["private key", "-----BEGIN", "PRIVATE KEY", ".pem", ".ppk"],
        "severity": "critical"
    },
    "T1555.003": {
        "name": "Credentials from Password Managers: Secrets from Vaults",
        "tactic": "Credential Access",
        "triggers": ["keyvault", "secrets manager", "parameter store", "vault"],
        "severity": "high"
    },
    "T1003.001": {
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "triggers": ["lsass", "sekurlsa", "mimikatz", "gsecdump", "comsvcs.dll"],
        "severity": "critical"
    },

    # Discovery
    "T1033": {
        "name": "System Owner/User Discovery",
        "tactic": "Discovery",
        "triggers": ["whoami", "users", "who", "w "],
        "severity": "low"
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "triggers": ["uname", "hostname", "uptime", "lscpu", "arch", "/proc/cpuinfo", "/etc/os-release"],
        "severity": "low"
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "triggers": ["ls ", "find ", "dir ", "tree ", "pwd", "ls -la", "ls -R"],
        "severity": "low"
    },
    "T1087.001": {
        "name": "Account Discovery: Local Account",
        "tactic": "Discovery",
        "triggers": ["id ", "id", "cat /etc/passwd", "getent passwd", "net user"],
        "severity": "low"
    },
    "T1087.002": {
        "name": "Account Discovery: Domain Account",
        "tactic": "Discovery",
        "triggers": ["net group", "net localgroup", "ad user", "get-aduser", "ldapsearch"],
        "severity": "low"
    },
    "T1482": {
        "name": "Domain Trust Discovery",
        "tactic": "Discovery",
        "triggers": ["trust", "federation", "domain", "ad domain"],
        "severity": "medium"
    },
    "T1018": {
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "triggers": ["nmap", "masscan", "zmap", "ssh -", "ping ", "traceroute", "arp -a"],
        "severity": "low"
    },
    "T1526": {
        "name": "Cloud Service Discovery",
        "tactic": "Discovery",
        "triggers": ["describe-instances", "list-vms", "compute instances list", "describe-volumes", "describe-vpcs", "describe-subnets", "list-buckets", "list-accounts", "list-projects"],
        "severity": "low"
    },
    "T1530": {
        "name": "Cloud Storage Object Discovery",
        "tactic": "Discovery",
        "triggers": ["s3 ls", "s3api list-objects", "storage blob list", "gsutil ls", "gsutil stat"],
        "severity": "low"
    },
    "T1538": {
        "name": "Cloud Infrastructure Discovery",
        "tactic": "Discovery",
        "triggers": ["describe-security-groups", "describe-network-interfaces", "describe-route-tables", "list-vpcs", "list-subnets", "list-firewalls", "list-networks"],
        "severity": "low"
    },

    # Lateral Movement
    "T1021.004": {
        "name": "Remote Services: SSH",
        "tactic": "Lateral Movement",
        "triggers": ["ssh ", "scp ", "sftp ", "ssh-copy-id", "ssh-add", "ssh-agent"],
        "severity": "medium"
    },
    "T1021.006": {
        "name": "Remote Services: Windows Remote Management",
        "tactic": "Lateral Movement",
        "triggers": ["winrm", "psexec", "wmic", "Invoke-Command", "Enter-PSSession"],
        "severity": "high"
    },
    "T1550.001": {
        "name": "Use Alternate Authentication Material: Application Access Token",
        "tactic": "Lateral Movement",
        "triggers": ["assume-role", "sts ", "session-token", "access-token", "bearer token", "service account token"],
        "severity": "critical"
    },
    "T1550.007": {
        "name": "Use Alternate Authentication Material: Cloud Token",
        "tactic": "Lateral Movement",
        "triggers": ["assume-role", "sts ", "session-token", "access-token", "bearer token", "service account token"],
        "severity": "critical"
    },
    "T1570": {
        "name": "Lateral Tool Transfer",
        "tactic": "Lateral Movement",
        "triggers": ["scp ", "rsync ", "aws s3 cp", "gsutil cp", "az storage blob upload", "curl -O", "wget "],
        "severity": "medium"
    },

    # Collection
    "T1530": {
        "name": "Data from Cloud Storage",
        "tactic": "Collection",
        "triggers": ["s3 cp", "s3 sync", "storage blob download", "gsutil cp", "gsutil rsync", "download", "get-object"],
        "severity": "high"
    },
    "T1213": {
        "name": "Data from Information Repositories",
        "tactic": "Collection",
        "triggers": ["confluence", "sharepoint", "github", "gitlab", "bitbucket", "wiki"],
        "severity": "medium"
    },

    # Exfiltration
    "T1537": {
        "name": "Transfer Data to Cloud Account",
        "tactic": "Exfiltration",
        "triggers": ["upload", "put-object", "cp s3://", "sync s3://", "gsutil cp", "az storage blob upload"],
        "severity": "high"
    },
    "T1041": {
        "name": "Exfiltration Over Command and Control Channel",
        "tactic": "Exfiltration",
        "triggers": ["exfil", "base64", "encode", "tar ", "gzip "],
        "severity": "high"
    },

    # Impact
    "T1485": {
        "name": "Data Destruction",
        "tactic": "Impact",
        "triggers": ["rm -rf", "delete", "terminate-instances", "delete-bucket", "drop database", "truncate"],
        "severity": "critical"
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "triggers": ["encrypt", "ransomware", ".encrypted", ".locked", "bitlocker", "crypt"],
        "severity": "critical"
    },
}

# IOC Patterns
IOC_PATTERNS = {
    "ipv4": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    "ipv6": r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
    "aws_access_key": r"\b(AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}\b",
    "aws_secret_key": r"\b[a-zA-Z0-9/+=]{40}\b",
    "aws_session_token": r"\bIQoJb3JpZ2luX2VjE[a-zA-Z0-9/+]{200,}\b",
    "ssh_private_key": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
    "ssh_public_key": r"ssh-(?:rsa|dsa|ecdsa|ed25519) [A-Za-z0-9+/]+",
    "jwt_token": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
    "api_key_generic": r"\b(?:api[_-]?key|apikey)[\"'\s:=]+([a-zA-Z0-9_-]{20,})\b",
    "gcp_service_account": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.iam\.gserviceaccount\.com",
    "azure_client_id": r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "domain": r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
    "url": r"https?://[^\s\"'<>]+",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "sha1": r"\b[a-fA-F0-9]{40}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
}


@dataclass
class ExtractedIOC:
    """Extracted Indicator of Compromise"""
    type: str
    value: str
    context: str = ""
    confidence: float = 0.8
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class MappedTechnique:
    """Mapped MITRE ATT&CK technique"""
    technique_id: str
    name: str
    tactic: str
    severity: str
    trigger: str
    confidence: float = 0.8


class IOCExtractor:
    """Extract IOCs from command output and session data"""

    def __init__(self):
        self.compiled_patterns = {k: re.compile(v, re.IGNORECASE) for k, v in IOC_PATTERNS.items()}

    def extract(self, text: str) -> List[ExtractedIOC]:
        """Extract all IOCs from text"""
        iocs = []
        seen = set()

        for ioc_type, pattern in self.compiled_patterns.items():
            matches = pattern.findall(text)
            for match in matches:
                value = match if isinstance(match, str) else match[0] if match else ""
                if value and value not in seen:
                    seen.add(value)
                    iocs.append(ExtractedIOC(
                        type=ioc_type,
                        value=value,
                        context=text[:200],
                        confidence=self._get_confidence(ioc_type)
                    ))

        return iocs

    def _get_confidence(self, ioc_type: str) -> float:
        """Confidence scores by IOC type"""
        confidences = {
            "aws_access_key": 0.95,
            "aws_secret_key": 0.9,
            "aws_session_token": 0.95,
            "ssh_private_key": 0.99,
            "ssh_public_key": 0.9,
            "jwt_token": 0.95,
            "gcp_service_account": 0.95,
            "azure_client_id": 0.85,
            "email": 0.7,
            "domain": 0.6,
            "ipv4": 0.7,
            "ipv6": 0.7,
            "url": 0.6,
            "api_key_generic": 0.8,
        }
        return confidences.get(ioc_type, 0.5)

    def extract_from_session(self, commands: List[Dict], outputs: List[str]) -> List[ExtractedIOC]:
        """Extract IOCs from entire session"""
        def _safe_get(cmd: Dict[str, Any], key: str, fallback: str = "") -> str:
            val = cmd.get(key)
            if val is None:
                return ""
            if isinstance(val, str):
                return val
            return str(val)

        all_text = " ".join([
            (_safe_get(cmd, "cmd") or _safe_get(cmd, "command") or "") + " " + _safe_get(cmd, "output")
            for cmd in commands
        ] + outputs)
        return self.extract(all_text)


class MITREMapper:
    """Map commands and behaviors to MITRE ATT&CK techniques"""

    def __init__(self):
        self.techniques = MITRE_CLOUD_TECHNIQUES

    def map_commands(self, commands: List[Dict]) -> List[MappedTechnique]:
        """Map command sequence to MITRE techniques, deduplicated by technique_id with evidence tracing"""
        mapped_dict: Dict[str, MappedTechnique] = {}

        for cmd in commands:
            cmd_str = (cmd.get("cmd") or cmd.get("command") or "").strip()
            out_str = (cmd.get("output") or "").strip()
            command_text = (cmd_str + " " + out_str).lower()

            for tech_id, tech_info in self.techniques.items():
                for trigger in tech_info["triggers"]:
                    if trigger.lower() in command_text:
                        clean_trig = trigger.strip()
                        is_heuristic = (tech_id == "T1083" and clean_trig == "pwd")
                        trig_label = f"{clean_trig} (heuristic: directory orientation)" if is_heuristic else clean_trig
                        conf = 0.50 if is_heuristic else 0.85

                        if tech_id not in mapped_dict:
                            mapped_dict[tech_id] = MappedTechnique(
                                technique_id=tech_id,
                                name=f"{tech_info['name']} (Heuristic)" if is_heuristic else tech_info["name"],
                                tactic=tech_info["tactic"],
                                severity=tech_info["severity"],
                                trigger=trig_label,
                                confidence=conf
                            )
                        else:
                            existing = mapped_dict[tech_id]
                            existing_triggers = [t.strip() for t in existing.trigger.split(",")]
                            if trig_label not in existing_triggers:
                                existing.trigger = f"{existing.trigger}, {trig_label}"
                            if not is_heuristic:
                                existing.name = tech_info["name"]
                                existing.confidence = max(existing.confidence, 0.85)

        mapped = list(mapped_dict.values())

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        mapped.sort(key=lambda x: severity_order.get(x.severity, 4))

        return mapped

    def get_tactic_summary(self, techniques: List[MappedTechnique]) -> Dict[str, int]:
        """Count techniques per tactic"""
        tactics = {}
        for tech in techniques:
            tactics[tech.tactic] = tactics.get(tech.tactic, 0) + 1
        return tactics




# Convenience functions
def extract_iocs(text: str) -> List[ExtractedIOC]:
    extractor = IOCExtractor()
    return extractor.extract(text)


def map_to_mitre(commands: List[Dict]) -> List[MappedTechnique]:
    mapper = MITREMapper()
    return mapper.map_commands(commands)