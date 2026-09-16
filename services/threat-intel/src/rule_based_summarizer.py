"""Deterministic rule-based session summarizer for Threat Intel"""

import re
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from intel import ExtractedIOC, MappedTechnique

logger = logging.getLogger(__name__)


class RuleBasedSummarizer:
    """Deterministic rule-based session summarizer"""

    def __init__(self):
        # No initialization needed for rule-based approach
        pass

    def summarize(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a deterministic summary of the attacker session"""

        # Extract session data
        commands = session_data.get("commands", [])
        intent_history = session_data.get("intent_history", [])
        iocs: List[ExtractedIOC] = session_data.get("iocs", [])
        techniques: List[MappedTechnique] = session_data.get("techniques", [])
        attacker_ip = session_data.get("attacker_ip", "unknown")
        attacker_country = session_data.get("attacker_country", "unknown")
        duration_seconds = session_data.get("duration_seconds", 0)

        # Determine skill level based on techniques, IOCs, and command sophistication
        skill_level = self._calculate_skill_level(techniques, iocs, commands, intent_history, duration_seconds)

        # Determine primary objective from intent history and techniques
        primary_objective = self._determine_primary_objective(intent_history, techniques, commands)

        # Generate techniques summary
        techniques_summary = self._generate_techniques_summary(techniques)

        # Extract notable IOCs
        iocs_of_interest = self._extract_notable_iocs(iocs)

        # Determine risk level
        risk_level = self._determine_risk_level(techniques, iocs, intent_history)

        # Generate defensive recommendations
        defensive_recommendations = self._generate_defensive_recommendations(
            techniques, iocs, intent_history, risk_level
        )

        # Generate narrative
        narrative = self._generate_narrative(
            primary_objective, techniques, iocs, intent_history, duration_seconds
        )

        # Build result
        result = {
            "skill_level": skill_level,
            "primary_objective": primary_objective,
            "techniques_summary": techniques_summary,
            "iocs_of_interest": iocs_of_interest,
            "risk_level": risk_level,
            "defensive_recommendations": defensive_recommendations,
            "narrative": narrative,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "model": "rule-based"
        }

        return result

    def _calculate_skill_level(
        self,
        techniques: List[MappedTechnique],
        iocs: List[ExtractedIOC],
        commands: List[Dict],
        intent_history: List[str],
        duration_seconds: int
    ) -> int:
        """Calculate attacker skill level (1-10) based on observed behaviors"""

        base_score = 1  # Start with minimal skill

        # Technique sophistication (0-3 points)
        technique_score = 0
        critical_techniques = [t for t in techniques if t.severity == "critical"]
        high_techniques = [t for t in techniques if t.severity == "high"]

        if len(critical_techniques) >= 2:
            technique_score = 3
        elif len(critical_techniques) >= 1 or len(high_techniques) >= 3:
            technique_score = 2
        elif len(high_techniques) >= 1:
            technique_score = 1

        # IOC sophistication (0-2 points)
        ioc_score = 0
        high_value_iocs = [
            ioc for ioc in iocs
            if ioc.type in ["aws_access_key", "aws_secret_key", "ssh_private_key", "jwt_token"]
        ]
        if len(high_value_iocs) >= 2:
            ioc_score = 2
        elif len(high_value_iocs) >= 1:
            ioc_score = 1

        # Command sophistication (0-2 points)
        command_score = 0
        advanced_patterns = [
            "assume-role", "sts ", "keyvault", "secrets manager", "parameter store",
            "create-function", "lambda", "cloudformation", "terraform", "ansible"
        ]
        command_text = " ".join([
            (c.get("cmd") or c.get("command") or "").lower()
            for c in commands
        ])
        advanced_count = sum(1 for pattern in advanced_patterns if pattern in command_text)
        if advanced_count >= 3:
            command_score = 2
        elif advanced_count >= 1:
            command_score = 1

        # Intent progression (0-2 points)
        intent_score = 0
        if len(intent_history) >= 3:
            # Check for progression: recon -> credential -> privilege -> data -> lateral
            progression_stages = [
                "cloud_recon",
                "credential_hunting",
                "privilege_escalation",
                "data_access",
                "persistence",
                "lateral_movement"
            ]
            found_stages = [
                stage for stage in progression_stages
                if stage in intent_history
            ]
            if len(found_stages) >= 4:
                intent_score = 2
            elif len(found_stages) >= 2:
                intent_score = 1

        # Duration factor (0-1 point)
        duration_score = 1 if duration_seconds > 300 else 0  # 5+ minutes shows persistence

        total_score = base_score + technique_score + ioc_score + command_score + intent_score + duration_score
        return min(10, max(1, total_score))

    def _determine_primary_objective(
        self,
        intent_history: List[str],
        techniques: List[MappedTechnique],
        commands: List[Dict]
    ) -> str:
        """Determine the attacker's primary objective"""

        if not intent_history and not techniques:
            return "unknown activity"

        # Use the most recent intent if available
        if intent_history:
            latest_intent = intent_history[-1]
            intent_to_objective = {
                "system_discovery": "system discovery",
                "file_discovery": "file and directory discovery",
                "account_discovery": "account discovery",
                "network_discovery": "network discovery",
                "process_discovery": "process discovery",
                "ingress_tool_transfer": "tool transfer",
                "cloud_recon": "cloud reconnaissance",
                "credential_hunting": "credential theft",
                "privilege_escalation": "privilege escalation",
                "data_access": "data exfiltration",
                "persistence": "establish persistence",
                "lateral_movement": "lateral movement",
                "defense_evasion": "defense evasion",
            }
            if latest_intent in intent_to_objective:
                return intent_to_objective[latest_intent]

        # Fallback to technique-based objective
        if techniques:
            tactic_counts = {}
            for tech in techniques:
                tactic = tech.tactic
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

            # Most common tactic determines objective
            if tactic_counts:
                primary_tactic = max(tactic_counts, key=tactic_counts.get)
                tactic_to_objective = {
                    "Initial Access": "initial compromise",
                    "Execution": "code execution",
                    "Persistence": "maintain access",
                    "Privilege Escalation": "gain higher privileges",
                    "Defense Evasion": "avoid detection",
                    "Credential Access": "steal credentials",
                    "Discovery": "system discovery",
                    "Lateral Movement": "move laterally",
                    "Collection": "collect data",
                    "Exfiltration": "exfiltrate data",
                    "Impact": "cause damage"
                }
                if primary_tactic in tactic_to_objective:
                    return tactic_to_objective[primary_tactic]

        # Command-based fallback
        command_text = " ".join([
            (c.get("cmd") or c.get("command") or "").lower()
            for c in commands
        ])
        if any(pattern in command_text for pattern in ["s3 cp", "storage blob", "gsutil cp"]):
            return "data exfiltration"
        elif any(pattern in command_text for pattern in ["ssh ", "scp ", "assume-role"]):
            return "lateral movement"
        elif any(pattern in command_text for pattern in ["create-access-key", "create-user", "lambda"]):
            return "persistence"
        elif any(pattern in command_text for pattern in ["attach-policy", "assume-role", "sudo"]):
            return "privilege escalation"
        elif any(pattern in command_text for pattern in ["describe-instances", "list-buckets", "az vm list"]):
            return "system discovery"
        elif any(pattern in command_text for pattern in [".aws/credentials", "env|grep", "get-caller-identity"]):
            return "credential theft"

        return "unknown objective"

    def _generate_techniques_summary(self, techniques: List[MappedTechnique]) -> str:
        """Generate a summary of MITRE techniques"""

        if not techniques:
            return "no significant techniques detected"

        # Group by severity and take top techniques
        critical = [t.technique_id for t in techniques if t.severity == "critical"]
        high = [t.technique_id for t in techniques if t.severity == "high"]
        medium = [t.technique_id for t in techniques if t.severity == "medium"]

        parts = []
        if critical:
            parts.append(f"Critical: {','.join(critical[:3])}")
        if high:
            parts.append(f"High: {','.join(high[:3])}")
        if medium and not (critical or high):  # Only show medium if no higher severity
            parts.append(f"Medium: {','.join(medium[:3])}")

        return "; ".join(parts) if parts else "low severity techniques detected"

    def _extract_notable_iocs(self, iocs: List[ExtractedIOC]) -> List[str]:
        """Extract notable IOC strings for the summary"""

        if not iocs:
            return []

        # Prioritize high-confidence, high-value IOCs
        notable_types = {
            "aws_access_key", "aws_secret_key", "ssh_private_key",
            "jwt_token", "gcp_service_account", "azure_client_id"
        }

        notable_iocs = []
        for ioc in iocs:
            if (ioc.type in notable_types and ioc.confidence >= 0.8) or \
               (ioc.confidence >= 0.9):
                notable_iocs.append(ioc.value)
                if len(notable_iocs) >= 5:  # Limit to top 5
                    break

        # If no notable IOCs found, return any IOCs up to limit
        if not notable_iocs and iocs:
            notable_iocs = [ioc.value for ioc in iocs[:3]]

        return notable_iocs

    def _determine_risk_level(
        self,
        techniques: List[MappedTechnique],
        iocs: List[ExtractedIOC],
        intent_history: List[str]
    ) -> str:
        """Determine overall risk level"""

        # Check for critical techniques
        critical_techniques = [t for t in techniques if t.severity == "critical"]
        if len(critical_techniques) >= 2:
            return "critical"
        elif len(critical_techniques) >= 1:
            # Check if combined with other high-risk factors
            high_techniques = [t for t in techniques if t.severity == "high"]
            if len(high_techniques) >= 2:
                return "critical"

        # Check for high-risk combinations
        high_risk_intents = {
            "credential_hunting", "privilege_escalation", "data_access",
            "lateral_movement"
        }
        recent_intents = set(intent_history[-3:]) if intent_history else set()
        high_risk_count = len(recent_intents.intersection(high_risk_intents))

        if high_risk_count >= 3:
            return "critical"
        elif high_risk_count >= 2:
            return "high"

        # Check for high-value IOCs
        high_value_ioc_types = {
            "aws_access_key", "aws_secret_key", "ssh_private_key",
            "jwt_token", "gcp_service_account"
        }
        high_value_iocs = [
            ioc for ioc in iocs
            if ioc.type in high_value_ioc_types and ioc.confidence >= 0.8
        ]
        if len(high_value_iocs) >= 2:
            return "high"
        elif len(high_value_iocs) >= 1:
            # Check for supporting evidence
            high_techniques = [t for t in techniques if t.severity == "high"]
            if len(high_techniques) >= 1:
                return "high"

        # Default to medium if we have any techniques or IOCs
        if techniques or iocs or intent_history:
            return "medium"

        return "low"

    def _generate_defensive_recommendations(
        self,
        techniques: List[MappedTechnique],
        iocs: List[ExtractedIOC],
        intent_history: List[str],
        risk_level: str
    ) -> List[str]:
        """Generate defensive recommendations"""

        recommendations = []

        # Based on techniques
        technique_tactics = {t.tactic for t in techniques}
        tactic_recommendations = {
            "Initial Access": "Review authentication logs and MFA enforcement",
            "Execution": "Monitor process creation and script execution",
            "Persistence": "Check for unauthorized scheduled tasks, services, and startup items",
            "Privilege Escalation": "Audit privileged account usage and sudo logs",
            "Defense Evasion": "Review disabled security tools and log clearing activities",
            "Credential Access": "Rotate credentials and monitor for credential dumping",
            "Discovery": "Monitor for network and system enumeration activities",
            "Lateral Movement": "Inspect lateral movement paths and segmented network access",
            "Collection": "Monitor for unusual data aggregation and compression activities",
            "Exfiltration": "Inspect outbound traffic for data exfiltration patterns",
            "Impact": "Ensure backups are intact and monitor for destructive commands"
        }

        for tactic in technique_tactics:
            if tactic in tactic_recommendations:
                recommendations.append(tactic_recommendations[tactic])

        # Based on IOCs
        ioc_types = {ioc.type for ioc in iocs}
        if "aws_access_key" in ioc_types or "aws_secret_key" in ioc_types:
            recommendations.append("Rotate AWS credentials and review CloudTrail logs")
        if "ssh_private_key" in ioc_types:
            recommendations.append("Rotate SSH keys and review authorized_keys files")
        if "jwt_token" in ioc_types:
            recommendations.append("Invalidate JWT tokens and review auth service logs")

        # Based on intents
        if "credential_hunting" in intent_history:
            recommendations.append("Scan for credential leakage in repositories and logs")
        if "data_access" in intent_history:
            recommendations.append("Review data access logs and check for unusual download patterns")
        if "persistence" in intent_history:
            recommendations.append("Check for unauthorized startup items, services, and scheduled tasks")
        if "lateral_movement" in intent_history:
            recommendations.append("Review network segmentation and monitor for unusual internal traffic")

        # Risk-based additions
        if risk_level == "critical":
            recommendations.append("Consider emergency isolation of affected systems")
            recommendations.append("Engage incident response team immediately")
        elif risk_level == "high":
            recommendations.append("Increase monitoring and consider temporary access restrictions")

        # Deduplicate and limit
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
                if len(unique_recommendations) >= 5:  # Limit to top 5
                    break

        return unique_recommendations if unique_recommendations else [
            "Monitor for continued attacker activity",
            "Review all available logs for completeness",
            "Ensure backups and snapshots are secure"
        ]

    def _generate_narrative(
        self,
        primary_objective: str,
        techniques: List[MappedTechnique],
        iocs: List[ExtractedIOC],
        intent_history: List[str],
        duration_seconds: int
    ) -> str:
        """Generate a concise narrative description"""

        # Start with primary objective
        narrative_parts = [f"Attacker attempting {primary_objective}"]

        # Add technique context if significant
        if techniques:
            critical_count = len([t for t in techniques if t.severity == "critical"])
            high_count = len([t for t in techniques if t.severity == "high"])
            if critical_count > 0:
                narrative_parts.append(f"using {critical_count} critical technique(s)")
            elif high_count > 0:
                narrative_parts.append(f"employing {high_count} high-risk technique(s)")

        # Add IOC context if notable
        if iocs:
            high_value_iocs = [
                ioc for ioc in iocs
                if ioc.type in ["aws_access_key", "aws_secret_key", "ssh_private_key", "jwt_token"]
                and ioc.confidence >= 0.8
            ]
            if len(high_value_iocs) > 0:
                narrative_parts.append(f"with {len(high_value_iocs)} high-value indicator(s) detected")

        # Add timing context
        if duration_seconds > 600:  # 10+ minutes
            narrative_parts.append(f"over {duration_seconds // 60} minute(s)")
        elif duration_seconds > 60:  # 1+ minute
            narrative_parts.append(f"over {duration_seconds} second(s)")

        # Add intent progression if available
        if len(intent_history) >= 2:
            unique_intents = list(dict.fromkeys(intent_history))  # Preserve order, remove duplicates
            if len(unique_intents) > 1:
                progression = " -> ".join(unique_intents[-3:])  # Last 3 intents
                narrative_parts.append(f"following progression: {progression}")

        # Combine and trim to ~30 words
        narrative = " ".join(narrative_parts)
        words = narrative.split()
        if len(words) > 30:
            narrative = " ".join(words[:30]) + "..."

        return narrative


# Convenience function for backward compatibility
def summarize_session_deterministic(session_data: Dict) -> Dict[str, Any]:
    """Convenience function for deterministic session summarization"""
    summarizer = RuleBasedSummarizer()
    return summarizer.summarize(session_data)