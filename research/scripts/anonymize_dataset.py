#!/usr/bin/env python3
"""
CloudDecept Dataset Anonymization Script
Anonymizes attacker IPs, credentials, and other sensitive data for public release.
"""

import json
import hashlib
import re
import sys
from pathlib import Path
from datetime import datetime, timezone

# Anonymization mappings
IP_HASH_SALT = "clouddecept-2024-salt"
CRED_PATTERNS = {
    'aws_access_key': r'AKIA[0-9A-Z]{16}',
    'aws_secret_key': r'[A-Za-z0-9/+=]{40}',
    'azure_token': r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
    'gcp_key': r'-----BEGIN PRIVATE KEY-----.+?-----END PRIVATE KEY-----',
    'ssh_key': r'ssh-(rsa|ed25519|ecdsa) [A-Za-z0-9+/=]+',
    'jwt': r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
    'api_key': r'(?i)api[_-]?key["\s:=]+[A-Za-z0-9_-]{20,}',
    'password': r'(?i)password["\s:=]+[^\s]{8,}',
}


def hash_ip(ip: str) -> str:
    """Consistent IP anonymization using salted hash."""
    if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
        return ip
    hashed = hashlib.sha256(f"{IP_HASH_SALT}{ip}".encode()).hexdigest()[:16]
    # Preserve first octet for geolocation studies
    first_octet = ip.split('.')[0]
    return f"{first_octet}.{hashed[:3]}.{hashed[3:6]}.{hashed[6:9]}"


def anonymize_string(text: str) -> str:
    """Anonymize sensitive strings in text."""
    if not isinstance(text, str):
        return text

    result = text
    for pattern_name, pattern in CRED_PATTERNS.items():
        result = re.sub(pattern, f"[REDACTED_{pattern_name.upper()}]", result, flags=re.IGNORECASE | re.DOTALL)
    return result


def anonymize_session(session: dict) -> dict:
    """Anonymize a session record."""
    session = session.copy()
    session['attacker_ip'] = hash_ip(session['attacker_ip'])
    session['session_id'] = hashlib.sha256(
        f"{IP_HASH_SALT}{session['session_id']}".encode()
    ).hexdigest()[:16]
    # Remove exact timestamps, keep only relative
    for field in ['start_time', 'end_time']:
        if field in session:
            session[f'{field}_relative'] = datetime.fromisoformat(
                session[field].replace('Z', '+00:00')
            ).timestamp()
            del session[field]
    return session


def anonymize_command(cmd: dict) -> dict:
    """Anonymize a command record."""
    cmd = cmd.copy()
    cmd['session_id'] = hashlib.sha256(
        f"{IP_HASH_SALT}{cmd['session_id']}".encode()
    ).hexdigest()[:16]
    cmd['command'] = anonymize_string(cmd['command'])
    cmd['output'] = anonymize_string(cmd['output'])
    return cmd


def anonymize_api_call(call: dict) -> dict:
    """Anonymize a cloud API call record."""
    call = call.copy()
    call['session_id'] = hashlib.sha256(
        f"{IP_HASH_SALT}{call['session_id']}".encode()
    ).hexdigest()[:16]
    call['request_body'] = anonymize_string(str(call.get('request_body', '')))
    call['response_body'] = anonymize_string(str(call.get('response_body', '')))
    return call


def anonymize_ioc(ioc: dict) -> dict:
    """Anonymize IOC - keep type but hash value."""
    ioc = ioc.copy()
    ioc['session_id'] = hashlib.sha256(
        f"{IP_HASH_SALT}{ioc['session_id']}".encode()
    ).hexdigest()[:16]
    # Don't hash IOC values - they're the threat intelligence
    # But remove any embedded IPs
    ioc['ioc_value'] = anonymize_string(ioc['ioc_value'])
    return ioc


def anonymize_mitre(tech: dict) -> dict:
    """Anonymize MITRE technique record."""
    tech = tech.copy()
    tech['session_id'] = hashlib.sha256(
        f"{IP_HASH_SALT}{tech['session_id']}".encode()
    ).hexdigest()[:16]
    return tech


def anonymize_summary(summary: dict) -> dict:
    """Anonymize session summary."""
    summary = summary.copy()
    summary['session_id'] = hashlib.sha256(
        f"{IP_HASH_SALT}{summary['session_id']}".encode()
    ).hexdigest()[:16]
    if 'summary_json' in summary:
        summary['summary_json'] = anonymize_string(str(summary['summary_json']))
    return summary


def process_file(input_path: Path, output_path: Path, processor_func):
    """Process a JSONL file with anonymization."""
    print(f"Processing {input_path}...")
    count = 0
    with open(input_path, 'r') as infile, open(output_path, 'w') as outfile:
        for line in infile:
            try:
                record = json.loads(line)
                anonymized = processor_func(record)
                outfile.write(json.dumps(anonymized) + '\n')
                count += 1
            except json.JSONDecodeError as e:
                print(f"  Warning: Skipping invalid JSON line: {e}")
    print(f"  Processed {count} records")
    return count


def main():
    input_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("raw_data")
    output_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("data/anonymized")

    if not input_dir.exists():
        print(f"Input directory {input_dir} does not exist")
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)

    files_to_process = [
        ("sessions.jsonl", anonymize_session),
        ("commands.jsonl", anonymize_command),
        ("cloud_api_calls.jsonl", anonymize_api_call),
        ("iocs.jsonl", anonymize_ioc),
        ("mitre_techniques.jsonl", anonymize_mitre),
        ("session_summaries.jsonl", anonymize_summary),
    ]

    total = 0
    for filename, processor in files_to_process:
        input_file = input_dir / filename
        output_file = output_dir / filename
        if input_file.exists():
            total += process_file(input_file, output_file, processor)
        else:
            print(f"Skipping {filename} (not found)")

    # Generate metadata
    metadata = {
        "anonymized_at": datetime.now(timezone.utc).isoformat(),
        "total_records": total,
        "salt_hash": hashlib.sha256(IP_HASH_SALT.encode()).hexdigest(),
        "schema_version": "1.0"
    }
    with open(output_dir / "metadata.json", 'w') as f:
        json.dump(metadata, f, indent=2)

    print(f"\nAnonymization complete: {total} total records")
    print(f"Output directory: {output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())