# GCP CLI command emulation for Cowrie
# Place this in /cowrie/cowrie/commands/gcp.py

from __future__ import annotations

import json
import random
import uuid
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List, Any

from cowrie.shell.command import HoneyPotCommand

commands = {}


class CommandGCLOUD(HoneyPotCommand):
    """
    GCP gcloud CLI command emulator for Cowrie honeypot.
    Provides fake gcloud CLI responses via cloud-api-mock service or local fallback.
    """

    # Define which commands we will handle via the cloud-api-mock service
    API_MOCK_ENDPOINTS = {
        ('compute', 'instances', 'list'): ('/gcp/compute/instances/list', 'GET'),
        ('storage', 'buckets', 'list'): ('/gcp/storage/buckets/list', 'GET'),
        ('iam', 'service-accounts', 'list'): ('/gcp/iam/service-accounts/list', 'GET'),
    }

    def __init__(self, protocol, *args):
        super().__init__(protocol, *args)
        self.project_id = "gcp-media-studios-prod"
        self.project_number = random.randint(100000000000, 999999999999)

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
        machine_types = ["n2-standard-2", "n2-standard-4", "c2-standard-8", "e2-medium"]
        zones = ["us-central1-a", "us-central1-b", "us-east1-b", "us-west1-a"]
        return [
            {
                "id": str(random.randint(1000000000000000000, 9999999999999999999)),
                "creationTimestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "name": f"{random.choice(['web', 'api', 'db', 'worker', 'ml'])}-{random.randint(100,999)}",
                "zone": f"https://www.googleapis.com/compute/v1/projects/{self.project_id}/zones/{random.choice(zones)}",
                "status": "RUNNING",
                "machineType": f"https://www.googleapis.com/compute/v1/projects/{self.project_id}/zones/us-central1-a/machineTypes/{random.choice(machine_types)}",
                "disks": [
                    {
                        "kind": "compute#attachedDisk",
                        "type": "PERSISTENT",
                        "mode": "READ_WRITE",
                        "source": f"https://www.googleapis.com/compute/v1/projects/{self.project_id}/zones/us-central1-a/disks/disk-{random.randint(100,999)}",
                        "deviceName": "persistent-disk-0",
                        "boot": True,
                        "autoDelete": True
                    }
                ],
                "networkInterfaces": [
                    {
                        "kind": "compute#networkInterface",
                        "network": f"https://www.googleapis.com/compute/v1/projects/{self.project_id}/global/networks/default",
                        "networkIP": f"10.0.{random.randint(1,255)}.{random.randint(1,255)}",
                        "accessConfigs": [
                            {
                                "kind": "compute#accessConfig",
                                "type": "ONE_TO_ONE_NAT",
                                "name": "External NAT",
                                "natIP": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                            }
                        ]
                    }
                ],
                "metadata": {
                    "kind": "compute#metadata",
                    "items": [
                        {"key": "ssh-keys", "value": "user:ssh-rsa AAAAB3NzaC1yc2E..."}
                    ]
                },
                "serviceAccounts": [
                    {
                        "email": f"compute@{self.project_id}.iam.gserviceaccount.com",
                        "scopes": [
                            "https://www.googleapis.com/auth/devstorage.read_only",
                            "https://www.googleapis.com/auth/logging.write",
                            "https://www.googleapis.com/auth/monitoring.write",
                            "https://www.googleapis.com/auth/servicecontrol",
                            "https://www.googleapis.com/auth/service.management.readonly",
                            "https://www.googleapis.com/auth/trace.append"
                        ]
                    }
                ],
                "labels": {"environment": "production", "app": "core-platform"},
                "scheduling": {"preemptible": False, "onHostMaintenance": "MIGRATE", "automaticRestart": True},
                "cpuPlatform": "Intel Cascade Lake",
                "startRestricted": False,
                "deletionProtection": False,
                "shieldedInstanceConfig": {
                    "enableSecureBoot": False,
                    "enableVtpm": True,
                    "enableIntegrityMonitoring": True
                }
            }
            for _ in range(random.randint(3, 7))
        ]

    def get_fake_buckets(self) -> List[Dict]:
        return [
            {
                "kind": "storage#bucket",
                "id": f"{self.project_id}/{name}",
                "selfLink": f"https://www.googleapis.com/storage/v1/b/{name}",
                "projectNumber": str(self.project_number),
                "name": name,
                "timeCreated": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "location": "US",
                "storageClass": "STANDARD",
                "labels": {"environment": "production"},
                "versioning": {"enabled": True}
            }
            for name in ["data-lake", "logs-archive", "ml-checkpoints", "terraform-state", "cdn-assets"]
        ]

    def get_fake_service_accounts(self) -> List[Dict]:
        return [
            {
                "name": f"projects/{self.project_id}/serviceAccounts/compute@{self.project_id}.iam.gserviceaccount.com",
                "projectId": self.project_id,
                "uniqueId": str(random.randint(100000000000000000000, 999999999999999999999)),
                "email": f"compute@{self.project_id}.iam.gserviceaccount.com",
                "displayName": "Compute Engine default service account",
                "etag": "CAE=",
                "description": "",
                "oauth2ClientId": str(random.randint(100000000000000000000, 999999999999999999999)),
                "disabled": False
            },
            {
                "name": f"projects/{self.project_id}/serviceAccounts/ci-cd@{self.project_id}.iam.gserviceaccount.com",
                "projectId": self.project_id,
                "uniqueId": str(random.randint(100000000000000000000, 999999999999999999999)),
                "email": f"ci-cd@{self.project_id}.iam.gserviceaccount.com",
                "displayName": "CI/CD Service Account",
                "etag": "CAE=",
                "description": "Used for deployments",
                "oauth2ClientId": str(random.randint(100000000000000000000, 999999999999999999999)),
                "disabled": False
            }
        ]

    def call(self) -> None:
        """Execute gcloud CLI command"""
        if len(self.args) < 1:
            self.errorWrite("usage: gcloud <group> <command> [params]\n")
            return

        group = self.args[0]

        # Handle version flag
        if "--version" in self.args or "-v" in self.args:
            self.write("Google Cloud SDK: 425.0.0\n")
            return

        # First, try to handle via cloud-api-mock for supported commands
        # Build key based on args length
        if len(self.args) >= 3:
            cmd = self.args[1]
            subcmd = self.args[2]
            key = (group, cmd, subcmd)
            if key in self.API_MOCK_ENDPOINTS:
                endpoint, method = self.API_MOCK_ENDPOINTS[key]
                result = self._call_api_mock(endpoint, method)
                if result is not None:
                    self.write(json.dumps(result, indent=2) + "\n")
                    return

        # If API mock fails or command not in mock endpoints, fall back to local implementation

        if group == "compute" and len(self.args) > 1:
            cmd = self.args[1]
            if cmd == "instances" and len(self.args) > 2 and self.args[2] == "list":
                self.write(json.dumps({"items": self.get_fake_instances()}, indent=2) + "\n")
                return
            elif cmd == "instances" and len(self.args) > 2 and self.args[2] == "describe":
                self.write(json.dumps(self.get_fake_instances()[0], indent=2) + "\n")
                return

        elif group == "storage" and len(self.args) > 1:
            cmd = self.args[1]
            if cmd == "buckets" and len(self.args) > 2 and self.args[2] == "list":
                self.write(json.dumps({"items": self.get_fake_buckets()}, indent=2) + "\n")
                return

        elif group == "iam" and len(self.args) > 1:
            cmd = self.args[1]
            if cmd == "service-accounts" and len(self.args) > 2 and self.args[2] == "list":
                self.write(json.dumps({"accounts": self.get_fake_service_accounts()}, indent=2) + "\n")
                return

        elif group == "config" and len(self.args) > 1 and self.args[1] == "get-value":
            if len(self.args) > 2 and self.args[2] == "project":
                self.write(json.dumps({"value": self.project_id}, indent=2) + "\n")
                return
            elif len(self.args) > 2 and self.args[2] == "account":
                self.write(json.dumps({"value": f"admin@{self.project_id}.iam.gserviceaccount.com"}, indent=2) + "\n")
                return

        elif group == "auth" and len(self.args) > 1 and self.args[1] == "list":
            self.write(json.dumps([
                {
                    "account": f"admin@{self.project_id}.iam.gserviceaccount.com",
                    "status": "ACTIVE"
                }
            ], indent=2) + "\n")
            return

        self.errorWrite(f"Unknown command: {' '.join(self.args)}\n")


# Register the command
commands["/usr/bin/gcloud"] = CommandGCLOUD
commands["gcloud"] = CommandGCLOUD