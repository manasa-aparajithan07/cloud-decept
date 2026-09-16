# Azure CLI command emulation for Cowrie
# Place this in /cowrie/cowrie/commands/azure.py

from __future__ import annotations

import json
import random
import uuid
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List, Any

from cowrie.shell.command import HoneyPotCommand

commands = {}


class CommandAZ(HoneyPotCommand):
    """
    Azure CLI command emulator for Cowrie honeypot.
    Provides fake Azure CLI responses via cloud-api-mock service or local fallback.
    """

    # Define which commands we will handle via the cloud-api-mock service
    API_MOCK_ENDPOINTS = {
        ('vm', 'list'): ('/azure/vm/list', 'GET'),
        ('storage', 'account', 'list'): ('/azure/storage/list', 'GET'),  # az storage account list
        ('ad', 'user', 'list'): ('/azure/ad/users', 'GET'),  # az ad user list
    }

    def __init__(self, protocol, *args):
        super().__init__(protocol, *args)
        self.subscription_id = f"sub-{''.join(random.choices('0123456789abcdef', k=32))}"

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

    def get_fake_vms(self) -> List[Dict]:
        vm_sizes = ["Standard_D2s_v3", "Standard_D4s_v3", "Standard_E4s_v3", "Standard_B2s"]
        return [
            {
                "id": f"/subscriptions/{self.subscription_id}/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-{i}",
                "name": f"vm-{random.choice(['web', 'api', 'db', 'worker'])}-{i:03d}",
                "type": "Microsoft.Compute/virtualMachines",
                "location": random.choice(["eastus", "westus2", "centralus"]),
                "properties": {
                    "hardwareProfile": {"vmSize": random.choice(vm_sizes)},
                    "storageProfile": {
                        "osDisk": {"osType": "Linux", "createOption": "FromImage"},
                        "imageReference": {
                            "publisher": "Canonical",
                            "offer": "UbuntuServer",
                            "sku": "18.04-LTS",
                            "version": "latest"
                        }
                    },
                    "networkProfile": {
                        "networkInterfaces": [
                            {"id": f"/subscriptions/{self.subscription_id}/resourceGroups/rg-prod/providers/Microsoft.Network/networkInterfaces/nic-{i}"}
                        ]
                    },
                    "provisioningState": "Succeeded"
                },
                "tags": {"Environment": "Production", "Application": "core-platform"}
            }
            for i in range(random.randint(3, 7))
        ]

    def get_fake_storage(self) -> List[Dict]:
        return [
            {
                "id": f"/subscriptions/{self.subscription_id}/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/st{''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=16))}",
                "name": f"st{''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=16))}",
                "type": "Microsoft.Storage/storageAccounts",
                "location": "eastus",
                "sku": {"name": "Standard_LRS", "tier": "Standard"},
                "kind": "StorageV2",
                "properties": {
                    "accessTier": "Hot",
                    "supportsHttpsTrafficOnly": True,
                    "encryption": {"services": {"blob": {"enabled": True}, "file": {"enabled": True}}}
                }
            }
            for _ in range(random.randint(2, 5))
        ]

    def call(self) -> None:
        """Execute Azure CLI command"""
        if len(self.args) < 1:
            self.errorWrite("usage: az <group> <command> [params]\n")
            return

        group = self.args[0]

        # Handle version flag
        if "--version" in self.args or "-v" in self.args:
            self.write("azure-cli: 2.55.0\n")
            return

        # First, try to handle via cloud-api-mock for supported commands
        # Build key based on args length
        if len(self.args) >= 2:
            cmd = self.args[1]
            if len(self.args) >= 3:
                subcmd = self.args[2]
                key = (group, cmd, subcmd)
            else:
                key = (group, cmd)

            # Special handling for az storage account list
            if group == "storage" and cmd == "account" and len(self.args) > 2 and self.args[2] == "list":
                endpoint, method = self.API_MOCK_ENDPOINTS.get(('storage', 'account', 'list'), (None, None))
                if endpoint:
                    result = self._call_api_mock(endpoint, method)
                    if result is not None:
                        self.write(json.dumps(result, indent=2) + "\n")
                        return
            elif (group, cmd) in self.API_MOCK_ENDPOINTS:
                endpoint, method = self.API_MOCK_ENDPOINTS[(group, cmd)]
                result = self._call_api_mock(endpoint, method)
                if result is not None:
                    self.write(json.dumps(result, indent=2) + "\n")
                    return
            # If API mock fails, fall back to local implementation below

        if group == "vm" and len(self.args) > 1:
            cmd = self.args[1]
            if cmd == "list":
                self.write(json.dumps(self.get_fake_vms(), indent=2) + "\n")
                return
            elif cmd == "show":
                self.write(json.dumps(self.get_fake_vms()[0], indent=2) + "\n")
                return

        elif group == "storage" and len(self.args) > 1:
            cmd = self.args[1]
            if cmd == "account" and len(self.args) > 2 and self.args[2] == "list":
                self.write(json.dumps(self.get_fake_storage(), indent=2) + "\n")
                return

        elif group == "ad" and len(self.args) > 1:
            cmd = self.args[1]
            if cmd == "user" and len(self.args) > 2 and self.args[2] == "list":
                result = {
                    "value": [
                        {
                            "id": str(uuid.uuid4()),
                            "userPrincipalName": f"admin@company.onmicrosoft.com",
                            "displayName": "Admin User",
                            "mail": "admin@company.com"
                        },
                        {
                            "id": str(uuid.uuid4()),
                            "userPrincipalName": f"ci-cd@company.onmicrosoft.com",
                            "displayName": "CI/CD Service Account",
                            "mail": None
                        }
                    ]
                }
                self.write(json.dumps(result, indent=2) + "\n")
                return

        elif group == "group" and len(self.args) > 1 and self.args[1] == "list":
            self.write(json.dumps([{"name": "rg-prod", "location": "eastus"}, {"name": "rg-dev", "location": "westus2"}], indent=2) + "\n")
            return

        elif group == "account" and len(self.args) > 1 and self.args[1] == "show":
            self.write(json.dumps({
                "id": self.subscription_id,
                "name": "Production Subscription",
                "state": "Enabled",
                "tenantId": str(uuid.uuid4())
            }, indent=2) + "\n")
            return

        self.errorWrite(f"Unknown command: {' '.join(self.args)}\n")


# Register the command
commands["/usr/bin/az"] = CommandAZ
commands["az"] = CommandAZ