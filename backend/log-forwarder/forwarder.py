#!/usr/bin/env python3
"""
Log Forwarder - Tails Cowrie JSON log file and forwards events to Event Collector.

Maps Cowrie event types to CloudDecept event schema and POSTs to /ingest endpoint.
Includes GeoIP enrichment for attacker IPs.
"""

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Dict

import httpx

# GeoIP support (optional - graceful fallback if not available)
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False
    print("WARNING: geoip2 not available - GeoIP enrichment disabled")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
logger = logging.getLogger("log-forwarder")

# Configuration
COWRIE_LOG_PATH = os.getenv("COWRIE_LOG_PATH", "/cowrie/var/log/cowrie/cowrie.json")
EVENT_COLLECTOR_URL = os.getenv("EVENT_COLLECTOR_URL", "http://event-collector:8000")
INGEST_ENDPOINT = f"{EVENT_COLLECTOR_URL}/ingest"
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "10"))
BATCH_TIMEOUT = float(os.getenv("BATCH_TIMEOUT", "1.0"))
FORWARDER_SOURCE = os.getenv("FORWARDER_SOURCE", "cowrie_ssh")
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "/usr/share/GeoIP/GeoLite2-Country.mmdb")

# Cowrie event type mapping to CloudDecept event types
COWRIE_EVENT_MAP = {
    "cowrie.session.connect": "session_start",
    "cowrie.session.closed": "session_end",
    "cowrie.login.failed": "auth",
    "cowrie.login.success": "auth",
    "cowrie.command.input": "command",
    "cowrie.command.failed": "command",
    "cowrie.command.success": "command",
    "cowrie.session.input": "command",  # interactive input
    "cowrie.session.file_download": "file_transfer",
    "cowrie.session.file_upload": "file_transfer",
}


class GeoIPEnricher:
    """Enriches IP addresses with GeoIP data using local MaxMind database."""

    def __init__(self, db_path: str = GEOIP_DB_PATH):
        self.db_path = db_path
        self.reader = None
        self.enabled = GEOIP_AVAILABLE and os.path.exists(db_path)

        if self.enabled:
            try:
                self.reader = geoip2.database.Reader(db_path)
                logger.info(f"GeoIP enrichment enabled using {db_path}")
            except Exception as e:
                logger.error(f"Failed to initialize GeoIP reader: {e}")
                self.enabled = False
        else:
            if not GEOIP_AVAILABLE:
                logger.warning("GeoIP enrichment disabled: geoip2 package not installed")
            else:
                logger.warning(f"GeoIP enrichment disabled: database not found at {db_path}")

    def lookup(self, ip: str) -> Dict[str, str]:
        """Look up country and ASN for an IP address."""
        result = {"country": "", "asn": ""}

        if not self.enabled or not self.reader:
            return result

        # Skip private/internal IPs
        if self._is_private_ip(ip):
            return result

        try:
            response = self.reader.country(ip)
            if response.country and response.country.iso_code:
                result["country"] = response.country.iso_code
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip}: {e}")

        return result

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal."""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return True
            first = int(parts[0])
            second = int(parts[1])
            # Private ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x, 0.0.0.0
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:
                return True
            if ip == "0.0.0.0":
                return True
        except Exception:
            return True
        return False

    def close(self):
        """Close the GeoIP reader."""
        if self.reader:
            self.reader.close()


class LogForwarder:
    """Tails a JSON log file and forwards events to HTTP endpoint."""

    def __init__(self):
        self.log_path = Path(COWRIE_LOG_PATH)
        self.client: Optional[httpx.AsyncClient] = None
        self.buffer: list[dict] = []
        self.last_flush = time.time()
        self.position = 0
        self.geoip = GeoIPEnricher()

    async def initialize(self):
        """Initialize HTTP client and verify log file exists."""
        self.client = httpx.AsyncClient(timeout=30.0)

        # Wait for log file to exist
        while not self.log_path.exists():
            logger.info(f"Waiting for log file: {self.log_path}")
            await asyncio.sleep(2)

        # Seek to end of file to only process new events
        self.position = self.log_path.stat().st_size
        logger.info(f"Starting tail at position {self.position}")

    async def close(self):
        """Flush buffer and close client."""
        await self.flush()
        if self.client:
            await self.client.aclose()
        if self.geoip:
            self.geoip.close()

    def _map_event(self, cowrie_event: dict) -> Optional[dict]:
        """Map Cowrie event to CloudDecept ingest schema."""
        event_type = cowrie_event.get("eventid") or cowrie_event.get("event")
        if not event_type:
            logger.warning(f"Event missing eventid: {cowrie_event}")
            return None

        mapped_type = COWRIE_EVENT_MAP.get(event_type)
        if not mapped_type:
            logger.debug(f"No mapping for event type: {event_type}")
            return None

        # Extract session ID
        session_id = cowrie_event.get("session", "unknown")
        src_ip = cowrie_event.get("src_ip", "0.0.0.0")

        # GeoIP enrichment for attacker IP
        geoip_data = self.geoip.lookup(src_ip)

        # Parse timestamp
        timestamp = cowrie_event.get("timestamp")
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except Exception:
                dt = datetime.utcnow()
        else:
            dt = datetime.utcnow()

        # Build payload based on event type
        payload = {}

        if mapped_type == "session_start":
            payload = {
                "session_id": session_id,
                "protocol": cowrie_event.get("protocol", "ssh"),
                "client_version": cowrie_event.get("version", ""),
                "client_ip": src_ip,
                "attacker_ip": src_ip,
                "country": geoip_data.get("country", ""),
                "asn": geoip_data.get("asn", ""),
                "org": "",
                "timestamp": dt.isoformat(),
            }
        elif mapped_type == "session_end":
            raw_dur = cowrie_event.get("duration", 0)
            try:
                raw_float = float(raw_dur)
                # Cowrie outputs duration in seconds (float). If > 100,000 it might be ms.
                dur_secs = int(raw_float / 1000) if raw_float > 100000 else int(round(raw_float))
            except (ValueError, TypeError):
                dur_secs = 0
            payload = {
                "session_id": session_id,
                "duration_seconds": dur_secs,
                "commands_executed": 0,  # Could track from command events
                "files_transferred": 0,
                "credentials_tried": 0,
                "intent": "",
                "skill_level": 0,
                "disconnection_reason": cowrie_event.get("message", ""),
                "timestamp": dt.isoformat(),
            }
        elif mapped_type == "auth":
            payload = {
                "session_id": session_id,
                "username": cowrie_event.get("username", ""),
                "password": cowrie_event.get("password", ""),
                "protocol": cowrie_event.get("protocol", "ssh"),
                "success": event_type == "cowrie.login.success",
                "auth_method": cowrie_event.get("auth_method", "password"),
                "timestamp": dt.isoformat(),
            }
        elif mapped_type == "command":
            cmd = cowrie_event.get("input", "")
            logger.info(f"Mapped command event: session={session_id}, src_ip={src_ip}, command={cmd[:50] if cmd else 'empty'}, type={event_type}")
            payload = {
                "session_id": session_id,
                "command": cmd,
                "arguments": [],
                "working_directory": "/home/ubuntu",
                "exit_code": 0 if event_type != "cowrie.command.failed" else 1,
                "duration_ms": 0,
                "intent": "",
                "mitre_techniques": [],
                "timestamp": dt.isoformat(),
            }
        elif mapped_type == "file_transfer":
            payload = {
                "session_id": session_id,
                "filename": cowrie_event.get("filename", ""),
                "size_bytes": cowrie_event.get("size", 0),
                "direction": "download" if "download" in event_type else "upload",
                "protocol": "ssh",
                "timestamp": dt.isoformat(),
            }

        return {
            "source": FORWARDER_SOURCE,
            "event_type": mapped_type,
            "session_id": session_id,
            "attacker_ip": src_ip,
            "timestamp": dt.isoformat(),
            "payload": payload,
        }

    async def _process_line(self, line: str) -> Optional[dict]:
        """Parse and map a single log line."""
        line = line.strip()
        if not line:
            return None

        try:
            cowrie_event = json.loads(line)
        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON: {e} - line: {line[:100]}")
            return None

        return self._map_event(cowrie_event)

    async def flush(self):
        """Send buffered events to Event Collector."""
        if not self.buffer:
            return

        # Log event types in this batch
        event_types = {}
        for ev in self.buffer:
            et = ev.get("event_type", "unknown")
            event_types[et] = event_types.get(et, 0) + 1
        logger.info(f"Flushing batch: {event_types}")

        batch = self.buffer[:BATCH_SIZE]
        self.buffer = self.buffer[BATCH_SIZE:]

        try:
            response = await self.client.post(
                f"{EVENT_COLLECTOR_URL}/ingest/batch",
                json=batch,
                timeout=10.0,
            )
            if response.status_code == 200:
                results = response.json()
                success = sum(1 for r in results if r.get("success"))
                logger.info(f"Flushed {len(batch)} events: {success} succeeded")
                # Log command events details
                for i, (ev, result) in enumerate(zip(batch, results)):
                    if ev.get("event_type") == "command" and result.get("success"):
                        cmd = ev.get("payload", {}).get("command", "")
                        logger.info(f"  CMD sent: session={ev.get('session_id')}, command={cmd[:50] if cmd else 'empty'}")
            else:
                logger.error(f"Failed to flush batch: {response.status_code} {response.text}")
                # Re-buffer on failure
                self.buffer = batch + self.buffer
        except Exception as e:
            logger.error(f"Error flushing events: {e}")
            # Re-buffer on error
            self.buffer = batch + self.buffer

    async def tail_log(self):
        """Main tail loop."""
        logger.info("Starting log tail...")

        while True:
            try:
                stat = self.log_path.stat()
                current_size = stat.st_size

                if current_size < self.position:
                    # Log rotated
                    logger.info("Log file rotated, seeking to start")
                    self.position = 0

                if current_size > self.position:
                    # New content
                    with open(self.log_path, "r") as f:
                        f.seek(self.position)
                        lines = f.readlines()
                        self.position = f.tell()

                    for line in lines:
                        mapped = await self._process_line(line)
                        if mapped:
                            self.buffer.append(mapped)

                    # Flush if buffer full or timeout
                    if len(self.buffer) >= BATCH_SIZE:
                        await self.flush()
                    elif time.time() - self.last_flush > BATCH_TIMEOUT:
                        await self.flush()
                        self.last_flush = time.time()

                await asyncio.sleep(0.5)

            except FileNotFoundError:
                logger.warning("Log file not found, waiting...")
                await asyncio.sleep(2)
            except Exception as e:
                logger.error(f"Error in tail loop: {e}")
                await asyncio.sleep(1)


async def main():
    forwarder = LogForwarder()
    await forwarder.initialize()

    try:
        await forwarder.tail_log()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        await forwarder.close()


if __name__ == "__main__":
    asyncio.run(main())