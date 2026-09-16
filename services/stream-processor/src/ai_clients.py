"""
AI Engine HTTP clients for Stream Processor.
Handles HTTP calls to Intent, Adaptive, and Threat Intel engines.
"""

import json
import logging
from typing import Any, Dict, List, Optional

import httpx

from src.config import settings

logger = logging.getLogger(__name__)


class AIClients:
    """HTTP clients for AI engine services."""

    def __init__(self):
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(settings.http_timeout_seconds, connect=5.0),
        )

    async def close(self) -> None:
        await self.client.aclose()

    # ============================================================
    # Intent Engine Client
    # ============================================================

    async def classify_intent(
        self,
        session_id: str,
        commands: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None,
        organization_profile: str = "tech-startup-aws",
    ) -> Optional[Dict[str, Any]]:
        """
        Call Intent Engine /classify endpoint.
        Returns the classification result or None on failure.
        """
        if not self.client:
            logger.error("HTTP client not initialized")
            return None

        payload = {
            "session_id": session_id,
            "organization_profile": organization_profile,
            "commands": commands or [],
            "context": context or {},
        }

        for attempt in range(settings.max_retries + 1):
            try:
                logger.info(f"Calling Intent Engine for session {session_id}")
                response = await self.client.post(
                    f"{settings.intent_engine_url}/classify",
                    json=payload,
                    timeout=settings.http_timeout_seconds,
                )
                logger.info(f"Intent Engine HTTP response for session {session_id}: {response.status_code}")

                if response.status_code == 200:
                    data = response.json()
                    logger.info(
                        f"Intent classified for session {session_id}: "
                        f"intent={data.get('intent')}, confidence={data.get('confidence')}"
                    )
                    return data
                else:
                    logger.warning(
                        f"Intent Engine returned {response.status_code}: {response.text}"
                    )

            except httpx.TimeoutException:
                logger.warning(f"Intent Engine timeout (attempt {attempt + 1})")
            except httpx.RequestError as e:
                logger.warning(f"Intent Engine request error: {e}")

            if attempt < settings.max_retries:
                import asyncio
                await asyncio.sleep(settings.retry_backoff_seconds * (attempt + 1))

        logger.error(f"Intent Engine failed after {settings.max_retries + 1} attempts")
        return None

    # ============================================================
    # Threat Intel Client
    # ============================================================

    async def analyze_threat(
        self,
        session_id: str,
        commands: List[Dict[str, Any]] = None,
        outputs: List[str] = None,
        intent_history: List[str] = None,
        attacker_ip: str = "unknown",
        attacker_country: str = "unknown",
        duration_seconds: int = 0,
    ) -> Optional[Dict[str, Any]]:
        """
        Call Threat Intel /analyze endpoint.
        Returns the analysis result or None on failure.
        """
        if not self.client:
            logger.error("HTTP client not initialized")
            return None

        payload = {
            "session_id": session_id,
            "commands": commands or [],
            "outputs": outputs or [],
            "intent_history": intent_history or [],
            "attacker_ip": attacker_ip,
            "attacker_country": attacker_country,
            "duration_seconds": duration_seconds,
        }

        for attempt in range(settings.max_retries + 1):
            try:
                logger.info(f"Calling Threat Intel for session {session_id}")
                response = await self.client.post(
                    f"{settings.threat_intel_url}/analyze",
                    json=payload,
                    timeout=settings.http_timeout_seconds,
                )
                logger.info(f"Threat Intel HTTP response for session {session_id}: {response.status_code}")

                if response.status_code == 200:
                    data = response.json()
                    logger.info(f"Threat analysis completed for session {session_id}")
                    return data
                else:
                    logger.warning(
                        f"Threat Intel returned {response.status_code}: {response.text}"
                    )

            except httpx.TimeoutException:
                logger.warning(f"Threat Intel timeout (attempt {attempt + 1})")
            except httpx.RequestError as e:
                logger.warning(f"Threat Intel request error: {e}")

            if attempt < settings.max_retries:
                import asyncio
                await asyncio.sleep(settings.retry_backoff_seconds * (attempt + 1))

        logger.error(f"Threat Intel failed after {settings.max_retries + 1} attempts")
        return None

    # ============================================================
    # Adaptive Engine Client
    # ============================================================

    async def adapt_response(
        self,
        intent: str,
        original_response: Optional[Dict[str, Any]] = None,
        session_context: Optional[Dict[str, Any]] = None,
        endpoint: str = "",
        cloud_provider: str = "aws",
        org_profile: str = "tech-startup-aws",
    ) -> Optional[Dict[str, Any]]:
        """
        Call Adaptive Engine /adapt endpoint.
        Returns the adapted response or None on failure.
        """
        if not self.client:
            logger.error("HTTP client not initialized")
            return None

        payload = {
            "intent": intent,
            "original_response": original_response or {},
            "session_context": session_context or {},
            "endpoint": endpoint,
            "cloud_provider": cloud_provider,
            "org_profile": org_profile,
        }

        for attempt in range(settings.max_retries + 1):
            try:
                logger.info(f"Calling Adaptive Engine for intent {intent}")
                response = await self.client.post(
                    f"{settings.adaptive_engine_url}/adapt",
                    json=payload,
                    timeout=settings.http_timeout_seconds,
                )
                logger.info(f"Adaptive Engine HTTP response for intent {intent}: {response.status_code}")

                if response.status_code == 200:
                    data = response.json()
                    logger.info(f"Adaptation applied for intent: {intent}")
                    return data
                else:
                    logger.warning(
                        f"Adaptive Engine returned {response.status_code}: {response.text}"
                    )

            except httpx.TimeoutException:
                logger.warning(f"Adaptive Engine timeout (attempt {attempt + 1})")
            except httpx.RequestError as e:
                logger.warning(f"Adaptive Engine request error: {e}")

            if attempt < settings.max_retries:
                import asyncio
                await asyncio.sleep(settings.retry_backoff_seconds * (attempt + 1))

        logger.error(f"Adaptive Engine failed after {settings.max_retries + 1} attempts")
        return None

    async def health_check(self) -> Dict[str, bool]:
        """Check health of all AI services."""
        results = {}

        # Intent Engine
        try:
            resp = await self.client.get(f"{settings.intent_engine_url}/health", timeout=5.0)
            results["intent_engine"] = resp.status_code == 200
        except Exception:
            results["intent_engine"] = False

        # Adaptive Engine
        try:
            resp = await self.client.get(f"{settings.adaptive_engine_url}/health", timeout=5.0)
            results["adaptive_engine"] = resp.status_code == 200
        except Exception:
            results["adaptive_engine"] = False

        # Threat Intel
        try:
            resp = await self.client.get(f"{settings.threat_intel_url}/health", timeout=5.0)
            results["threat_intel"] = resp.status_code == 200
        except Exception:
            results["threat_intel"] = False

        return results