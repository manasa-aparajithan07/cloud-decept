"""Threat Intelligence Engine Service"""

import logging
from contextlib import asynccontextmanager
from typing import Dict, Any, List, Optional

import httpx
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from config import settings
from intel import (
    IOCExtractor,
    MITREMapper,
    ExtractedIOC,
    MappedTechnique
)
from rule_based_summarizer import RuleBasedSummarizer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global instances
ioc_extractor = IOCExtractor()
mitre_mapper = MITREMapper()
session_summarizer: Optional[RuleBasedSummarizer] = None
event_collector_client: Optional[httpx.AsyncClient] = None


# Request/Response models
class AnalyzeSessionRequest(BaseModel):
    session_id: str
    commands: List[Dict[str, Any]] = Field(default_factory=list)
    outputs: List[str] = Field(default_factory=list)
    intent_history: List[str] = Field(default_factory=list)
    attacker_ip: str = "unknown"
    attacker_country: str = "unknown"
    duration_seconds: int = 0


class IOCResponse(BaseModel):
    type: str
    value: str
    context: str
    confidence: float
    first_seen: str


class TechniqueResponse(BaseModel):
    technique_id: str
    name: str
    tactic: str
    severity: str
    trigger: str
    confidence: float


class SessionSummaryResponse(BaseModel):
    skill_level: int
    primary_objective: str
    techniques_summary: str
    iocs_of_interest: List[str]
    risk_level: str
    defensive_recommendations: List[str]
    narrative: str
    generated_at: str
    model: str


class AnalysisResponse(BaseModel):
    session_id: str
    iocs: List[IOCResponse]
    techniques: List[TechniqueResponse]
    tactic_summary: Dict[str, int]
    summary: Optional[SessionSummaryResponse] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global session_summarizer, event_collector_client
    session_summarizer = RuleBasedSummarizer()
    event_collector_client = httpx.AsyncClient(timeout=30.0)
    logger.info("Threat Intelligence Engine started (rule-based)")
    yield
    if event_collector_client:
        await event_collector_client.aclose()
    logger.info("Threat Intelligence Engine shutting down")


app = FastAPI(
    title="CloudDecept Threat Intelligence Engine",
    description="MITRE ATT&CK mapping, IOC extraction, and session summarization (rule-based)",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "threat-intel",
        "summarizer_ready": session_summarizer is not None
    }


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_session(request: AnalyzeSessionRequest, background_tasks: BackgroundTasks):
    """Analyze a session for IOCs, MITRE techniques, and generate summary"""

    def _safe_get(cmd: Dict[str, Any], key: str, fallback: str = "") -> str:
        """Safely get a string value from a command dict, handling None values."""
        val = cmd.get(key)
        if val is None:
            return ""
        if isinstance(val, str):
            return val
        return str(val)

    # Extract IOCs
    all_text = " ".join([
        (_safe_get(cmd, "cmd") or _safe_get(cmd, "command") or "") + " " + _safe_get(cmd, "output")
        for cmd in request.commands
    ] + request.outputs)

    iocs = ioc_extractor.extract(all_text)

    # Map to MITRE
    techniques = mitre_mapper.map_commands(request.commands)
    tactic_summary = mitre_mapper.get_tactic_summary(techniques)

    # Generate summary in background
    summary = None
    if session_summarizer:
        session_data = {
            "session_id": request.session_id,
            "commands": request.commands,
            "intent_history": request.intent_history,
            "iocs": iocs,
            "techniques": techniques,
            "attacker_ip": request.attacker_ip,
            "attacker_country": request.attacker_country,
            "duration_seconds": request.duration_seconds
        }
        summary_dict = session_summarizer.summarize(session_data)
        summary = SessionSummaryResponse(**summary_dict)

        # Persist skill_level and primary intent to ClickHouse via event collector
        if event_collector_client and summary:
            try:
                # Use the latest intent from history, or primary_objective as intent
                intent = request.intent_history[-1] if request.intent_history else summary.primary_objective
                skill_level = summary.skill_level

                response = await event_collector_client.post(
                    f"{settings.EVENT_COLLECTOR_URL}/update-session",
                    json={
                        "session_id": request.session_id,
                        "intent": intent,
                        "skill_level": skill_level
                    }
                )
                if response.status_code == 200:
                    result = response.json()
                    if result.get("success"):
                        logger.info(f"Updated session {request.session_id} with intent={intent}, skill_level={skill_level}")
                    else:
                        logger.warning(f"Failed to update session {request.session_id}: {result.get('error')}")
                else:
                    logger.warning(f"Event collector returned {response.status_code} for session update")
            except Exception as e:
                logger.warning(f"Failed to persist session analysis: {e}")

    return AnalysisResponse(
        session_id=request.session_id,
        iocs=[IOCResponse(**ioc.__dict__) for ioc in iocs],
        techniques=[TechniqueResponse(**tech.__dict__) for tech in techniques],
        tactic_summary=tactic_summary,
        summary=summary
    )


@app.post("/extract-iocs")
async def extract_iocs(text: str):
    """Extract IOCs from raw text"""
    iocs = ioc_extractor.extract(text)
    return {"iocs": [IOCResponse(**ioc.__dict__) for ioc in iocs]}


@app.post("/map-mitre")
async def map_mitre(commands: List[Dict[str, Any]]):
    """Map commands to MITRE ATT&CK techniques"""
    techniques = mitre_mapper.map_commands(commands)
    tactic_summary = mitre_mapper.get_tactic_summary(techniques)
    return {
        "techniques": [TechniqueResponse(**tech.__dict__) for tech in techniques],
        "tactic_summary": tactic_summary
    }


@app.post("/summarize")
async def summarize(request: AnalyzeSessionRequest):
    """Generate LLM summary of session"""
    if not session_summarizer:
        raise HTTPException(status_code=503, detail="Summarizer not ready")

    def _safe_get(cmd: Dict[str, Any], key: str, fallback: str = "") -> str:
        """Safely get a string value from a command dict, handling None values."""
        val = cmd.get(key)
        if val is None:
            return ""
        if isinstance(val, str):
            return val
        return str(val)

    session_data = {
        "session_id": request.session_id,
        "commands": request.commands,
        "intent_history": request.intent_history,
        "iocs": ioc_extractor.extract(" ".join([
            (_safe_get(cmd, "cmd") or _safe_get(cmd, "command") or "") + " " + _safe_get(cmd, "output")
            for cmd in request.commands
        ])),
        "techniques": mitre_mapper.map_commands(request.commands),
        "attacker_ip": request.attacker_ip,
        "attacker_country": request.attacker_country,
        "duration_seconds": request.duration_seconds
    }

    summary_dict = session_summarizer.summarize(session_data)
    summary = SessionSummaryResponse(**summary_dict)

    # Persist skill_level and primary intent to ClickHouse via event collector
    if event_collector_client and summary:
        try:
            intent = request.intent_history[-1] if request.intent_history else summary.primary_objective
            skill_level = summary.skill_level

            response = await event_collector_client.post(
                f"{settings.EVENT_COLLECTOR_URL}/update-session",
                json={
                    "session_id": request.session_id,
                    "intent": intent,
                    "skill_level": skill_level
                }
            )
            if response.status_code == 200:
                result = response.json()
                if result.get("success"):
                    logger.info(f"Updated session {request.session_id} with intent={intent}, skill_level={skill_level}")
                else:
                    logger.warning(f"Failed to update session {request.session_id}: {result.get('error')}")
            else:
                logger.warning(f"Event collector returned {response.status_code} for session update")
        except Exception as e:
            logger.warning(f"Failed to persist session analysis: {e}")

    return summary


@app.get("/mitre-catalog")
async def get_mitre_catalog():
    """Get all known MITRE cloud techniques"""
    from intel import MITRE_CLOUD_TECHNIQUES
    return {"techniques": MITRE_CLOUD_TECHNIQUES}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8005)