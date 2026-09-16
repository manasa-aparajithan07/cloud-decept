"""Adaptive Engine API"""

import logging
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from config import settings
from adapter import adapt_response, should_adapt, ADAPTATION_STRATEGIES

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Track session states
session_states: Dict[str, Dict] = {}


class AdaptRequest(BaseModel):
    intent: str = Field(..., description="Predicted intent")
    original_response: Dict[str, Any] = Field(default_factory=dict, description="Original API response")
    session_context: Dict[str, Any] = Field(default_factory=dict, description="Session state")
    endpoint: str = Field(default="", description="API endpoint called")
    cloud_provider: str = Field(default="aws", description="Cloud provider")
    org_profile: str = Field(default="tech-startup-aws", description="Organization profile")


class AdaptResponse(BaseModel):
    adapted_response: Dict[str, Any]
    adaptation_applied: bool
    strategy: str
    message: str = ""


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Adaptive Engine started")
    yield
    logger.info("Adaptive Engine shutting down")


app = FastAPI(
    title="CloudDecept Adaptive Response Engine",
    description="Dynamic honeypot response adaptation based on attacker intent",
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
    return {"status": "healthy", "service": "adaptive-engine"}


@app.post("/adapt", response_model=AdaptResponse)
async def adapt(request: AdaptRequest):
    """Adapt response based on predicted intent"""

    session_id = request.session_context.get("session_id", "unknown")

    # Get or create session state
    if session_id not in session_states:
        session_states[session_id] = {
            "credential_attempts": 0,
            "privilege_escalation_attempts": 0,
            "credential_commands": 0,
            "data_access_commands": 0,
            "start_time": __import__("time").time()
        }

    session_state = session_states[session_id]

    # Check if we should adapt
    if not should_adapt(request.intent, session_state, request.endpoint):
        return AdaptResponse(
            adapted_response=request.original_response,
            adaptation_applied=False,
            strategy="none",
            message="No adaptation needed"
        )

    try:
        # Apply adaptation
        adapted = adapt_response(
            intent=request.intent,
            original_response=request.original_response,
            session_context=session_state,
            endpoint=request.endpoint,
            cloud_provider=request.cloud_provider,
            org_profile=request.org_profile
        )

        strategy = ADAPTATION_STRATEGIES.get(
            request.intent, {"name": "Default"}
        )["name"]

        return AdaptResponse(
            adapted_response=adapted,
            adaptation_applied=True,
            strategy=strategy,
            message=f"Applied {request.intent} adaptation"
        )

    except Exception as e:
        logger.error(f"Adaptation error: {e}")
        return AdaptResponse(
            adapted_response=request.original_response,
            adaptation_applied=False,
            strategy="error",
            message=f"Adaptation failed: {str(e)}"
        )


@app.get("/session/{session_id}")
async def get_session(session_id: str):
    """Get session adaptation state"""
    if session_id not in session_states:
        raise HTTPException(status_code=404, detail="Session not found")
    return session_states[session_id]


@app.delete("/session/{session_id}")
async def clear_session(session_id: str):
    """Clear session state"""
    session_states.pop(session_id, None)
    return {"status": "cleared"}


@app.get("/strategies")
async def list_strategies():
    """List available adaptation strategies"""
    return {k: {"name": v["name"], "description": v["description"]} for k, v in ADAPTATION_STRATEGIES.items()}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)