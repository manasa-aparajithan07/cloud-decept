"""
LLM Gateway Service - Abstracts LLM providers behind a unified API.
Supports: Ollama, OpenAI, Claude, Gemini, Azure OpenAI, NVIDIA NIM
"""
from __future__ import annotations

import os
import time
import uuid
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

import httpx
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field, ConfigDict

from backend.schemas.events import (
    EventSource,
    LLMRequestEvent,
    LLMResponseEvent,
    StreamNames,
)


class LLMProvider(str, Enum):
    OLLAMA = "ollama"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    AZURE_OPENAI = "azure_openai"
    NVIDIA_NIM = "nvidia_nim"


class LLMProviderBase(ABC):
    """Abstract base class for LLM providers"""

    @abstractmethod
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        model: str = "",
        temperature: float = 0.0,
        max_tokens: int = 512,
    ) -> tuple[str, dict[str, int]]:
        """Generate response from LLM. Returns (response_text, token_usage)"""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if provider is available"""
        pass

    @abstractmethod
    def get_model_list(self) -> list[str]:
        """Get available models"""
        pass


class OllamaProvider(LLMProviderBase):
    """Ollama local LLM provider"""

    def __init__(self, base_url: str = "http://ollama:11434"):
        self.base_url = base_url.rstrip("/")
        self.client = httpx.AsyncClient(timeout=180.0)  # Increased from 120s to 180s for slower models

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        model: str = "qwen2.5:1.5b",
        temperature: float = 0.0,
        max_tokens: int = 512,
    ) -> tuple[str, dict[str, int]]:
        payload = {
            "model": model,
            "prompt": prompt,
            "system": system_prompt or "",
            "temperature": temperature,
            "num_predict": max_tokens,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            }
        }

        start = time.time()
        response = await self.client.post(f"{self.base_url}/api/generate", json=payload)
        response.raise_for_status()
        latency_ms = int((time.time() - start) * 1000)

        data = response.json()
        return data.get("response", ""), {
            "prompt_tokens": data.get("prompt_eval_count", 0),
            "completion_tokens": data.get("eval_count", 0),
            "latency_ms": latency_ms,
        }

    async def health_check(self) -> bool:
        try:
            resp = await self.client.get(f"{self.base_url}/api/tags", timeout=5.0)
            return resp.status_code == 200
        except Exception:
            return False

    def get_model_list(self) -> list[str]:
        return [
            "qwen2.5:1.5b"
        ]


class OpenAIProvider(LLMProviderBase):
    """OpenAI API provider"""

    def __init__(self, api_key: str, base_url: str = "https://api.openai.com/v1"):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.client = httpx.AsyncClient(
            timeout=180.0,  # Increased from 120s to 180s for consistency
            headers={"Authorization": f"Bearer {api_key}"}
        )

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        model: str = "gpt-4o-mini",
        temperature: float = 0.0,
        max_tokens: int = 512,
    ) -> tuple[str, dict[str, int]]:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        start = time.time()
        response = await self.client.post(f"{self.base_url}/chat/completions", json=payload)
        response.raise_for_status()
        latency_ms = int((time.time() - start) * 1000)

        data = response.json()
        return data["choices"][0]["message"]["content"], {
            "prompt_tokens": data["usage"]["prompt_tokens"],
            "completion_tokens": data["usage"]["completion_tokens"],
            "latency_ms": latency_ms,
        }

    async def health_check(self) -> bool:
        try:
            resp = await self.client.get(f"{self.base_url}/models", timeout=10.0)
            return resp.status_code == 200
        except Exception:
            return False

    def get_model_list(self) -> list[str]:
        return ["gpt-4o-mini", "gpt-3.5-turbo"]


class AnthropicProvider(LLMProviderBase):
    """Anthropic Claude API provider"""

    def __init__(self, api_key: str, base_url: str = "https://api.anthropic.com/v1"):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.client = httpx.AsyncClient(
            timeout=180.0,  # Increased from 120s to 180s for consistency
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01"
            }
        )

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        model: str = "claude-3-haiku-20240307",
        temperature: float = 0.0,
        max_tokens: int = 512,
    ) -> tuple[str, dict[str, int]]:
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system_prompt:
            payload["system"] = system_prompt

        start = time.time()
        response = await self.client.post(f"{self.base_url}/messages", json=payload)
        response.raise_for_status()
        latency_ms = int((time.time() - start) * 1000)

        data = response.json()
        return data["content"][0]["text"], {
            "prompt_tokens": data["usage"]["input_tokens"],
            "completion_tokens": data["usage"]["output_tokens"],
            "latency_ms": latency_ms,
        }

    async def health_check(self) -> bool:
        # Anthropic doesn't have a simple health endpoint
        return bool(self.api_key)

    def get_model_list(self) -> list[str]:
        return ["claude-3-haiku-20240307", "claude-3-sonnet-20240229"]


class LLMGateway:
    """Main gateway managing all providers"""

    def __init__(self):
        self.providers: dict[LLMProvider, LLMProviderBase] = {}
        self.default_provider = LLMProvider(os.getenv("LLM_PROVIDER", "ollama"))
        self._initialize_providers()

    def _initialize_providers(self):
        # Ollama (always available locally)
        ollama_url = os.getenv("OLLAMA_URL", "http://ollama:11434")
        self.providers[LLMProvider.OLLAMA] = OllamaProvider(ollama_url)

        # OpenAI
        if openai_key := os.getenv("OPENAI_API_KEY"):
            self.providers[LLMProvider.OPENAI] = OpenAIProvider(openai_key)

        # Anthropic
        if anthropic_key := os.getenv("ANTHROPIC_API_KEY"):
            self.providers[LLMProvider.ANTHROPIC] = AnthropicProvider(anthropic_key)

    def get_provider(self, provider: LLMProvider) -> LLMProviderBase:
        if provider not in self.providers:
            raise ValueError(f"Provider {provider} not configured")
        return self.providers[provider]

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        model: str = "",
        temperature: float = 0.0,
        max_tokens: int = 512,
        provider: Optional[LLMProvider] = None,
    ) -> tuple[str, dict[str, int]]:
        provider = provider or self.default_provider
        provider_instance = self.get_provider(provider)
        return await provider_instance.generate(
            prompt, system_prompt, model, temperature, max_tokens
        )

    async def health_check(self, provider: Optional[LLMProvider] = None) -> dict[str, bool]:
        results = {}
        providers_to_check = [provider] if provider else list(self.providers.keys())
        for p in providers_to_check:
            if p in self.providers:
                results[p.value] = await self.providers[p].health_check()
        return results


# --- FastAPI Application ---

gateway = LLMGateway()


class GenerateRequest(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    prompt: str
    system_prompt: Optional[str] = None
    model: str = ""
    temperature: float = 0.0
    max_tokens: int = 512
    provider: Optional[LLMProvider] = None
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request_type: str = "general"


class GenerateResponse(BaseModel):
    request_id: str
    response: str
    model: str
    provider: str
    latency_ms: int
    tokens_used: dict[str, int]
    success: bool
    error: Optional[str] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    yield
    # Shutdown
    for provider in gateway.providers.values():
        if hasattr(provider, 'client'):
            await provider.client.aclose()


app = FastAPI(
    title="CloudDecept LLM Gateway",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health(request: Request, provider: Optional[LLMProvider] = None):
    results = await gateway.health_check(provider)
    return {"status": "healthy" if any(results.values()) else "degraded", "providers": results}


@app.post("/generate", response_model=GenerateResponse)
async def generate(request: GenerateRequest):
    try:
        provider = request.provider or gateway.default_provider
        provider_instance = gateway.get_provider(provider)

        model = request.model or (
            "qwen2.5:1.5b" if provider == LLMProvider.OLLAMA else "gpt-4o-mini"
        )

        response_text, token_usage = await provider_instance.generate(
            prompt=request.prompt,
            system_prompt=request.system_prompt,
            model=model,
            temperature=request.temperature,
            max_tokens=request.max_tokens,
        )

        provider_str = provider.value if isinstance(provider, LLMProvider) else (str(provider) if provider else "unknown")

        return GenerateResponse(
            request_id=request.request_id,
            response=response_text,
            model=model,
            provider=provider_str,
            latency_ms=token_usage.get("latency_ms", 0),
            tokens_used={
                "prompt": token_usage.get("prompt_tokens", 0),
                "completion": token_usage.get("completion_tokens", 0),
            },
            success=True,
        )
    except Exception as e:
        return GenerateResponse(
            request_id=request.request_id,
            response="",
            model="",
            provider=provider.value if isinstance(provider, LLMProvider) else (str(provider) if provider else "unknown"),
            latency_ms=0,
            tokens_used={},
            success=False,
            error=str(e),
        )


@app.get("/models")
async def list_models(provider: Optional[LLMProvider] = None):
    if provider:
        p = gateway.get_provider(provider)
        return {"provider": provider.value, "models": p.get_model_list()}
    return {p.value: gw.get_model_list() for p, gw in gateway.providers.items()}


@app.post("/intent/classify")
async def classify_intent(
    commands: list[str],
    context: dict[str, Any] = None,
    model: str = "",
):
    """Specialized endpoint for intent classification"""
    from backend.schemas.events import IntentCategory

    # Construct classification prompt
    prompt = f"""Classify attacker intent from cloud commands:

COMMANDS:
{chr(10).join(f"- {cmd}" for cmd in commands)}

CONTEXT: {context or {}}

Categories: {', '.join([c.value for c in IntentCategory])}

Respond with JSON: {{"intent": "...", "confidence": 0.0-1.0, "skill": 1-10, "reasoning": "..."}}"""

    try:
        response_text, token_usage = await gateway.generate(
            prompt=prompt,
            system_prompt="You are a cybersecurity expert classifying attacker intent from honeypot logs. Respond ONLY with valid JSON.",
            model=model or "qwen2.5:1.5b",
            temperature=0.0,
            max_tokens=512,
        )

        import json
        result = json.loads(response_text)
        result["raw_response"] = response_text
        result["tokens_used"] = token_usage
        return result
    except Exception as e:
        return {
            "intent": "unknown",
            "confidence": 0.0,
            "skill": 1,
            "reasoning": f"Classification failed: {e}",
            "error": str(e),
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)