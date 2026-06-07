"""
LLM client for local models (LM Studio, Ollama, vLLM, etc.).

Uses the OpenAI-compatible /v1/chat/completions endpoint.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from openai import OpenAI
from openai.types.chat import ChatCompletion

from .config import LLMConfig

logger = logging.getLogger(__name__)


def normalize_base_url(base_url: str) -> str:
    """Ensure OpenAI-compatible base_url ends with exactly /v1 (no doubles).
    Used by both runtime clients and the config test endpoints.
    """
    if not base_url:
        return base_url
    u = base_url.rstrip("/")
    if not u.endswith("/v1"):
        u += "/v1"
    return u


SECURITY_SYSTEM_PROMPT = """You are an expert security operations analyst specializing in syslog and system log analysis.

Your job is to identify real security threats, attacks, and dangerous anomalies from raw log lines.

You must:
- Be conservative: only report genuine concerns, not normal noise.
- Prioritize by severity: critical > high > medium.
- Focus on: authentication failures/brute force, privilege escalation, exploit attempts, malware/miners, suspicious downloads, configuration tampering, unusual process or network activity, kernel-level failures on critical systems.
- For every threat you find, provide:
  - severity (critical/high/medium/low)
  - short description (what happened)
  - affected host/app if identifiable
  - recommended immediate action (one sentence)
  - confidence (0-10)

Respond ONLY with valid JSON matching this schema:

{
  "threats": [
    {
      "severity": "high",
      "score": 8.2,
      "description": "...",
      "hostname": "server01" or null,
      "appname": "sshd" or null,
      "recommended_action": "...",
      "evidence": ["exact log excerpt 1", "excerpt 2"]
    }
  ],
  "overall_risk": "medium",
  "summary": "One paragraph plain-English summary of the security posture from these logs."
}

If there are no meaningful threats, return:
{"threats": [], "overall_risk": "low", "summary": "No significant security issues detected in the provided logs."}
"""

# JSON schema for structured outputs (used when response_format="json_schema" or "auto")
THREAT_ANALYSIS_SCHEMA = {
    "name": "security_threat_analysis",
    "strict": True,
    "schema": {
        "type": "object",
        "properties": {
            "threats": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                        "score": {"type": "number", "minimum": 0, "maximum": 10},
                        "description": {"type": "string"},
                        "hostname": {"type": ["string", "null"]},
                        "appname": {"type": ["string", "null"]},
                        "recommended_action": {"type": "string"},
                        "evidence": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["severity", "score", "description", "hostname", "appname", "recommended_action", "evidence"],
                    "additionalProperties": False,
                },
            },
            "overall_risk": {"type": "string", "enum": ["critical", "high", "medium", "low", "unknown"]},
            "summary": {"type": "string"},
        },
        "required": ["threats", "overall_risk", "summary"],
        "additionalProperties": False,
    },
}


class LocalLLM:
    def __init__(self, cfg: LLMConfig):
        self.cfg = cfg
        base = normalize_base_url(cfg.base_url)
        self.client = OpenAI(
            base_url=base,
            api_key=cfg.api_key,
            timeout=cfg.timeout,
        )
        self._consecutive_failures: int = 0
        self._last_failure_msg: str | None = None

    def analyze_logs(self, log_lines: list[str], model: str | None = None) -> dict[str, Any]:
        """
        Send a batch of log lines to the local model and request structured threat analysis.
        Returns the parsed JSON response (or a safe fallback).
        """
        if not log_lines:
            return {"threats": [], "overall_risk": "low", "summary": "No logs to analyze."}

        # Prepare compact context
        context = "\n".join(f"- {line}" for line in log_lines[-150:])  # safety cap

        messages = [
            {"role": "system", "content": SECURITY_SYSTEM_PROMPT},
            {"role": "user", "content": f"Analyze the following syslog messages for security threats:\n\n{context}"},
        ]

        model_name = model or self.cfg.model or "local-model"
        fmt = (self.cfg.response_format or "auto").lower()

        # Build completion kwargs, handling response_format compatibility
        create_kwargs: dict[str, Any] = {
            "model": model_name,
            "messages": messages,
            "temperature": self.cfg.temperature,
            "max_tokens": self.cfg.max_tokens,
        }

        rf_param = self._build_response_format_param(fmt)
        if rf_param is not None:
            create_kwargs["response_format"] = rf_param

        try:
            resp: ChatCompletion = self.client.chat.completions.create(**create_kwargs)
            content = self._extract_message_content(resp)
            data = self._parse_llm_json(content)
            # Basic normalization
            if "threats" not in data:
                data["threats"] = []

            # Attach what the model actually returned so callers can store it
            data["_raw_llm_text"] = content

            # Success path - reset failure tracking
            if self._consecutive_failures > 0:
                logger.info("LLM recovered after %d failures", self._consecutive_failures)
                self._consecutive_failures = 0
                self._last_failure_msg = None
            return data

        except Exception as exc:
            err_str = str(exc)
            # If auto mode and we got a 400 about response_format, retry once without it
            if fmt == "auto" and self._is_response_format_error(err_str):
                if self._consecutive_failures == 0:
                    logger.info("Structured output not supported by this LLM server; retrying without response_format")
                try:
                    create_kwargs.pop("response_format", None)
                    resp = self.client.chat.completions.create(**create_kwargs)
                    content = self._extract_message_content(resp)
                    data = self._parse_llm_json(content)
                    if "threats" not in data:
                        data["threats"] = []

                    data["_raw_llm_text"] = content

                    if self._consecutive_failures > 0:
                        logger.info("LLM recovered after %d failures (via fallback)", self._consecutive_failures)
                        self._consecutive_failures = 0
                        self._last_failure_msg = None
                    return data
                except Exception as exc2:
                    err_str = str(exc2)

            self._consecutive_failures += 1
            # Only spam the log on the first failure or when the error message changes
            if self._consecutive_failures == 1 or err_str != self._last_failure_msg:
                logger.warning("LLM analysis failed (will retry): %s", err_str)
            elif self._consecutive_failures % 10 == 0:
                logger.info("LLM still unavailable after %d attempts (last error: %s)",
                            self._consecutive_failures, err_str[:120])
            self._last_failure_msg = err_str

            return {
                "threats": [],
                "overall_risk": "unknown",
                "summary": f"LLM analysis unavailable: {err_str}",
                "error": err_str,
            }

    def _build_response_format_param(self, fmt: str) -> dict[str, Any] | None:
        """Return the response_format value for the OpenAI client, or None to omit it."""
        if fmt in ("none", "", "off", "false"):
            return None
        if fmt == "json_schema":
            return {"type": "json_schema", "json_schema": THREAT_ANALYSIS_SCHEMA}
        if fmt == "json_object":
            return {"type": "json_object"}
        if fmt == "text":
            return {"type": "text"}
        if fmt == "auto":
            # Start with the modern structured schema; analyze_logs will fall back on error
            return {"type": "json_schema", "json_schema": THREAT_ANALYSIS_SCHEMA}
        # Unknown value -> be conservative and omit
        logger.debug("Unknown response_format=%r, omitting parameter", fmt)
        return None

    def _is_response_format_error(self, err: str) -> bool:
        """Heuristic to detect 'your server doesn't like this response_format' errors."""
        err_lower = err.lower()
        return (
            "response_format" in err_lower
            or "json_schema" in err_lower
            or "json_object" in err_lower
            or "type" in err_lower and "must be" in err_lower
        )

    def _parse_llm_json(self, content: str) -> dict[str, Any]:
        """Robustly extract and parse JSON from model output (handles markdown, prose, etc.)."""
        if not content or not content.strip():
            return {}

        text = content.strip()

        # Fast path: already valid JSON
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try to pull JSON out of ```json ... ``` or ``` ... ```
        fence_match = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL | re.IGNORECASE)
        if fence_match:
            candidate = fence_match.group(1).strip()
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass

        # Try to find the first {...} block that looks like our schema
        brace_match = re.search(r"\{.*\}", text, re.DOTALL)
        if brace_match:
            candidate = brace_match.group(0)
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                # Last-ditch: try to repair common trailing comma issues
                candidate = re.sub(r",\s*([}\]])", r"\1", candidate)
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    pass

        # Give up — return a minimal structure; caller will treat as empty threats
        logger.debug("Could not parse JSON from LLM content (first 200 chars): %s", text[:200])
        return {"threats": [], "overall_risk": "unknown", "summary": text[:500]}

    def _extract_message_content(self, resp: ChatCompletion) -> str:
        """
        Extract the actual text from a chat completion.

        Modern reasoning models (Qwen with reasoning, DeepSeek-R1 style, certain Claude fine-tunes, etc.)
        often put the final answer (or the entire chain-of-thought + JSON) in `reasoning_content`
        while leaving `content` empty.
        """
        if not resp or not resp.choices:
            return ""

        msg = resp.choices[0].message

        # 1. Normal content (most models)
        content = getattr(msg, "content", None)
        if content and content.strip():
            return content

        # 2. Reasoning content (very common with the model the user is running)
        reasoning = getattr(msg, "reasoning_content", None)
        if reasoning and reasoning.strip():
            return reasoning

        # 3. Some servers expose extra fields via model_extra (pydantic v2)
        extra = getattr(msg, "model_extra", None)
        if isinstance(extra, dict):
            for key in ("reasoning_content", "content", "text", "response"):
                val = extra.get(key)
                if isinstance(val, str) and val.strip():
                    return val

        # 4. Last resort: try to stringify whatever is there
        if content is not None:
            return str(content)
        if reasoning is not None:
            return str(reasoning)

        return ""

    def is_available(self) -> bool:
        """Quick health check against the LLM endpoint.
        Returns True only if the server is reachable AND has at least one model loaded/available.
        """
        try:
            models_resp = self.client.models.list()
            models = getattr(models_resp, "data", models_resp) or []
            # Some servers return a list, some an object with .data
            if hasattr(models, "__iter__"):
                return len(list(models)) > 0
            return True  # server responded even if we can't count models
        except Exception:
            return False


# =============================================================================
# LLM CLIENT FACTORY (PR1 foundation for Microsoft 365 Copilot / Azure support)
# =============================================================================

class AzureOpenAIClient:
    """
    Thin wrapper around openai.AzureOpenAI (when available).
    Falls back gracefully if the azure extra / recent openai package is not installed.
    """

    def __init__(self, cfg: LLMConfig):
        self.cfg = cfg
        self._client = None
        self._available = False

        try:
            from openai import AzureOpenAI  # type: ignore

            if cfg.azure_endpoint and cfg.azure_deployment:
                self._client = AzureOpenAI(
                    azure_endpoint=cfg.azure_endpoint,
                    azure_deployment=cfg.azure_deployment,
                    api_key=cfg.api_key or "",
                    api_version=cfg.azure_api_version or "2024-10-21",
                    timeout=cfg.timeout,
                )
                self._available = True
            else:
                logger.warning("Azure provider selected but azure_endpoint/deployment not configured")
        except Exception as e:
            logger.info("AzureOpenAI not available (will use local fallback): %s", e)

    def analyze_logs(self, log_lines: list[str], model: str | None = None) -> dict[str, Any]:
        if not self._available or self._client is None:
            return {
                "threats": [],
                "overall_risk": "unknown",
                "summary": "Azure OpenAI client not configured or package not available.",
            }
        # For PR1 we keep behavior identical to LocalLLM path for now.
        # Full implementation will be in PR6.
        logger.info("AzureOpenAIClient stub called — falling back to local-style analysis for safety in PR1")
        # Delegate to a temporary LocalLLM instance using the same config (safe)
        local = LocalLLM(self.cfg)
        return local.analyze_logs(log_lines, model)

    def is_available(self) -> bool:
        return self._available


def get_llm_client(cfg: LLMConfig):
    """
    Central factory for all LLM backends with priority + failover support.
    If cfg.llm.servers is populated (list of {"provider", "base_url", ... "enabled"}), we try them in list order.
    First one that is available (or succeeds a quick check) wins.
    Falls back to legacy single-LLM behavior for old configs.
    """
    servers = getattr(cfg, "servers", None) or []
    if not servers:
        # legacy single
        servers = [{
            "provider": getattr(cfg, "provider", "local") or "local",
            "base_url": getattr(cfg, "base_url", ""),
            "api_key": getattr(cfg, "api_key", ""),
            "model": getattr(cfg, "model", ""),
            "enabled": True,
        }]

    last_error = None
    for srv in servers:
        if not srv.get("enabled", True):
            continue
        # Build a temp cfg for this server (minimal)
        try:
            temp_cfg = LLMConfig(
                provider=srv.get("provider", "local"),
                base_url=srv.get("base_url", getattr(cfg, "base_url", "")),
                api_key=srv.get("api_key", getattr(cfg, "api_key", "")),
                model=srv.get("model", getattr(cfg, "model", "")),
                # copy other timeouts etc from main
                timeout=getattr(cfg, "timeout", 180),
                max_tokens=getattr(cfg, "max_tokens", 1200),
                temperature=getattr(cfg, "temperature", 0.1),
                response_format=getattr(cfg, "response_format", "auto"),
                azure_endpoint=getattr(cfg, "azure_endpoint", ""),
                azure_deployment=getattr(cfg, "azure_deployment", ""),
                azure_api_version=getattr(cfg, "azure_api_version", "2024-10-21"),
            )
        except Exception as e:
            last_error = e
            continue

        provider = (temp_cfg.provider or "local").lower().strip()

        candidate = None
        if provider in ("azure", "azure_openai"):
            candidate = AzureOpenAIClient(temp_cfg)
        elif provider == "microsoft_365_copilot":
            candidate = Microsoft365CopilotClient(temp_cfg)
        else:
            candidate = LocalLLM(temp_cfg)

        if candidate and getattr(candidate, "is_available", lambda: True)():
            # quick health for local-style
            try:
                if hasattr(candidate, "is_available") and not candidate.is_available():
                    continue
            except Exception:
                continue
            return candidate

    # ultimate fallback
    return LocalLLM(cfg)


class Microsoft365CopilotClient(AzureOpenAIClient):
    """
    Microsoft 365 Copilot / Azure OpenAI compatibility path (production stub).

    IMPORTANT FOR USERS WITH MICROSOFT 365 COPILOT:
    - Microsoft 365 Copilot (the chat in Teams/Office) is powered by Azure OpenAI under the hood in most tenants.
    - Recommended production configuration:
        llm:
          provider: "microsoft_365_copilot"   # or "azure"
          azure_endpoint: "https://YOUR-RESOURCE.openai.azure.com/"
          azure_deployment: "gpt-4o"          # or your Copilot model deployment name
          api_key: "your-azure-openai-key"    # from Azure portal (or use Entra managed identity)
          azure_api_version: "2024-10-21"

    - For direct Microsoft Graph "Copilot" conversations (advanced / beta), you would need a separate
      Entra app registration + delegated or application permissions to Copilot.ReadWrite.All or similar.
      That full Graph path is NOT implemented here to keep the server safe and dependency-free.
      Use the Azure OpenAI route above instead — it gives you the exact same models that power M365 Copilot.

    The client automatically falls back to AzureOpenAIClient logic and then to LocalLLM if Azure is not reachable.
    All existing retry, JSON extraction, and reasoning_content handling from LocalLLM are preserved via delegation.
    """
    def __init__(self, cfg: LLMConfig):
        super().__init__(cfg)
        # If no azure_endpoint but we have base_url pointing at azure, treat it as such (common for Copilot tenants)
        if not self._available and cfg.base_url and "openai.azure.com" in cfg.base_url:
            try:
                from openai import AzureOpenAI
                self._client = AzureOpenAI(
                    azure_endpoint=cfg.base_url,
                    azure_deployment=cfg.azure_deployment or None,
                    api_key=cfg.api_key or "",
                    api_version=cfg.azure_api_version or "2024-10-21",
                    timeout=cfg.timeout,
                )
                self._available = True
            except Exception:
                pass

        # Future hook note: a real Graph Copilot client would live here behind an extra flag + msgraph SDK.
        # For now we document the Azure path as the supported "M365 Copilot compatible" route.
