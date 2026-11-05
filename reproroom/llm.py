"""Minimal OpenAI-compatible chat client (Vultr Serverless Inference in production).

Plain httpx; the API key is only ever placed in the Authorization header and is never logged.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Protocol

import httpx

_THINK = re.compile(r"<think(?:ing)?>.*?</think(?:ing)?>", re.S | re.I)
_UNCLOSED_THINK_END = re.compile(r"^.*?</think(?:ing)?>", re.S | re.I)
_FENCE = re.compile(r"```[ \t]*([\w+-]*)[ \t]*\n(.*?)```", re.S)


class LLMError(RuntimeError):
    pass


@dataclass
class LLMReply:
    text: str
    model: str
    duration: float
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


class ChatModel(Protocol):
    model: str

    def chat(self, messages: list[dict], *, purpose: str) -> LLMReply: ...


def strip_thinking(text: str) -> str:
    text = _THINK.sub("", text)
    if re.search(r"</think(?:ing)?>", text, re.I):  # opening tag was consumed upstream
        text = _UNCLOSED_THINK_END.sub("", text, count=1)
    return text.strip()


def extract_code(text: str) -> str:
    """The Python code in a reply: the first python (or untagged) fenced block, else the text."""
    text = strip_thinking(text)
    blocks = _FENCE.findall(text)
    for lang, body in blocks:
        if lang.lower() in ("python", "py", "python3"):
            return body.strip("\n") + "\n"
    for lang, body in blocks:
        if not lang:
            return body.strip("\n") + "\n"
    if text.startswith("```"):  # unterminated fence
        text = text.split("\n", 1)[1] if "\n" in text else ""
    return text.strip("`\n") + "\n"


def extract_json(text: str) -> dict:
    """First JSON object in a reply, tolerating thinking blocks, fences and surrounding prose."""
    text = strip_thinking(text)
    for lang, body in _FENCE.findall(text):
        try:
            obj = json.loads(body)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
    decoder = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch != "{":
            continue
        try:
            obj, _ = decoder.raw_decode(text, i)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj
    raise LLMError("model reply contained no JSON object")


class OpenAICompatClient:
    def __init__(self, base_url: str, api_key: str, model: str, *, timeout: float = 120.0,
                 max_retries: int = 3, transport: httpx.BaseTransport | None = None):
        if not api_key:
            raise LLMError("LLM_API_KEY is not set")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.max_retries = max_retries
        self._redact = api_key
        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout, connect=15.0),
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            transport=transport,
        )

    def chat(self, messages: list[dict], *, purpose: str = "") -> LLMReply:
        body = {"model": self.model, "messages": messages, "temperature": 0}
        t0 = time.monotonic()
        last_error = ""
        for attempt in range(self.max_retries + 1):
            try:
                r = self._client.post(f"{self.base_url}/chat/completions", json=body)
            except httpx.HTTPError as e:
                last_error = f"{type(e).__name__}"
            else:
                if r.status_code == 200:
                    data = r.json()
                    try:
                        msg = data["choices"][0]["message"]
                        text = msg.get("content") or ""
                    except (KeyError, IndexError, TypeError) as e:
                        raise LLMError(f"unexpected response shape ({purpose})") from e
                    usage = data.get("usage") or {}
                    return LLMReply(
                        text=text,
                        model=data.get("model") or self.model,
                        duration=round(time.monotonic() - t0, 2),
                        prompt_tokens=usage.get("prompt_tokens"),
                        completion_tokens=usage.get("completion_tokens"),
                    )
                detail = " ".join(r.text.replace(self._redact, "***").split())[:240]
                last_error = f"HTTP {r.status_code}: {detail}"
                if r.status_code not in (408, 409, 429) and r.status_code < 500:
                    break
            if attempt < self.max_retries:
                time.sleep(3 * 2 ** attempt)  # 3, 6, 12 s: rides out short provider overloads
        raise LLMError(f"LLM call failed ({purpose}): {last_error}")

    def list_models(self) -> list[str]:
        r = self._client.get(f"{self.base_url}/models")
        r.raise_for_status()
        return [m.get("id", "") for m in r.json().get("data", [])]
