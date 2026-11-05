"""Extraction, script parsing and the LLM client with a fake model (no network)."""

import json

import httpx
import pytest

from reproroom.agent import ADDED_MARK, Agent, Facts, annotate_script, fill_comment
from reproroom.llm import LLMError, LLMReply, OpenAICompatClient, extract_code, extract_json, strip_thinking


class FakeLLM:
    model = "fake-model"

    def __init__(self, replies):
        self.replies = list(replies)
        self.seen = []

    def chat(self, messages, *, purpose=""):
        self.seen.append((purpose, messages))
        if not self.replies:
            raise LLMError("no more replies")
        return LLMReply(text=self.replies.pop(0), model=self.model, duration=0.01, prompt_tokens=10, completion_tokens=5)


TOMLKIT_FACTS = {
    "ecosystem": "python", "package": "tomlkit", "import_name": "tomlkit", "affected_version": "0.13.3",
    "claimed_behaviour": "tomlkit.boolean(True) renders 'false'", "symptom": "wrong_output",
    "expected_exception": None, "snippet": ">>> import tomlkit\n... print(tomlkit.boolean(True).as_string())\nfalse",
    "supported": True, "unsupported_reason": None,
}


def test_extract_strips_thinking_and_fences():
    reply = "<think>The user wants JSON. {not json}</think>\nHere you go:\n```json\n" + json.dumps(TOMLKIT_FACTS) + "\n```"
    agent = Agent(FakeLLM([reply]))
    facts = agent.extract("issue text", "python-poetry/tomlkit")
    assert facts.package == "tomlkit" and facts.affected_version == "0.13.3"
    assert facts.check_supported() == (True, "")
    assert [c.purpose for c in agent.calls] == ["extract facts"]


def test_extract_retries_once_on_invalid_reply():
    bad = json.dumps({**TOMLKIT_FACTS, "package": "tomlkit; rm -rf /"})
    agent = Agent(FakeLLM([bad, json.dumps(TOMLKIT_FACTS)]))
    facts = agent.extract("issue", None)
    assert facts.package == "tomlkit"
    assert len(agent.calls) == 2
    retry_messages = agent.llm.seen[1][1]
    assert "invalid" in retry_messages[-1]["content"]


def test_extract_gives_up_after_retry():
    agent = Agent(FakeLLM(["no json here", "still none"]))
    with pytest.raises(LLMError):
        agent.extract("issue", None)


@pytest.mark.parametrize("field,value", [
    ("package", "../../etc/passwd"), ("affected_version", "latest-and-greatest"),
    ("expected_exception", "ValueError; import os"), ("symptom", "explodes"),
])
def test_facts_validation_rejects_bad_values(field, value):
    with pytest.raises(ValueError):
        Facts.model_validate({**TOMLKIT_FACTS, field: value})


def test_facts_normalise_versions_and_unsupported():
    f = Facts.model_validate({**TOMLKIT_FACTS, "affected_version": "v0.13.3"})
    assert f.affected_version == "0.13.3"
    f = Facts.model_validate({**TOMLKIT_FACTS, "affected_version": "null"})
    assert f.affected_version is None
    js = Facts.model_validate({**TOMLKIT_FACTS, "ecosystem": "JavaScript", "package": "left-pad"})
    ok, why = js.check_supported()
    assert not ok and "Python" in why
    assert not Facts.model_validate({**TOMLKIT_FACTS, "snippet": ""}).check_supported()[0]


def test_write_script_extracts_python_block():
    reply = (
        "<think>plan</think>Sure!\n```python\nimport tomlkit\n"
        f"value = tomlkit.boolean(True).as_string()  {ADDED_MARK}\n"
        f"print('REPRO: BUG' if value == 'false' else 'REPRO: OK')  {ADDED_MARK}\n```\nDone."
    )
    agent = Agent(FakeLLM([reply]))
    facts = Facts.model_validate(TOMLKIT_FACTS)
    script = agent.write_script(facts, "issue")
    assert script.startswith("import tomlkit\n") and script.endswith("\n")
    assert "Sure" not in script and "<think>" not in script
    system, user = agent.llm.seen[0][1]
    assert "REPRO: BUG" in system["content"] and ADDED_MARK in system["content"]
    assert facts.snippet in user["content"]


def test_repair_prompt_carries_error():
    agent = Agent(FakeLLM(["```python\nprint('REPRO: OK')\n```"]))
    facts = Facts.model_validate(TOMLKIT_FACTS)
    out = agent.repair_script(facts, ">>> import tomlkit\n", "SyntaxError: invalid syntax", "", "SyntaxError: invalid syntax", 1)
    assert out == "print('REPRO: OK')\n"
    purpose, messages = agent.llm.seen[0]
    assert purpose == "repair repro.py (attempt 1)"
    assert "SyntaxError" in messages[-1]["content"] and ">>> import tomlkit" in messages[-1]["content"]


def test_explain_fills_placeholders_with_real_script_and_runs():
    reply = json.dumps({"explanation": "It was fixed.", "draft_comment": "Checked.\n\n{{RESULTS}}\n\n{{SCRIPT}}"})
    agent = Agent(FakeLLM([reply]))
    runs = [{"version": "0.13.3", "role": "affected", "exit_code": 0, "timed_out": False, "duration": 1.2,
             "classification": {"kind": "bug", "reason": "script printed REPRO: BUG"}}]
    explanation, comment = agent.explain(Facts.model_validate(TOMLKIT_FACTS), {"code": "already_fixed"}, runs, "print(1)\n")
    assert explanation == "It was fixed."
    assert "| 0.13.3 (affected) | bug: script printed REPRO: BUG | 0 | 1.2 s |" in comment
    assert "```python\nprint(1)\n```" in comment
    assert "{{" not in comment


def test_fill_comment_appends_when_placeholders_missing():
    out = fill_comment("Hello", "x = 1\n", [])
    assert "| Version |" in out and "x = 1" in out


def test_fill_comment_unwraps_fenced_placeholders():
    out = fill_comment("Runs:\n```\n{{RESULTS}}\n```\nScript:\n```python\n{{SCRIPT}}\n```\nThanks", "x = 1\n", [])
    assert out.count("```python") == 1
    assert "```\n| Version |" not in out
    assert out.endswith("</details>\nThanks")


def test_annotate_script_marks_added_original_and_unmarked():
    snippet = ">>> import tomlkit\n... t = tomlkit.boolean(True)\nprint(t)  # shows false\nfalse"
    script = (
        f"import tomlkit  {ADDED_MARK}\n"                 # prompt stripped and marked
        "t = tomlkit.boolean(True)\n"                      # prompt stripped WITHOUT the marker
        "print(t)  # shows false\n"                        # verbatim
        f"print(t)  # shows false  {ADDED_MARK}\n"        # verbatim, but the model marked it anyway
        "print(t.as_string())\n"                           # new, unmarked
        "\n# comment\n"
    )
    kinds = [l["kind"] for l in annotate_script(script, snippet)]
    assert kinds == ["added", "unmarked", "original", "original", "unmarked", "neutral", "neutral"]


@pytest.mark.parametrize("text,expected", [
    ('{"a": 1}', {"a": 1}),
    ('<think>{"wrong": true</think>{"a": 2}', {"a": 2}),
    ('reasoning…</think>\n{"a": 3}', {"a": 3}),
    ('Sure: ```json\n{"a": 4}\n``` hope it helps', {"a": 4}),
    ('prefix {"a": {"b": [1, 2]}} suffix {"c": 1}', {"a": {"b": [1, 2]}}),
])
def test_extract_json_variants(text, expected):
    assert extract_json(text) == expected


def test_extract_code_variants():
    assert extract_code("```py\nx = 1\n```") == "x = 1\n"
    assert extract_code("```\ny = 2\n```") == "y = 2\n"
    assert extract_code("```python\nz = 3\n") == "z = 3\n"  # unterminated fence
    assert extract_code("w = 4") == "w = 4\n"
    assert strip_thinking("<thinking>a</thinking>b") == "b"


def test_openai_client_sends_bearer_and_parses_reply():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers["authorization"]
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"model": "glm-5.3", "choices": [{"message": {"content": "hi"}}],
                                         "usage": {"prompt_tokens": 3, "completion_tokens": 1}})

    c = OpenAICompatClient("https://api.example.test/v1/", "sk-secret", "glm-5.3", transport=httpx.MockTransport(handler))
    r = c.chat([{"role": "user", "content": "x"}], purpose="t")
    assert r.text == "hi" and r.prompt_tokens == 3
    assert seen["auth"] == "Bearer sk-secret"
    assert seen["url"] == "https://api.example.test/v1/chat/completions"
    assert seen["body"]["model"] == "glm-5.3"


def test_openai_client_errors_never_contain_the_key(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    handler = lambda req: httpx.Response(401, text="bad key sk-secret-value")  # noqa: E731
    c = OpenAICompatClient("https://api.example.test/v1", "sk-secret-value", "m", transport=httpx.MockTransport(handler))
    with pytest.raises(LLMError) as e:
        c.chat([], purpose="t")
    assert "sk-secret-value" not in str(e.value)
    assert "401" in str(e.value)


def test_openai_client_retries_overload_then_succeeds(monkeypatch):
    sleeps = []
    monkeypatch.setattr("time.sleep", sleeps.append)
    replies = iter([httpx.Response(503, json={"error": {"message": "high demand"}}), httpx.Response(429, text="slow down"),
                    httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})])
    c = OpenAICompatClient("https://x/v1", "k" * 20, "m", transport=httpx.MockTransport(lambda req: next(replies)))
    assert c.chat([], purpose="t").text == "ok"
    assert sleeps == [3, 6]


def test_openai_client_requires_key():
    with pytest.raises(LLMError):
        OpenAICompatClient("https://x", "", "m")
