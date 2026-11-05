"""Web app: pages, validation, abuse limits, /healthz, rendering of a complete job."""

import os
import time
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from reproroom.app import create_app, flag_pairs
from reproroom.config import SandboxSettings, Settings
from reproroom.pipeline import new_state
from reproroom.sandbox import SandboxRunner

from .conftest import FAKE_LLM_KEY

URL = "https://github.com/python-poetry/tomlkit/issues/442"


class NoRuntime(SandboxRunner):
    def available(self):
        return False

    def containers_for(self, job_id=None):
        return []


@pytest.fixture
def make_client(tmp_path):
    def make(**overrides):
        settings = replace(Settings(), data_dir=tmp_path, work_root=tmp_path / "work",
                           llm_api_key=FAKE_LLM_KEY, **overrides)
        app = create_app(settings, runner=NoRuntime(SandboxSettings(cli="false"), tmp_path / "work"),
                         start_worker=False)
        return TestClient(app), app
    return make


def test_home_renders_with_examples_and_drill(make_client):
    client, _ = make_client()
    r = client.get("/")
    assert r.status_code == 200
    assert "Repro Room" in r.text and "Nightjar Labs" in r.text
    assert "tomlkit#442" in r.text and "Run containment drill" in r.text
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"


@pytest.mark.parametrize("url", [
    "https://gitlab.com/a/b/issues/1", "https://github.com/a/b/pull/1", "http://github.com/a/b/issues/1",
    "https://github.com.evil.com/a/b/issues/1", "https://github.com/a/b/issues/abc", "javascript:alert(1)",
])
def test_only_github_issue_urls_are_accepted(make_client, url):
    client, app = make_client()
    r = client.post("/jobs", data={"url": url}, follow_redirects=False)
    assert r.status_code == 400
    assert "Only public GitHub issue URLs" in r.text
    assert app.state.store.count_active() == 0


def test_valid_url_creates_a_queued_job(make_client):
    client, app = make_client()
    r = client.post("/jobs", data={"url": URL}, follow_redirects=False)
    assert r.status_code == 303
    job_id = r.headers["location"].rsplit("/", 1)[1]
    page = client.get(f"/jobs/{job_id}")
    assert page.status_code == 200 and "Queued" in page.text
    assert client.get(f"/api/jobs/{job_id}/rev").json()["status"] == "queued"
    assert client.get(f"/jobs/{job_id}/fragment").status_code == 200


def test_pasted_text_is_length_limited(make_client):
    client, _ = make_client(max_issue_chars=100)
    assert client.post("/jobs", data={"text": "x" * 101}, follow_redirects=False).status_code == 400
    assert client.post("/jobs", data={"text": "x" * 50}, follow_redirects=False).status_code == 303
    assert client.post("/jobs", data={}, follow_redirects=False).status_code == 400


def test_per_ip_rate_limit(make_client):
    client, _ = make_client(rate_limit_per_ip=2, max_queue=10)
    for _ in range(2):
        assert client.post("/jobs", data={"url": URL}, follow_redirects=False).status_code == 303
    r = client.post("/jobs", data={"url": URL}, follow_redirects=False)
    assert r.status_code == 429 and "Rate limit" in r.text
    assert client.post("/drill", follow_redirects=False).status_code == 429


def test_queue_length_limit(make_client):
    client, _ = make_client(max_queue=1, rate_limit_per_ip=10)
    assert client.post("/jobs", data={"url": URL}, follow_redirects=False).status_code == 303
    r = client.post("/jobs", data={"url": URL}, follow_redirects=False)
    assert r.status_code == 503 and "queue is full" in r.text


def test_daily_cap(make_client):
    client, app = make_client(daily_job_cap=1, rate_limit_per_ip=10, max_queue=10)
    assert client.post("/drill", follow_redirects=False).status_code == 303
    r = client.post("/jobs", data={"url": URL}, follow_redirects=False)
    assert r.status_code == 429 and "daily cap" in r.text


def test_healthz_never_exposes_secrets(make_client):
    client, _ = make_client()
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["llm"]["configured"] is True
    assert body["sandbox"]["runtime_ok"] is False and body["status"] == "degraded"
    assert FAKE_LLM_KEY not in r.text
    assert os.environ["REPRO_ROOM_CANARY_SECRET"] not in r.text


def test_full_job_page_renders_every_section(make_client):
    client, app = make_client()
    st = new_state("abc123", "issue", URL)
    now = time.time()
    st.update(
        status="done", started_at=now - 30, finished_at=now,
        issue={"url": URL, "repo": "python-poetry/tomlkit", "number": 442, "title": "boolean <True> renders false", "state": "open"},
        facts={"package": "tomlkit", "import_name": "tomlkit", "affected_version": "0.13.3", "symptom": "wrong_output",
               "expected_exception": None, "claimed_behaviour": "renders false", "snippet": ">>> import tomlkit"},
        versions={"package": "tomlkit", "stated": "0.13.3", "affected": "0.13.3", "latest": "0.15.2"},
        events=[{"title": "Read the issue", "kind": "issue", "status": "done", "started": now - 30, "ended": now - 29, "detail": "ok", "ref": None},
                {"title": "Run repro.py", "kind": "run", "status": "bug", "started": now - 20, "ended": now - 18, "detail": "bug", "ref": 0}],
        scripts=[{"code": "import tomlkit", "reason": "written", "added": 1, "unmarked": 1,
                  "lines": [{"text": "import tomlkit  # added by Repro Room", "kind": "added"}, {"text": "print(1)", "kind": "unmarked"}]}],
        runs=[{"phase": "run", "label": "affected-0", "version": "0.13.3", "attempt": 0, "role": "affected",
               "exit_code": 0, "timed_out": False, "duration": 1.9, "removed": True, "truncated": False,
               "installed_version": "0.13.3", "stdout": "REPRO: BUG\n", "stderr": "<script>alert(1)</script>",
               "flags": ["--read-only", "--memory", "512m", "--label", "reproroom=1"], "command": ["podman", "run"],
               "image_digest": "docker.io/library/python@sha256:" + "a" * 64,
               "classification": {"kind": "bug", "reason": "script printed REPRO: BUG"}}],
        verdict={"code": "already_fixed", "label": "Already fixed in v0.15.2", "reason": "bug at 0.13.3, not at 0.15.2"},
        explanation="It reproduced.", draft_comment="Checked with Repro Room.",
        llm_calls=[{"purpose": "extract facts", "model": "glm-5.3", "duration": 1.0, "ok": True, "prompt_tokens": 10, "completion_tokens": 5, "error": None}],
        drill={"attacks": [{"attack": "Fork bomb", "goal": "fork", "observed": "refused", "contained": True}],
               "checks": [{"check": "Host canary file untouched", "ok": True, "detail": "same"}],
               "before": {"canary": {"sha256": "abc", "exists": True}, "app": {"status": 200, "ms": 3}, "sandbox_containers": 0, "load1": 0.1, "mem_available_mb": 1000},
               "after": {"canary": {"sha256": "abc", "exists": True}, "app": {"status": 200, "ms": 3}, "sandbox_containers": 0, "load1": 0.1, "mem_available_mb": 1000}},
    )
    app.state.store.create("abc123", "1.2.3.4", "issue", st)
    r = client.get("/jobs/abc123")
    assert r.status_code == 200
    for text in ("Already fixed in v0.15.2", "Timeline", "Extracted facts", "repro.py", "Sandbox runs",
                 "Draft maintainer comment", "Copy comment", "Attacker", "Host", "LLM calls", "--memory 512m"):
        assert text in r.text, text
    assert "<script>alert(1)</script>" not in r.text  # untrusted output is escaped
    assert "&lt;True&gt;" in r.text
    assert "reproroom=1" not in r.text  # labels are hidden from the flag chips
    assert "1.2.3.4" not in client.get("/api/jobs/abc123").text  # submitter IP is never published


def test_flag_pairs():
    assert flag_pairs(["--read-only", "--memory", "512m", "--label", "x=1", "--init", "--env", "HOME=/work"]) == [
        "--read-only", "--memory 512m", "--init", "--env HOME=/work"]
