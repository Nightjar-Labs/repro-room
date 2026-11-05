"""The whole job pipeline with a fake LLM, fake GitHub/PyPI and the REAL sandbox.

The sandbox downloads real wheels from PyPI in its fetch phase (network required).
"""

import json
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from reproroom import drill
from reproroom.agent import ADDED_MARK, Agent
from reproroom.config import Settings
from reproroom.pipeline import Pipeline, new_state
from reproroom.sources import GitHubReader, PyPI
from reproroom.store import Store

from .conftest import CANARY
from .test_agent import TOMLKIT_FACTS, FakeLLM

pytestmark = pytest.mark.sandbox

ISSUE_URL = "https://github.com/python-poetry/tomlkit/issues/442"
ISSUE = {"title": "boolean(True) renders false", "state": "open", "comments": 0,
         "body": "```\n>>> import tomlkit\n... print(tomlkit.boolean(True).as_string())\nfalse\n```\ntomlkit 0.13.3"}


def github_mock() -> GitHubReader:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/repos/python-poetry/tomlkit/issues/442":
            return httpx.Response(200, json=ISSUE)
        return httpx.Response(404, json={})
    return GitHubReader("", transport=httpx.MockTransport(handler))


def pypi_mock() -> PyPI:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/pypi/tomlkit/json":
            files = [{"yanked": False}]
            return httpx.Response(200, json={"info": {"name": "tomlkit", "version": "0.15.2"},
                                             "releases": {"0.13.2": files, "0.13.3": files, "0.15.2": files}})
        return httpx.Response(404, json={})
    return PyPI(transport=httpx.MockTransport(handler))


BROKEN_SCRIPT = "```python\n>>> import tomlkit\n... value = tomlkit.boolean(True).as_string()\n```"
FIXED_SCRIPT = (
    "```python\n"
    f"import tomlkit  {ADDED_MARK}\n"
    f"value = tomlkit.boolean(True).as_string()  {ADDED_MARK}\n"
    f"print('True renders as', value)  {ADDED_MARK}\n"
    f"print('REPRO: BUG' if value == 'false' else 'REPRO: OK')  {ADDED_MARK}\n"
    "```"
)
EXPLAIN = json.dumps({"explanation": "Reproduced at 0.13.3; fixed in 0.15.2.",
                      "draft_comment": "Checked with Repro Room.\n\n{{RESULTS}}\n\n{{SCRIPT}}"})


@pytest.fixture
def health_url():
    """A stand-in control plane answering /healthz, so the drill's probe has something to check."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200 if self.path == "/healthz" else 404)
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture
def make_pipeline(runner, tmp_path, health_url):
    def make(replies):
        settings = replace(Settings(), data_dir=tmp_path, work_root=runner.work_root, sandbox=runner.s,
                           self_url=health_url)
        store = Store(tmp_path / "jobs.db")
        llm = FakeLLM(replies)
        probe = drill.HostProbe(tmp_path, settings.self_url, lambda: len(runner.containers_for(None)),
                                secrets_held=("file-loaded-secret-value",))
        return Pipeline(settings, store, runner, lambda: Agent(llm), github_mock(), pypi_mock(), probe), store
    return make


def test_issue_pipeline_with_repair_and_already_fixed_verdict(make_pipeline, runner):
    pipeline, store = make_pipeline([json.dumps(TOMLKIT_FACTS), BROKEN_SCRIPT, FIXED_SCRIPT, EXPLAIN])
    store.create("job1", "127.0.0.1", "issue", new_state("job1", "issue", ISSUE_URL))
    pipeline.process("job1")
    st = store.get("job1")

    assert st["status"] == "done", st["error"]
    assert st["verdict"]["code"] == "already_fixed"
    assert st["verdict"]["label"] == "Already fixed in v0.15.2"
    # attempt 1 hit a SyntaxError at the affected version, so the script was repaired once
    assert len(st["scripts"]) == 2 and st["scripts"][1]["reason"].startswith("repair 1")
    runs = [r for r in st["runs"] if r["phase"] == "run"]
    assert [(r["version"], r["attempt"], r["classification"]["kind"]) for r in runs] == [
        ("0.13.3", 0, "script_error"), ("0.13.3", 1, "bug"), ("0.15.2", 1, "ok")]
    assert all(r["removed"] for r in st["runs"])
    assert [c["purpose"] for c in st["llm_calls"]] == [
        "extract facts", "write repro.py", "repair repro.py (attempt 1)", "explain verdict"]
    assert "```python" in st["draft_comment"] and "0.15.2 (latest)" in st["draft_comment"]
    assert st["cleanup"]["dir_removed"] and runner.containers_for("job1") == []
    assert CANARY not in json.dumps(st)


def test_unsupported_issue_stops_before_the_sandbox(make_pipeline):
    facts = {**TOMLKIT_FACTS, "ecosystem": "javascript", "package": "left-pad", "supported": False,
             "unsupported_reason": "npm package"}
    pipeline, store = make_pipeline([json.dumps(facts)])
    store.create("job2", "127.0.0.1", "issue", new_state("job2", "issue", ISSUE_URL))
    pipeline.process("job2")
    st = store.get("job2")
    assert st["verdict"]["code"] == "inconclusive" and "not supported" in st["verdict"]["reason"]
    assert st["runs"] == []


def test_llm_failure_fails_the_job_cleanly(make_pipeline):
    pipeline, store = make_pipeline([])
    store.create("job3", "127.0.0.1", "issue", new_state("job3", "issue", ISSUE_URL))
    pipeline.process("job3")
    st = store.get("job3")
    assert st["status"] == "failed" and "no more replies" in st["error"]
    assert st["verdict"]["code"] == "inconclusive"
    assert all(ev["status"] != "running" for ev in st["events"])


def test_drill_pipeline_reports_containment(make_pipeline, runner, tmp_path):
    pipeline, store = make_pipeline([])
    store.create("drill1", "127.0.0.1", "drill", new_state("drill1", "drill", "containment drill"))
    pipeline.process("drill1")
    st = store.get("drill1")
    d = st["drill"]
    assert all(a["contained"] for a in d["attacks"]) and len(d["attacks"]) >= 10
    checks = {c["check"]: c["ok"] for c in d["checks"]}
    assert checks["Host canary file untouched"]
    assert checks["No control-plane secret in sandbox output"]
    assert checks["Sandbox ended and was destroyed"] and checks["No leftover sandbox containers"]
    assert checks["Control plane still responds"]
    assert st["verdict"]["code"] == "contained", st["verdict"]
    assert d["before"]["canary"]["sha256"] == d["after"]["canary"]["sha256"]
    assert (tmp_path / "host-canary.txt").exists()


def test_drill_reports_breach_when_a_host_check_fails(make_pipeline, tmp_path):
    pipeline, store = make_pipeline([])
    pipeline.probe.self_url = "http://127.0.0.1:9"  # nothing listens: the control-plane check must fail
    store.create("drill2", "127.0.0.1", "drill", new_state("drill2", "drill", "containment drill"))
    pipeline.process("drill2")
    st = store.get("drill2")
    assert st["verdict"]["code"] == "breach" and "Control plane still responds" in st["verdict"]["reason"]
