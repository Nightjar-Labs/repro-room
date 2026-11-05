"""Live end-to-end: real GitHub, PyPI, LLM endpoint and sandbox. Deselected by default.

    LLM_BASE_URL=... LLM_API_KEY=... LLM_MODEL=... uv run pytest -m live
"""

import os
from dataclasses import replace

import pytest

from reproroom import drill
from reproroom.agent import Agent
from reproroom.config import Settings
from reproroom.llm import OpenAICompatClient
from reproroom.pipeline import Pipeline, new_state
from reproroom.sources import GitHubReader, PyPI
from reproroom.store import Store

pytestmark = [pytest.mark.live, pytest.mark.sandbox]


@pytest.mark.skipif(not os.environ.get("LLM_BASE_URL"), reason="LLM_BASE_URL not set")
def test_tomlkit_442_end_to_end(runner, tmp_path):
    env = Settings.from_env()
    settings = replace(env, data_dir=tmp_path, work_root=runner.work_root, sandbox=runner.s)
    llm = OpenAICompatClient(settings.llm_base_url, settings.llm_api_key, settings.llm_model)
    store = Store(tmp_path / "jobs.db")
    probe = drill.HostProbe(tmp_path, settings.self_url, lambda: 0)
    pipeline = Pipeline(settings, store, runner, lambda: Agent(llm), GitHubReader(settings.github_token), PyPI(), probe)
    url = "https://github.com/python-poetry/tomlkit/issues/442"
    store.create("live1", "127.0.0.1", "issue", new_state("live1", "issue", url))
    pipeline.process("live1")
    st = store.get("live1")
    assert st["status"] == "done", st["error"]
    assert st["verdict"]["code"] == "already_fixed", st["verdict"]
    assert st["draft_comment"], [e for e in st["events"] if e["status"] == "failed"]
