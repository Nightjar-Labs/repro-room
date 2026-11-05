import os
import secrets
import shutil

import pytest

from reproroom.config import SandboxSettings
from reproroom.sandbox import SandboxRunner

# Fake control-plane secrets present for the whole test session; they must never reach a sandbox.
CANARY = "rr-test-canary-" + secrets.token_hex(12)
os.environ["REPRO_ROOM_CANARY_SECRET"] = CANARY
FAKE_LLM_KEY = "sk-test-not-a-real-key-" + secrets.token_hex(8)
if not os.environ.get("LLM_API_KEY") and not os.environ.get("LLM_API_KEY_FILE"):
    os.environ["LLM_API_KEY"] = FAKE_LLM_KEY  # live runs may use LLM_API_KEY_FILE instead; don't shadow it


def _detect_cli() -> str | None:
    configured = os.environ.get("SANDBOX_RUNTIME_CLI")
    if configured:
        return configured
    for cli in ("podman", "docker"):
        if shutil.which(cli):
            return cli
    return None


@pytest.fixture(scope="session")
def sandbox_settings() -> SandboxSettings:
    cli = _detect_cli()
    if cli is None:
        pytest.skip("no container runtime (podman/docker) available")
    base = SandboxSettings.from_env()
    return SandboxSettings(**{**base.__dict__, "cli": cli})


@pytest.fixture(scope="session")
def runner(sandbox_settings, tmp_path_factory) -> SandboxRunner:
    r = SandboxRunner(sandbox_settings, tmp_path_factory.mktemp("work"))
    if not r.available():
        pytest.skip(f"{sandbox_settings.cli} is installed but not usable")
    r.ensure_image()
    return r


@pytest.fixture
def run_script(runner):
    """Run a script in the run phase (no package) and return the StepResult."""
    counter = {"n": 0}

    def _run(code: str, job_id: str = "test", timeout: float | None = None):
        counter["n"] += 1
        path = runner.write_script(job_id, counter["n"], code)
        return runner.run(job_id, path, timeout=timeout, label=f"t{counter['n']}")

    yield _run
    runner.cleanup_job("test")
