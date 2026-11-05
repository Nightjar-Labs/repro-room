"""Settings, read once from the environment of the control plane.

Secrets (LLM_API_KEY, GITHUB_TOKEN) live here and only here: the sandbox runner never
receives this object's secret fields and never forwards host environment to containers.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    return int(raw) if raw else default


def _float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    return float(raw) if raw else default


def _str(name: str, default: str) -> str:
    raw = os.environ.get(name, "").strip()
    return raw or default


def _secret(name: str) -> str:
    """Read NAME, or the file named by NAME_FILE (systemd credentials, secret files)."""
    value = os.environ.get(name, "").strip()
    if value:
        return value
    path = os.environ.get(f"{name}_FILE", "").strip()
    if path:
        return Path(path).read_text().strip()
    return ""


@dataclass(frozen=True)
class SandboxSettings:
    cli: str = "docker"
    oci_runtime: str = ""
    image: str = "docker.io/library/python:3.12-slim"
    run_timeout: float = 60.0
    fetch_timeout: float = 180.0
    memory: str = "512m"
    cpus: str = "1"
    pids_limit: int = 128
    work_tmpfs: str = "256m"
    tmp_tmpfs: str = "64m"
    output_cap: int = 256 * 1024
    use_init: bool = True

    @classmethod
    def from_env(cls) -> "SandboxSettings":
        return cls(
            cli=_str("SANDBOX_RUNTIME_CLI", "docker"),
            oci_runtime=os.environ.get("SANDBOX_OCI_RUNTIME", "").strip(),
            image=_str("SANDBOX_IMAGE", "docker.io/library/python:3.12-slim"),
            run_timeout=_float("SANDBOX_RUN_TIMEOUT", 60.0),
            fetch_timeout=_float("SANDBOX_FETCH_TIMEOUT", 180.0),
            memory=_str("SANDBOX_MEMORY", "512m"),
            cpus=_str("SANDBOX_CPUS", "1"),
            pids_limit=_int("SANDBOX_PIDS_LIMIT", 128),
            output_cap=_int("SANDBOX_OUTPUT_CAP", 256 * 1024),
            use_init=_str("SANDBOX_INIT", "1") not in ("0", "false", "no"),
        )


@dataclass(frozen=True)
class Settings:
    llm_base_url: str = "https://api.vultrinference.com/v1"
    llm_api_key: str = field(default="", repr=False)
    llm_model: str = "glm-5.3"
    llm_timeout: float = 120.0
    github_token: str = field(default="", repr=False)
    data_dir: Path = Path("data")
    work_root: Path = Path("data/work")
    self_url: str = "http://127.0.0.1:8000"
    max_queue: int = 5
    rate_limit_per_ip: int = 4
    rate_limit_window: int = 3600
    daily_job_cap: int = 60
    max_issue_chars: int = 20_000
    sandbox: SandboxSettings = field(default_factory=SandboxSettings)

    @classmethod
    def from_env(cls) -> "Settings":
        data_dir = Path(_str("DATA_DIR", "data")).resolve()
        work_root = Path(_str("WORK_ROOT", str(data_dir / "work"))).resolve()
        return cls(
            llm_base_url=_str("LLM_BASE_URL", "https://api.vultrinference.com/v1").rstrip("/"),
            llm_api_key=_secret("LLM_API_KEY"),
            llm_model=_str("LLM_MODEL", "glm-5.3"),
            llm_timeout=_float("LLM_TIMEOUT", 120.0),
            github_token=_secret("GITHUB_TOKEN"),
            data_dir=data_dir,
            work_root=work_root,
            self_url=_str("SELF_URL", "http://127.0.0.1:8000").rstrip("/"),
            max_queue=_int("MAX_QUEUE", 5),
            rate_limit_per_ip=_int("RATE_LIMIT_PER_IP", 4),
            rate_limit_window=_int("RATE_LIMIT_WINDOW", 3600),
            daily_job_cap=_int("DAILY_JOB_CAP", 60),
            sandbox=SandboxSettings.from_env(),
        )
