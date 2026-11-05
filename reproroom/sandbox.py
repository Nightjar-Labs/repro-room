"""Disposable container sandbox for untrusted reproduction scripts.

Every step is one fresh `--rm` container, labelled `reproroom.job=<id>`:

* fetch: network on, but no untrusted code runs. `pip download --only-binary=:all:` only
  saves wheels (no sdist, so no `setup.py` execution) into a per-job host directory.
* run:   network off, read-only root fs, tmpfs work dir, unprivileged user, all caps dropped,
  memory/cpu/pids limits, wheels and script mounted read-only, wall clock enforced host-side.

The runner never forwards host environment variables: containers get an explicit minimal
environment, and the container CLI itself is started with an allowlisted environment so a
`-e NAME` (value from host) or proxy passthrough cannot leak control-plane secrets.
"""

from __future__ import annotations

import logging
import os
import re
import secrets
import shutil
import subprocess
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .config import SandboxSettings

log = logging.getLogger(__name__)

SETUP_FAILED_EXIT = 97
TIMEOUT_EXIT = 124
SENTINEL = "::reproroom::"
SANDBOX_USER = "65534:65534"

# Host env the container CLI itself needs to reach its daemon / rootless storage. Nothing else.
_CLI_ENV_ALLOW = (
    "PATH", "HOME", "USER", "LOGNAME", "LANG", "TMPDIR",
    "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "DBUS_SESSION_BUS_ADDRESS",
    "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY",
    "CONTAINER_HOST", "CONTAINERS_CONF", "CONTAINERS_STORAGE_CONF", "CONTAINERS_REGISTRIES_CONF",
)

# Environment for the sandbox's setup steps (plus the image's own ENV such as PATH).
RUN_ENV = {
    "HOME": "/work",
    "LANG": "C.UTF-8",
    "PYTHONUNBUFFERED": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PIP_NO_CACHE_DIR": "1",
    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    "PIP_NO_INPUT": "1",
}
FETCH_ENV = {**RUN_ENV, "HOME": "/tmp"}
# The repro script is exec'd under `env -i` with exactly this environment (image ENV dropped).
SCRIPT_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/work",
    "LANG": "C.UTF-8",
    "PYTHONUNBUFFERED": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
}

_REQUIREMENT = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?==[A-Za-z0-9][A-Za-z0-9.+!_-]*$")
_DIST = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_SAFE_NAME = re.compile(r"[^a-zA-Z0-9_.-]+")

_FETCH_SH = 'umask 0000 && exec python -m pip download --progress-bar off --only-binary=:all: --dest /wheels "$1"'

# $1 = requirement ("" = no package), $2 = distribution name. Setup output only surfaces on failure.
_RUN_SH = f"""
set -u
PY=python
if [ -n "$1" ]; then
  if ! {{ python -m venv --without-pip /work/venv && python -m pip --python /work/venv/bin/python install --no-index --find-links /wheels "$1"; }} >/tmp/setup.log 2>&1; then
    echo "{SENTINEL} setup failed" >&2
    tail -n 40 /tmp/setup.log >&2
    exit {SETUP_FAILED_EXIT}
  fi
  PY=/work/venv/bin/python
  echo "{SENTINEL} installed $2 $($PY -c 'import importlib.metadata as m, sys; print(m.version(sys.argv[1]))' "$2")"
fi
echo "{SENTINEL} start"
exec env -i {" ".join(f"{k}={v}" for k, v in SCRIPT_ENV.items())} "$PY" /repro/repro.py
"""


@dataclass
class StepResult:
    phase: str
    label: str
    container: str
    command: list[str]
    flags: list[str]
    image: str
    image_digest: str
    exit_code: int
    timed_out: bool
    duration: float
    stdout: str
    stderr: str
    truncated: bool
    removed: bool
    started_at: float = field(default_factory=time.time)

    @property
    def setup_failed(self) -> bool:
        return self.phase == "run" and self.exit_code == SETUP_FAILED_EXIT and f"{SENTINEL} setup failed" in self.stderr

    @property
    def script_started(self) -> bool:
        return f"{SENTINEL} start" in self.stdout

    @property
    def installed_version(self) -> str | None:
        m = re.search(rf"^{re.escape(SENTINEL)} installed \S+ (\S+)$", self.stdout, re.M)
        return m.group(1) if m else None

    @property
    def script_stdout(self) -> str:
        """stdout of the repro script itself (setup sentinels removed)."""
        return "\n".join(l for l in self.stdout.splitlines() if not l.startswith(SENTINEL))

    def to_dict(self) -> dict:
        d = asdict(self)
        d["setup_failed"] = self.setup_failed
        d["script_started"] = self.script_started
        d["installed_version"] = self.installed_version
        return d


class _Capture:
    """Reads both pipes concurrently under one shared byte budget; keeps draining past the cap."""

    def __init__(self, limit: int):
        self.remaining = limit
        self.truncated = False
        self.data = {"stdout": bytearray(), "stderr": bytearray()}
        self._lock = threading.Lock()

    def pump(self, fd: int, key: str) -> None:
        while True:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            with self._lock:
                take = min(len(chunk), self.remaining)
                if take:
                    self.data[key] += chunk[:take]
                    self.remaining -= take
                if take < len(chunk):
                    self.truncated = True

    def text(self, key: str) -> str:
        return self.data[key].decode("utf-8", errors="replace")


def cli_env() -> dict[str, str]:
    return {k: os.environ[k] for k in _CLI_ENV_ALLOW if k in os.environ}


class SandboxError(RuntimeError):
    pass


class SandboxRunner:
    def __init__(self, settings: SandboxSettings, work_root: Path):
        self.s = settings
        self.work_root = Path(work_root)
        self._digest: str | None = None
        self._is_podman: bool | None = None

    # ---- container CLI helpers -------------------------------------------------------------
    def _cli(self, args: list[str], timeout: float = 60) -> subprocess.CompletedProcess:
        return subprocess.run(
            [self.s.cli, *args], stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=timeout, env=cli_env(),
        )

    @property
    def is_podman(self) -> bool:
        if self._is_podman is None:
            try:
                out = self._cli(["--version"], timeout=20).stdout.lower()
            except (OSError, subprocess.TimeoutExpired):
                out = ""
            self._is_podman = "podman" in out or Path(self.s.cli).name == "podman"
        return self._is_podman

    def available(self) -> bool:
        try:
            return self._cli(["version"], timeout=20).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def ensure_image(self) -> str:
        """Pull the sandbox image once if missing; return its repo digest."""
        r = self._cli(["image", "inspect", "--format", "{{json .RepoDigests}}", self.s.image], timeout=60)
        if r.returncode != 0:
            log.info("pulling sandbox image %s", self.s.image)
            p = self._cli(["pull", self.s.image], timeout=900)
            if p.returncode != 0:
                raise SandboxError(f"cannot pull {self.s.image}: {p.stderr.strip()[-500:]}")
            r = self._cli(["image", "inspect", "--format", "{{json .RepoDigests}}", self.s.image], timeout=60)
        digests = re.findall(r"[^\"\[\],]+@sha256:[0-9a-f]{64}", r.stdout)
        self._digest = digests[0] if digests else "unknown"
        return self._digest

    @property
    def image_digest(self) -> str:
        if self._digest is None:
            try:
                self.ensure_image()
            except (SandboxError, OSError, subprocess.TimeoutExpired):
                self._digest = "unknown"
        return self._digest or "unknown"

    def container_exists(self, name: str) -> bool:
        r = self._cli(["container", "inspect", "--format", "{{.Id}}", name], timeout=30)
        return r.returncode == 0 and bool(r.stdout.strip())

    def containers_for(self, job_id: str | None = None) -> list[str]:
        label = f"reproroom.job={job_id}" if job_id else "reproroom=1"
        r = self._cli(["ps", "-a", "-q", "--filter", f"label={label}"], timeout=30)
        return r.stdout.split() if r.returncode == 0 else []

    # ---- host-side directories ---------------------------------------------------------------
    def job_dir(self, job_id: str) -> Path:
        d = self.work_root / _SAFE_NAME.sub("-", job_id)
        d.mkdir(parents=True, exist_ok=True)
        d.chmod(0o755)
        return d

    def wheels_dir(self, job_id: str, version: str) -> Path:
        d = self.job_dir(job_id) / f"wheels-{_SAFE_NAME.sub('-', version)}"
        d.mkdir(exist_ok=True)
        d.chmod(0o777)  # the unprivileged sandbox user writes wheels here during fetch only
        return d

    def write_script(self, job_id: str, attempt: int, code: str) -> Path:
        d = self.job_dir(job_id) / f"script-{attempt}"
        d.mkdir(exist_ok=True)
        d.chmod(0o755)
        p = d / "repro.py"
        p.write_text(code)
        p.chmod(0o644)
        return p

    # ---- the two phases --------------------------------------------------------------------
    def _flags(self, job_id: str, phase: str) -> list[str]:
        s = self.s
        flags = [
            "--pull=never",
            "--read-only",
            "--user", SANDBOX_USER,
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--memory", s.memory,
            "--memory-swap", s.memory,
            "--cpus", s.cpus,
            "--pids-limit", str(s.pids_limit),
            "--tmpfs", f"/tmp:rw,nosuid,nodev,size={s.tmp_tmpfs}",
            "--label", "reproroom=1",
            "--label", f"reproroom.job={job_id}",
            "--label", f"reproroom.phase={phase}",
        ]
        if s.use_init:
            flags.append("--init")
        if s.oci_runtime:
            flags += ["--runtime", s.oci_runtime]
        if self.is_podman:
            flags.append("--http-proxy=false")  # podman forwards host proxy vars by default
        return flags

    def _name(self, job_id: str, phase: str, label: str) -> str:
        base = _SAFE_NAME.sub("-", f"reproroom-{job_id}-{phase}-{label}")[:90]
        return f"{base}-{secrets.token_hex(3)}"

    def fetch(self, job_id: str, requirement: str, wheels_dir: Path, label: str = "") -> StepResult:
        if not _REQUIREMENT.match(requirement):
            raise ValueError(f"refusing unpinned or malformed requirement: {requirement!r}")
        flags = self._flags(job_id, "fetch")
        for k, v in FETCH_ENV.items():
            flags += ["--env", f"{k}={v}"]
        flags += ["--workdir", "/tmp", "--volume", f"{wheels_dir}:/wheels:rw"]
        argv = ["sh", "-c", _FETCH_SH, "sh", requirement]
        return self._execute(job_id, "fetch", label or requirement, flags, argv, self.s.fetch_timeout)

    def run(
        self,
        job_id: str,
        script: Path,
        *,
        wheels_dir: Path | None = None,
        requirement: str | None = None,
        label: str = "",
        timeout: float | None = None,
    ) -> StepResult:
        flags = self._flags(job_id, "run")
        flags += [
            "--network", "none",
            "--tmpfs", f"/work:rw,exec,nosuid,nodev,size={self.s.work_tmpfs}",
            "--workdir", "/work",
        ]
        for k, v in RUN_ENV.items():
            flags += ["--env", f"{k}={v}"]
        dist = ""
        if requirement:
            if not _REQUIREMENT.match(requirement) or wheels_dir is None:
                raise ValueError(f"refusing malformed requirement: {requirement!r}")
            dist = requirement.split("==", 1)[0]
            if not _DIST.match(dist):
                raise ValueError(f"bad distribution name {dist!r}")
            flags += ["--volume", f"{wheels_dir}:/wheels:ro"]
        flags += ["--volume", f"{script.parent}:/repro:ro"]
        argv = ["sh", "-c", _RUN_SH, "sh", requirement or "", dist]
        return self._execute(job_id, "run", label or "run", flags, argv, timeout or self.s.run_timeout)

    def _sanitise(self, items: list[str]) -> list[str]:
        root = str(self.work_root)
        return [i.replace(root, "$WORK_ROOT") for i in items]

    def _execute(self, job_id: str, phase: str, label: str, flags: list[str], argv: list[str], timeout: float) -> StepResult:
        name = self._name(job_id, phase, label)
        cmd = [self.s.cli, "run", "--rm", "--name", name, *flags, self.s.image, *argv]
        digest = self.image_digest
        started_at = time.time()
        t0 = time.monotonic()
        proc = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=cli_env(), start_new_session=True,
        )
        cap = _Capture(self.s.output_cap)
        readers = [
            threading.Thread(target=cap.pump, args=(proc.stdout.fileno(), "stdout"), daemon=True),
            threading.Thread(target=cap.pump, args=(proc.stderr.fileno(), "stderr"), daemon=True),
        ]
        for t in readers:
            t.start()
        timed_out = False
        try:
            exit_code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._destroy(name)
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            exit_code = TIMEOUT_EXIT
        duration = time.monotonic() - t0
        for t in readers:
            t.join(timeout=10)
        proc.stdout.close()
        proc.stderr.close()
        # `--rm` already removes the container; make sure, then verify it is gone.
        self._destroy(name)
        removed = not self.container_exists(name)
        if not removed:
            log.error("container %s still present after step", name)
        return StepResult(
            phase=phase,
            label=label,
            container=name,
            command=self._sanitise([self.s.cli, "run", "--rm", "--name", name, *flags, self.s.image, *argv]),
            flags=self._sanitise(flags),
            image=self.s.image,
            image_digest=digest,
            exit_code=exit_code,
            timed_out=timed_out,
            duration=round(duration, 2),
            stdout=cap.text("stdout"),
            stderr=cap.text("stderr"),
            truncated=cap.truncated,
            removed=removed,
            started_at=started_at,
        )

    def _destroy(self, name: str) -> None:
        for args in (["kill", name], ["rm", "-f", name]):
            try:
                self._cli(args, timeout=60)
            except subprocess.TimeoutExpired:
                log.error("timeout running %s %s", self.s.cli, args[0])

    # ---- lifecycle -------------------------------------------------------------------------
    def cleanup_job(self, job_id: str) -> dict:
        ids = self.containers_for(job_id)
        if ids:
            self._cli(["rm", "-f", *ids], timeout=120)
        d = self.work_root / _SAFE_NAME.sub("-", job_id)
        removed_dir = False
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)
            removed_dir = not d.exists()
        return {"containers_removed": len(ids), "dir_removed": removed_dir}

    def janitor(self) -> dict:
        """Startup sweep: remove every container we labelled and every leftover job dir."""
        ids = self.containers_for(None)
        if ids:
            self._cli(["rm", "-f", *ids], timeout=300)
        dirs = 0
        if self.work_root.exists():
            for child in self.work_root.iterdir():
                if child.is_dir():
                    shutil.rmtree(child, ignore_errors=True)
                    dirs += 1
        self.work_root.mkdir(parents=True, exist_ok=True)
        return {"containers_removed": len(ids), "dirs_removed": dirs}
