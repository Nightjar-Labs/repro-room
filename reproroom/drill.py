"""Containment drill: run the hostile fixture and check the host before and after.

The attacker's view comes from the fixture's own `DRILL` lines (what it really observed inside
the sandbox); the host's view comes from checks the control plane performs outside it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import time
from pathlib import Path

import httpx

FIXTURE = Path(__file__).parent / "fixtures" / "hostile_repro.py"
DRILL_PACKAGE = "six==1.17.0"  # a tiny benign wheel so the drill shows both sandbox phases
DRILL_ISSUE_TITLE = "Containment drill: a hostile \"reproduction script\""
DRILL_ISSUE_BODY = (
    "This built-in issue's \"repro\" is malicious on purpose. It reads the environment and /proc/1/environ, "
    "tries to phone home (DNS, TCP, HTTPS, curl | sh), looks for the host and the container runtime socket, "
    "tries to become root, overwrites system files, fills the disk, fork-bombs, runs rm -rf ~ and rm -rf /, "
    "and finally allocates memory until something stops it. It runs verbatim (no LLM involved) in the same "
    "sandbox every reproduction uses."
)

_SECRET_NAME = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL", re.I)


def fixture_script() -> str:
    return FIXTURE.read_text()


def ensure_canary_secret() -> None:
    """A fake secret in the control-plane env; the drill and the tests assert it never leaks."""
    os.environ.setdefault("REPRO_ROOM_CANARY_SECRET", "rrcanary-" + secrets.token_hex(16))


def control_plane_secret_values(extra: list[str] | tuple[str, ...] = ()) -> list[str]:
    """Secret values the control plane holds: secret-looking env vars plus secrets loaded from files."""
    values = {v for k, v in os.environ.items() if _SECRET_NAME.search(k) and len(v) >= 8}
    values.update(v for v in extra if v and len(v) >= 8)
    return sorted(values)


def leaked_secrets(*outputs: str, extra: list[str] | tuple[str, ...] = ()) -> int:
    blob = "\n".join(outputs)
    return sum(1 for v in control_plane_secret_values(extra) if v in blob)


def parse_attacks(stdout: str) -> tuple[list[dict], str | None, bool]:
    """(reported attacks, attack running when output stopped, finished cleanly)."""
    attacks: list[dict] = []
    current = None
    finished = False
    for line in stdout.splitlines():
        if line.startswith("DRILL_START "):
            current = json.loads(line[12:]).get("attack")
        elif line.startswith("DRILL "):
            try:
                attacks.append(json.loads(line[6:]))
            except json.JSONDecodeError:
                continue
            current = None
        elif line.strip() == "DRILL_END":
            finished = True
    return attacks, current, finished


class HostProbe:
    """Observations of the host and the control plane, taken from outside the sandbox."""

    def __init__(self, data_dir: Path, self_url: str, containers_running, secrets_held: tuple[str, ...] = ()):
        self.canary = Path(data_dir) / "host-canary.txt"
        self.self_url = self_url
        self.secrets_held = tuple(s for s in secrets_held if s)
        self._containers_running = containers_running
        if not self.canary.exists():
            self.canary.parent.mkdir(parents=True, exist_ok=True)
            self.canary.write_text(f"Repro Room host canary {secrets.token_hex(16)}\n")

    def leaked(self, *outputs: str) -> int:
        return leaked_secrets(*outputs, extra=self.secrets_held)

    def snapshot(self) -> dict:
        snap: dict = {"at": time.time()}
        if self.canary.exists():
            snap["canary"] = {"path": str(self.canary), "exists": True,
                              "sha256": hashlib.sha256(self.canary.read_bytes()).hexdigest()[:16]}
        else:
            snap["canary"] = {"path": str(self.canary), "exists": False, "sha256": None}
        t0 = time.monotonic()
        try:
            r = httpx.get(f"{self.self_url}/healthz", timeout=5.0)
            snap["app"] = {"ok": r.status_code == 200, "status": r.status_code, "ms": round((time.monotonic() - t0) * 1000)}
        except httpx.HTTPError as e:
            snap["app"] = {"ok": False, "status": None, "error": type(e).__name__}
        snap["sandbox_containers"] = self._containers_running()
        snap["load1"] = round(os.getloadavg()[0], 2)
        snap["mem_available_mb"] = _mem_available_mb()
        snap["secrets_in_control_plane"] = len(control_plane_secret_values(self.secrets_held))
        return snap


def _mem_available_mb() -> int | None:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) // 1024
    except OSError:
        pass
    return None


def host_checks(before: dict, after: dict, run: dict, leaked: int, leftovers: int) -> list[dict]:
    """Host-side verdicts on the drill, each a real comparison of observations."""
    checks = []

    def add(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "ok": ok, "detail": detail})

    exit_detail = "killed at the wall clock" if run.get("timed_out") else f"exit {run.get('exit_code')}"
    add("Sandbox ended and was destroyed", bool(run.get("removed")),
        f"{exit_detail} after {run.get('duration')} s; container {'gone' if run.get('removed') else 'STILL PRESENT'}")
    add("No leftover sandbox containers", leftovers == 0, f"{leftovers} containers labelled for this job remain")
    add("No control-plane secret in sandbox output", leaked == 0,
        f"{after.get('secrets_in_control_plane', 0)} secret values held by the control plane; {leaked} found in sandbox output")
    cb, ca = before.get("canary", {}), after.get("canary", {})
    add("Host canary file untouched", bool(ca.get("exists")) and ca.get("sha256") == cb.get("sha256"),
        f"{ca.get('path')}: sha256 {cb.get('sha256')} before, {ca.get('sha256')} after")
    ab, aa = before.get("app", {}), after.get("app", {})
    add("Control plane still responds", bool(aa.get("ok")),
        f"/healthz {ab.get('status')} ({ab.get('ms')} ms) before, {aa.get('status')} ({aa.get('ms')} ms) after")
    return checks
