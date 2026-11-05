"""Deterministic verdict rules. Code decides the verdict; the LLM only explains it.

Each sandbox run is classified from observable facts only (exit code, host-side timeout,
`REPRO: BUG` / `REPRO: OK` marker lines, the uncaught exception type and where it was raised).
The job verdict is then a pure function of the two run classifications.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

BUG, OK, SCRIPT_ERROR, SETUP_FAILED, INCONCLUSIVE = "bug", "ok", "script_error", "setup_failed", "inconclusive"

SYMPTOMS = ("exception", "hang", "wrong_output", "crash")

_MARKER = re.compile(r"^REPRO: (BUG|OK)\s*$", re.M)
_EXC_LINE = re.compile(r"^([A-Za-z_][\w.]*)(?::\s?(.*))?$")
_FRAME = re.compile(r'^\s*File "([^"]+)", line (\d+)')
_MISSING_MODULE = re.compile(r"No module named '([^']+)'")
_SCRIPT_PATH = "/repro/repro.py"
_REPAIRABLE_SYNTAX = {"SyntaxError", "IndentationError", "TabError"}


@dataclass(frozen=True)
class ExceptionInfo:
    name: str  # short class name, e.g. "ValueError"
    message: str
    in_script: bool  # raised from a frame in repro.py (not inside the package)


@dataclass(frozen=True)
class RunObservation:
    """What the sandbox showed for one version. Built from a StepResult or a test table."""

    exit_code: int
    timed_out: bool = False
    setup_failed: bool = False
    script_started: bool = True
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True)
class RunClass:
    kind: str
    reason: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Verdict:
    code: str  # reproduced | not_reproduced | already_fixed | still_present | inconclusive
    label: str
    reason: str

    def to_dict(self) -> dict:
        return asdict(self)


def markers(stdout: str) -> list[str]:
    return _MARKER.findall(stdout)


def parse_exception(stderr: str) -> ExceptionInfo | None:
    """The uncaught exception Python printed last (handles tracebacks and bare SyntaxErrors)."""
    lines = stderr.rstrip().splitlines()
    for i in range(len(lines) - 1, -1, -1):
        line = lines[i]
        if not line or line[0].isspace():
            continue
        m = _EXC_LINE.match(line)
        if not m:
            continue
        name = m.group(1).rsplit(".", 1)[-1]
        if not (name.endswith(("Error", "Exception", "Exit", "Interrupt", "Group", "Warning"))
                or name in ("StopIteration", "StopAsyncIteration", "GeneratorExit")):
            continue
        frames = [f for f in (_FRAME.match(l) for l in lines[:i]) if f]
        if not frames:
            continue
        in_script = frames[-1].group(1) == _SCRIPT_PATH
        return ExceptionInfo(name=name, message=(m.group(2) or "").strip(), in_script=in_script)
    return None


def _top(module: str) -> str:
    return module.split(".", 1)[0].strip().lower().replace("-", "_")


def is_script_error(exc: ExceptionInfo | None, target_modules: list[str]) -> bool:
    """Failures unrelated to the bug that the repair loop may fix (script only)."""
    if exc is None:
        return False
    if exc.name in _REPAIRABLE_SYNTAX:
        return exc.in_script
    if exc.name == "NameError":
        return exc.in_script
    if exc.name in ("ImportError", "ModuleNotFoundError"):
        m = _MISSING_MODULE.search(exc.message)
        if not m:
            return False
        targets = {_top(t) for t in target_modules if t}
        return _top(m.group(1)) not in targets
    return False


def classify_run(obs: RunObservation, *, symptom: str, expected_exception: str | None,
                 target_modules: list[str], timeout_s: float = 60) -> RunClass:
    if obs.setup_failed:
        return RunClass(SETUP_FAILED, "could not install the package in the sandbox")
    if obs.exit_code == 125:
        return RunClass(INCONCLUSIVE, "container runtime error")
    if obs.timed_out and not obs.script_started:
        return RunClass(SETUP_FAILED, f"setup did not finish within the {timeout_s:g} s wall clock")
    found = set(markers(obs.stdout))
    exc = parse_exception(obs.stderr)

    if symptom == "hang":
        # The claim is "never returns", so termination is the observable; REPRO markers are ignored.
        if obs.timed_out:
            return RunClass(BUG, f"hung: killed by the {timeout_s:g} s wall clock, as the issue claims")
        if is_script_error(exc, target_modules):
            return RunClass(SCRIPT_ERROR, f"script error unrelated to the bug: {exc.name}: {exc.message}"[:300])
        if obs.exit_code in (137, -9):
            return RunClass(INCONCLUSIVE, "killed by SIGKILL (memory limit reached?)")
        how = f"by raising {exc.name}" if exc and obs.exit_code != 0 else f"exit {obs.exit_code}"
        return RunClass(OK, f"finished within the {timeout_s:g} s wall clock ({how}), so it did not hang")

    if obs.timed_out:
        if found == {"BUG"}:
            return RunClass(BUG, f"printed REPRO: BUG, then was killed by the {timeout_s:g} s wall clock")
        return RunClass(INCONCLUSIVE, f"timed out after {timeout_s:g} s, but the issue does not claim a hang")
    if len(found) > 1:
        return RunClass(INCONCLUSIVE, "script printed both REPRO: BUG and REPRO: OK")
    if found == {"BUG"}:
        return RunClass(BUG, "script printed REPRO: BUG")
    if found == {"OK"}:
        if obs.exit_code == 0:
            return RunClass(OK, "script printed REPRO: OK")
        detail = f" ({exc.name})" if exc else ""
        return RunClass(INCONCLUSIVE, f"script printed REPRO: OK but exited with code {obs.exit_code}{detail}")
    # No marker.
    if is_script_error(exc, target_modules):
        return RunClass(SCRIPT_ERROR, f"script error unrelated to the bug: {exc.name}: {exc.message}"[:300])
    if obs.exit_code in (137, -9):
        return RunClass(INCONCLUSIVE, "killed by SIGKILL (memory limit reached?)")
    if expected_exception and exc and exc.name == expected_exception.rsplit(".", 1)[-1]:
        return RunClass(BUG, f"raised {exc.name} as the issue claims")
    if symptom == "crash" and obs.exit_code in (134, 139, -6, -11):
        return RunClass(BUG, f"interpreter crashed (exit {obs.exit_code}) as the issue claims")
    if obs.exit_code == 0:
        if symptom == "exception" and expected_exception:
            return RunClass(OK, f"completed without raising {expected_exception}")
        return RunClass(INCONCLUSIVE, "script finished without printing a REPRO marker")
    if exc and symptom == "wrong_output":
        # The claim is a wrong value, so an uncaught exception means the script never reached its check.
        return RunClass(SCRIPT_ERROR, f"script stopped on an uncaught {exc.name} before printing a REPRO marker "
                                      f"(the claimed bug is a wrong value, not an exception)"[:300])
    if exc:
        return RunClass(INCONCLUSIVE, f"raised {exc.name}, which is not the claimed behaviour"[:300])
    return RunClass(INCONCLUSIVE, f"exited with code {obs.exit_code} without a REPRO marker")


def decide(affected: RunClass | None, latest: RunClass | None, *,
           affected_version: str | None, latest_version: str) -> Verdict:
    """Job verdict from the run at the affected version (None = not run) and at latest."""
    lv = f"v{latest_version}"
    if latest is None:
        return Verdict("inconclusive", "Inconclusive", "the latest version was not run")
    if affected is None:
        where = f"latest {lv}" + (f" (the reported version is {lv})" if affected_version == latest_version else "")
        if latest.kind == BUG:
            return Verdict("still_present", f"Still present on latest {lv}", f"observed on {where}: {latest.reason}")
        if latest.kind == OK:
            return Verdict("not_reproduced", "Not reproduced", f"not observed on {where}: {latest.reason}")
        return Verdict("inconclusive", "Inconclusive", f"on {lv}: {latest.reason}")

    av = f"v{affected_version}"
    a, l = affected.kind, latest.kind
    if a == BUG and l == OK:
        return Verdict("already_fixed", f"Already fixed in {lv}",
                       f"bug observed at {av} ({affected.reason}); not observed at {lv} ({latest.reason})")
    if a == BUG and l == BUG:
        return Verdict("still_present", f"Still present on latest {lv}",
                       f"bug observed at {av} and at {lv} ({latest.reason})")
    if a == BUG:
        return Verdict("reproduced", "Reproduced",
                       f"bug observed at {av} ({affected.reason}); {lv} was inconclusive: {latest.reason}")
    if a == OK and l == BUG:
        return Verdict("reproduced", "Reproduced",
                       f"not observed at {av}, but observed at {lv} ({latest.reason})")
    if a == OK and l == OK:
        return Verdict("not_reproduced", "Not reproduced",
                       f"claimed behaviour not observed at {av} ({affected.reason}) nor at {lv}")
    if a == OK:
        return Verdict("not_reproduced", "Not reproduced",
                       f"not observed at {av} ({affected.reason}); {lv} was inconclusive: {latest.reason}")
    if l == BUG:
        return Verdict("still_present", f"Still present on latest {lv}",
                       f"observed at {lv} ({latest.reason}); {av} could not be checked: {affected.reason}")
    if l == OK:
        return Verdict("inconclusive", "Inconclusive",
                       f"{av} could not be checked ({affected.reason}); not observed at {lv}")
    return Verdict("inconclusive", "Inconclusive", f"{av}: {affected.reason}; {lv}: {latest.reason}")
