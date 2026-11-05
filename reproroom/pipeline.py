"""Job orchestration: issue → facts → script → sandbox runs (+ bounded repair) → verdict → explanation."""

from __future__ import annotations

import logging
import secrets
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass

from . import drill
from .agent import MAX_REPAIRS, Agent, annotate_script
from .config import Settings
from .llm import LLMError
from .sandbox import SandboxRunner, StepResult
from .sources import GitHubReader, Issue, PyPI, SourceError
from .store import Store
from .verdict import (BUG, OK, SCRIPT_ERROR, SETUP_FAILED, RunClass, RunObservation, Verdict, classify_run,
                      decide)

log = logging.getLogger(__name__)


def new_job_id() -> str:
    return secrets.token_hex(5)


def new_state(job_id: str, kind: str, source: str, *, title: str = "", text: str = "") -> dict:
    return {
        "id": job_id, "kind": kind, "source": source, "title": title, "text": text,
        "status": "queued", "rev": 0,
        "created_at": time.time(), "started_at": None, "finished_at": None,
        "issue": None, "facts": None, "versions": None,
        "events": [], "scripts": [], "runs": [], "llm_calls": [],
        "verdict": None, "explanation": None, "draft_comment": None,
        "drill": None, "cleanup": None, "notes": [], "error": None,
    }


class JobCtx:
    """Mutates one job's state and persists every change (the UI polls `rev`)."""

    def __init__(self, store: Store, state: dict):
        self.store = store
        self.state = state

    def save(self) -> None:
        self.state["rev"] += 1
        self.store.save(self.state)

    def begin(self, title: str, kind: str) -> dict:
        ev = {"title": title, "kind": kind, "status": "running", "started": time.time(), "ended": None,
              "detail": "", "ref": None}
        self.state["events"].append(ev)
        self.save()
        return ev

    def end(self, ev: dict, status: str = "done", detail: str = "", ref: int | None = None) -> None:
        ev.update(status=status, ended=time.time(), detail=detail)
        if ref is not None:
            ev["ref"] = ref
        self.save()

    def note(self, text: str) -> None:
        self.state["notes"].append(text)
        self.save()

    def add_script(self, code: str, reason: str, snippet: str) -> int:
        lines = annotate_script(code, snippet)
        self.state["scripts"].append({
            "code": code, "reason": reason, "lines": lines,
            "added": sum(l["kind"] == "added" for l in lines),
            "unmarked": sum(l["kind"] == "unmarked" for l in lines),
        })
        self.save()
        return len(self.state["scripts"]) - 1

    def add_run(self, res: StepResult, **extra) -> int:
        d = res.to_dict()
        d["script_stdout"] = res.script_stdout
        d.update(extra)
        self.state["runs"].append(d)
        self.save()
        return len(self.state["runs"]) - 1


@dataclass
class Pipeline:
    settings: Settings
    store: Store
    runner: SandboxRunner
    make_agent: Callable[[], Agent]
    github: GitHubReader
    pypi: PyPI
    probe: drill.HostProbe

    def process(self, job_id: str) -> None:
        state = self.store.get(job_id)
        if state is None:
            return
        ctx = JobCtx(self.store, state)
        state["status"] = "running"
        state["started_at"] = time.time()
        ctx.save()
        agent: Agent | None = None
        try:
            if state["kind"] == "drill":
                self._drill(ctx)
            else:
                agent = self.make_agent()
                self._issue(ctx, agent)
            state["status"] = "done"
        except (SourceError, LLMError) as e:
            self._fail(ctx, str(e))
        except Exception as e:  # keep the worker alive; record what happened
            log.error("job %s crashed: %s", job_id, traceback.format_exc())
            self._fail(ctx, f"internal error: {type(e).__name__}: {e}"[:500])
        finally:
            if agent is not None:
                state["llm_calls"] = [c.__dict__ for c in agent.calls]
            ev = ctx.begin("Destroy job sandbox leftovers", "cleanup")
            cleanup = self.runner.cleanup_job(job_id)
            state["cleanup"] = cleanup
            ctx.end(ev, "done", f"{cleanup['containers_removed']} stray containers removed; "
                                f"job directory {'deleted' if cleanup['dir_removed'] else 'already gone'}")
            state["finished_at"] = time.time()
            ctx.save()

    def _fail(self, ctx: JobCtx, message: str) -> None:
        st = ctx.state
        for ev in st["events"]:
            if ev["status"] == "running":
                ev.update(status="failed", ended=time.time(), detail=ev["detail"] or message)
        st["status"] = "failed"
        st["error"] = message
        if st["verdict"] is None:
            st["verdict"] = Verdict("inconclusive", "Inconclusive", message).to_dict()

    # ---- issue jobs ----------------------------------------------------------------------------
    def _issue(self, ctx: JobCtx, agent: Agent) -> None:
        st, job = ctx.state, ctx.state["id"]
        ev = ctx.begin("Read the issue", "issue")
        if st["kind"] == "issue":
            issue = self.github.read(st["source"])
            detail = f"{issue.repo}#{issue.number} ({issue.state}): {issue.title}"
        else:
            issue = Issue(url="", repo="", number=None, title=st.get("title") or "Pasted issue text",
                          state="", body=st.get("text") or "", comments=[])
            detail = f"pasted text, {len(issue.body)} characters"
        st["issue"] = issue.to_dict()
        ctx.end(ev, "done", detail)
        text = issue.as_prompt_text(self.settings.max_issue_chars)

        ev = ctx.begin("Extract facts (LLM)", "llm")
        facts = agent.extract(text, issue.repo or None)
        st["facts"] = facts.model_dump()
        supported, why = facts.check_supported()
        if not supported:
            ctx.end(ev, "warn", why)
            st["verdict"] = Verdict("inconclusive", "Inconclusive", f"not supported: {why}").to_dict()
            return
        ctx.end(ev, "done", f"{facts.package} {facts.affected_version or '(version not stated)'}; symptom: {facts.symptom}")

        ev = ctx.begin("Look up the package on PyPI", "pypi")
        info = self.pypi.info(facts.package)
        affected = info.find(facts.affected_version)
        latest = info.latest
        if facts.affected_version and not affected:
            ctx.note(f"The reported version {facts.affected_version} is not on PyPI; only the latest release is checked.")
        st["versions"] = {"package": info.name, "stated": facts.affected_version, "affected": affected, "latest": latest}
        ctx.end(ev, "done", f"{info.name}: reported {affected or 'n/a'}, latest {latest}")

        ev = ctx.begin("Write repro.py from the snippet (LLM)", "llm")
        script = agent.write_script(facts, text)
        idx = ctx.add_script(script, "written from the issue's snippet", facts.snippet)
        sc = st["scripts"][idx]
        ctx.end(ev, "done" if not sc["unmarked"] else "warn",
                f"{len(script.splitlines())} lines, {sc['added']} marked as added"
                + (f", {sc['unmarked']} changed without the marker" if sc["unmarked"] else ""))

        plan = [("affected", affected)] if affected and affected != latest else []
        plan.append(("latest", latest))
        fetched: dict[str, StepResult] = {}
        for role, ver in plan:
            req = f"{info.name}=={ver}"
            ev = ctx.begin(f"Fetch {req} (network on, no untrusted code runs)", "fetch")
            res = self.runner.fetch(job, req, self.runner.wheels_dir(job, ver), label=role)
            ref = ctx.add_run(res, role=role, version=ver, attempt=None, classification=None)
            fetched[role] = res
            ok = res.exit_code == 0 and not res.timed_out
            ctx.end(ev, "done" if ok else "failed",
                    f"{'wheels downloaded' if ok else 'pip download failed'} in {res.duration} s", ref)

        targets = [t for t in (facts.import_name, info.name, facts.package) if t]
        attempt = 0
        script_ref = idx
        while True:
            classes: dict[str, RunClass] = {}
            runs_this_attempt: list[dict] = []
            failing: tuple[RunClass, StepResult] | None = None
            for role, ver in plan:
                f = fetched[role]
                if f.exit_code != 0 or f.timed_out:
                    tail = (f.stderr.strip().splitlines() or ["no output"])[-1][:200]
                    classes[role] = RunClass(SETUP_FAILED, f"no installable wheel for Python 3.12 ({tail})")
                    continue
                req = f"{info.name}=={ver}"
                ev = ctx.begin(f"Run repro.py at {ver} (network off, attempt {attempt + 1})", "run")
                script_path = self.runner.write_script(job, attempt, script)
                res = self.runner.run(job, script_path, wheels_dir=self.runner.wheels_dir(job, ver),
                                      requirement=req, label=f"{role}-{attempt}")
                obs = RunObservation(exit_code=res.exit_code, timed_out=res.timed_out, setup_failed=res.setup_failed,
                                     script_started=res.script_started, stdout=res.script_stdout, stderr=res.stderr)
                cls = classify_run(obs, symptom=facts.symptom, expected_exception=facts.expected_exception,
                                   target_modules=targets, timeout_s=self.settings.sandbox.run_timeout)
                classes[role] = cls
                ref = ctx.add_run(res, role=role, version=ver, attempt=attempt, script=script_ref,
                                  classification=cls.to_dict())
                runs_this_attempt.append(st["runs"][ref])
                status = {BUG: "bug", OK: "ok", SCRIPT_ERROR: "warn"}.get(cls.kind, "warn")
                ctx.end(ev, status, f"{cls.kind.replace('_', ' ')}: {cls.reason}", ref)
                if cls.kind == SCRIPT_ERROR and attempt < MAX_REPAIRS:
                    failing = (cls, res)
                    break
            if failing is None:
                break
            attempt += 1
            cls, res = failing
            ev = ctx.begin(f"Repair repro.py, attempt {attempt} of {MAX_REPAIRS} (LLM)", "llm")
            script = agent.repair_script(facts, script, cls.reason, res.script_stdout, res.stderr, attempt)
            script_ref = ctx.add_script(script, f"repair {attempt}: {cls.reason}", facts.snippet)
            ctx.end(ev, "done", f"rewrote the script only, because of: {cls.reason}")

        ev = ctx.begin("Verdict (deterministic rules)", "verdict")
        verdict = decide(classes.get("affected"), classes.get("latest"),
                         affected_version=affected or facts.affected_version, latest_version=latest)
        st["verdict"] = verdict.to_dict()
        st["final_runs"] = [r["version"] for r in runs_this_attempt]
        ctx.end(ev, "done", f"{verdict.label}: {verdict.reason}")

        ev = ctx.begin("Explain and draft a maintainer comment (LLM)", "llm")
        try:
            explanation, comment = agent.explain(facts, verdict.to_dict(), runs_this_attempt, script)
        except LLMError as e:
            ctx.end(ev, "failed", f"no explanation: {e}"[:300])
            return
        st["explanation"], st["draft_comment"] = explanation, comment
        ctx.end(ev, "done", "draft comment ready (not posted anywhere)")

    # ---- containment drill ---------------------------------------------------------------------
    def _drill(self, ctx: JobCtx) -> None:
        st, job = ctx.state, ctx.state["id"]
        st["issue"] = {"url": "", "repo": "built-in fixture", "number": None, "title": drill.DRILL_ISSUE_TITLE, "state": ""}
        st["facts"] = {"package": drill.DRILL_PACKAGE.split("==")[0], "affected_version": drill.DRILL_PACKAGE.split("==")[1],
                       "claimed_behaviour": drill.DRILL_ISSUE_BODY, "symptom": "hostile", "snippet": ""}
        script = drill.fixture_script()
        ctx.add_script(script, "hostile fixture, run verbatim (no LLM involved)", script)

        ev = ctx.begin("Host health check (before)", "health")
        before = self.probe.snapshot()
        ctx.end(ev, "done", _health_detail(before))

        ev = ctx.begin(f"Fetch {drill.DRILL_PACKAGE} (network on, no untrusted code runs)", "fetch")
        wheels = self.runner.wheels_dir(job, "drill")
        f = self.runner.fetch(job, drill.DRILL_PACKAGE, wheels, label="drill")
        ref = ctx.add_run(f, role="drill", version=drill.DRILL_PACKAGE.split("==")[1], attempt=None, classification=None)
        ctx.end(ev, "done" if f.exit_code == 0 else "failed", f"exit {f.exit_code} in {f.duration} s", ref)
        if f.exit_code != 0:
            raise RuntimeError("could not fetch the drill package")

        ev = ctx.begin("Run the hostile script (network off, all limits on)", "run")
        script_path = self.runner.write_script(job, 0, script)
        res = self.runner.run(job, script_path, wheels_dir=wheels, requirement=drill.DRILL_PACKAGE, label="hostile")
        ref = ctx.add_run(res, role="hostile", version=drill.DRILL_PACKAGE.split("==")[1], attempt=0, script=0, classification=None)
        attacks, interrupted, finished = drill.parse_attacks(res.script_stdout)
        if interrupted:
            how = "killed at the wall clock" if res.timed_out else f"exit {res.exit_code}"
            attacks.append({"attack": interrupted, "goal": "", "contained": True,
                            "observed": f"the sandbox ended mid-attack ({how}); seen from the host"})
        ctx.end(ev, "done", f"{len(attacks)} attacks, exit {res.exit_code} in {res.duration} s, "
                            f"container {'destroyed' if res.removed else 'NOT destroyed'}", ref)

        leftovers = len(self.runner.containers_for(job))
        leaked = self.probe.leaked(res.stdout, res.stderr)
        ev = ctx.begin("Host health check (after)", "health")
        after = self.probe.snapshot()
        ctx.end(ev, "done", _health_detail(after))

        checks = drill.host_checks(before, after, st["runs"][ref], leaked, leftovers)
        st["drill"] = {"attacks": attacks, "finished": finished, "before": before, "after": after, "checks": checks}
        contained = all(a.get("contained") for a in attacks) and all(c["ok"] for c in checks) and bool(attacks)
        ev = ctx.begin("Containment verdict (host-side checks)", "verdict")
        n_ok = sum(bool(a.get("contained")) for a in attacks)
        if contained:
            st["verdict"] = Verdict("contained", "Contained",
                                    f"{n_ok}/{len(attacks)} attacks contained; all {len(checks)} host checks passed").to_dict()
        else:
            failed = [c["check"] for c in checks if not c["ok"]] + [a["attack"] for a in attacks if not a.get("contained")]
            st["verdict"] = Verdict("breach", "Breach", f"not contained: {', '.join(failed) or 'no attacks reported'}").to_dict()
        ctx.end(ev, "done" if contained else "failed", st["verdict"]["reason"])


def _health_detail(s: dict) -> str:
    app = s.get("app", {})
    canary = s.get("canary", {})
    return (f"app /healthz {app.get('status')} in {app.get('ms', '?')} ms; canary "
            f"{'present' if canary.get('exists') else 'MISSING'} (sha256 {canary.get('sha256')}); "
            f"{s.get('sandbox_containers')} sandbox containers; load {s.get('load1')}; "
            f"{s.get('mem_available_mb')} MB free")
