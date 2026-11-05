"""FastAPI control plane: server-rendered pages, a JSON job API and /healthz."""

from __future__ import annotations

import logging
import threading
import time
from contextlib import asynccontextmanager
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import __version__, drill
from .agent import Agent
from .config import Settings
from .jobqueue import JobQueue, LimitError
from .llm import ChatModel, OpenAICompatClient
from .pipeline import Pipeline
from .sandbox import SandboxRunner
from .sources import GitHubReader, PyPI, SourceError, parse_issue_url
from .store import Store

log = logging.getLogger("reproroom")
HERE = Path(__file__).parent

EXAMPLES = [
    {"url": "https://github.com/python-poetry/tomlkit/issues/442", "label": "tomlkit#442",
     "blurb": "boolean(True) renders “false”; snippet pasted with >>> prompts"},
    {"url": "https://github.com/jd/tenacity/issues/658", "label": "tenacity#658",
     "blurb": "retry spins forever on a cause cycle; the wall clock has to kill it"},
    {"url": "https://github.com/Textualize/rich/issues/4234", "label": "rich#4234",
     "blurb": "Text.wrap(width=0) raises ValueError; still open"},
    {"url": "https://github.com/marshmallow-code/marshmallow/issues/2831", "label": "marshmallow#2831",
     "blurb": "Boolean with custom truthy accepts 0/1, or does it?"},
    {"url": "https://github.com/andialbrecht/sqlparse/issues/826", "label": "sqlparse#826",
     "blurb": "split() regression; output-based, needs the REPRO marker"},
    {"url": "https://github.com/pypa/packaging/issues/938", "label": "packaging#938",
     "blurb": "InvalidVersion when evaluating markers"},
]

VERDICT_STYLE = {
    "already_fixed": "good", "contained": "good", "still_present": "bad", "breach": "bad",
    "reproduced": "warn", "not_reproduced": "info", "inconclusive": "muted",
}

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


def _default_chat_factory(settings: Settings) -> Callable[[], ChatModel]:
    client: OpenAICompatClient | None = None

    def make() -> ChatModel:  # one shared HTTP client; created lazily so a missing key fails the job, not startup
        nonlocal client
        if client is None:
            client = OpenAICompatClient(settings.llm_base_url, settings.llm_api_key, settings.llm_model,
                                        timeout=settings.llm_timeout)
        return client
    return make


def create_app(settings: Settings | None = None, *, chat_factory: Callable[[], ChatModel] | None = None,
               runner: SandboxRunner | None = None, start_worker: bool = True,
               github: GitHubReader | None = None, pypi: PyPI | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    drill.ensure_canary_secret()
    store = Store(settings.data_dir / "reproroom.db")
    runner = runner or SandboxRunner(settings.sandbox, settings.work_root)
    chat_factory = chat_factory or _default_chat_factory(settings)
    probe = drill.HostProbe(settings.data_dir, settings.self_url, lambda: len(runner.containers_for(None)),
                            secrets_held=(settings.llm_api_key, settings.github_token))
    pipeline = Pipeline(settings, store, runner, lambda: Agent(chat_factory()),
                        github or GitHubReader(settings.github_token), pypi or PyPI(), probe)
    jobs = JobQueue(settings, store, pipeline.process)
    runtime_cache = {"at": 0.0, "ok": False}
    runtime_lock = threading.Lock()

    def runtime_ok() -> bool:
        with runtime_lock:
            if time.monotonic() - runtime_cache["at"] > 30:
                runtime_cache.update(at=time.monotonic(), ok=runner.available())
            return runtime_cache["ok"]

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if start_worker:
            swept = runner.janitor()
            log.info("janitor: %s", swept)
            try:
                log.info("sandbox image digest: %s", runner.ensure_image())
            except Exception as e:  # keep serving; /healthz reports the runtime state
                log.error("sandbox image unavailable: %s", e)
            n = store.mark_interrupted()
            if n:
                log.warning("marked %d interrupted jobs as failed", n)
            jobs.start()
        yield
        if start_worker:
            jobs.stop()

    app = FastAPI(title="Repro Room", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.settings, app.state.store, app.state.jobs, app.state.pipeline = settings, store, jobs, pipeline
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.globals.update(
        verdict_style=VERDICT_STYLE, version=__version__, model=settings.llm_model,
        llm_host=urlparse(settings.llm_base_url).hostname or "", sandbox=settings.sandbox,
    )
    templates.env.filters["ago"] = _ago
    templates.env.filters["flag_pairs"] = flag_pairs

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp: Response = await call_next(request)
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        return resp

    def client_ip(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def home(request: Request, error: str | None = None, status: int = 200, url: str = "") -> HTMLResponse:
        recent = [j for j in store.recent(12)]
        return templates.TemplateResponse(request, "home.html", {
            "examples": EXAMPLES, "recent": recent, "error": error, "url": url,
            "limits": {"queue": settings.max_queue, "per_ip": settings.rate_limit_per_ip,
                       "window_min": settings.rate_limit_window // 60, "daily": settings.daily_job_cap},
        }, status_code=status)

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        return home(request)

    @app.post("/jobs")
    def submit(request: Request, url: str = Form(""), text: str = Form(""), title: str = Form("")):
        url, text, title = url.strip(), text.strip(), title.strip()[:200]
        try:
            if url:
                parse_issue_url(url)
                job_id = jobs.submit("issue", url, client_ip(request))
            elif text:
                if len(text) > settings.max_issue_chars:
                    raise SourceError(f"Pasted text is limited to {settings.max_issue_chars} characters.")
                job_id = jobs.submit("text", "pasted text", client_ip(request), title=title, text=text)
            else:
                raise SourceError("Paste a GitHub issue URL or the issue text.")
        except SourceError as e:
            return home(request, str(e), 400, url)
        except LimitError as e:
            return home(request, e.message, e.status, url)
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)

    @app.post("/drill")
    def start_drill(request: Request):
        try:
            job_id = jobs.submit("drill", "containment drill", client_ip(request))
        except LimitError as e:
            return home(request, e.message, e.status)
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)

    def job_context(job_id: str) -> dict | None:
        state = store.get(job_id)
        if state is None:
            return None
        return {"job": state, "position": jobs.position(job_id) if state["status"] == "queued" else None,
                "now": time.time()}

    @app.get("/jobs/{job_id}", response_class=HTMLResponse)
    def job_page(request: Request, job_id: str):
        ctx = job_context(job_id)
        if ctx is None:
            return home(request, "No such job.", 404)
        return templates.TemplateResponse(request, "job.html", ctx)

    @app.get("/jobs/{job_id}/fragment", response_class=HTMLResponse)
    def job_fragment(request: Request, job_id: str):
        ctx = job_context(job_id)
        if ctx is None:
            return HTMLResponse("", status_code=404)
        return templates.TemplateResponse(request, "_job_body.html", ctx)

    @app.get("/api/jobs/{job_id}")
    def job_json(job_id: str):
        state = store.get(job_id)
        if state is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        return state

    @app.get("/api/jobs/{job_id}/rev")
    def job_rev(job_id: str):
        state = store.get(job_id)
        if state is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        return {"rev": state["rev"], "status": state["status"]}

    @app.get("/healthz")
    def healthz():
        ok = runtime_ok()
        return JSONResponse({
            "status": "ok" if ok else "degraded",
            "version": __version__,
            "sandbox": {"cli": settings.sandbox.cli, "oci_runtime": settings.sandbox.oci_runtime or "default",
                        "image": settings.sandbox.image, "runtime_ok": ok},
            "queue": store.count_active(),
            "llm": {"host": urlparse(settings.llm_base_url).hostname, "model": settings.llm_model,
                    "configured": bool(settings.llm_api_key)},
        }, status_code=200)

    return app


_BOOL_FLAGS = {"--read-only", "--init", "--rm", "--http-proxy=false", "--pull=never"}


def flag_pairs(flags: list[str]) -> list[str]:
    """['--memory', '512m', '--init'] -> ['--memory 512m', '--init'] for display; labels omitted."""
    out, i = [], 0
    while i < len(flags):
        f = flags[i]
        if f.startswith("--") and f not in _BOOL_FLAGS and i + 1 < len(flags) and not flags[i + 1].startswith("--"):
            if f != "--label":
                out.append(f"{f} {flags[i + 1]}")
            i += 2
        else:
            out.append(f)
            i += 1
    return out


def _ago(ts: float | None) -> str:
    if not ts:
        return ""
    d = time.time() - ts
    if d < 60:
        return "just now"
    if d < 3600:
        return f"{int(d // 60)} min ago"
    if d < 86400:
        return f"{int(d // 3600)} h ago"
    return f"{int(d // 86400)} d ago"


def main() -> None:
    import os

    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    uvicorn.run("reproroom.app:create_app", factory=True, host=os.environ.get("HOST", "127.0.0.1"),
                port=int(os.environ.get("PORT", "8000")), proxy_headers=True, forwarded_allow_ips="127.0.0.1")
