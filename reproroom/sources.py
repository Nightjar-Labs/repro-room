"""Read-only inputs: GitHub issues (REST) and PyPI package metadata (JSON API)."""

from __future__ import annotations

import re
from dataclasses import dataclass

import httpx
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

ISSUE_URL = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/(?P<repo>[A-Za-z0-9._-]{1,100})"
    r"/issues/(?P<number>[1-9][0-9]{0,6})/?(?:[?#].*)?$"
)
PYPI_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$")
_UA = "ReproRoom/0.1 (Nightjar Labs)"


class SourceError(ValueError):
    pass


@dataclass
class Issue:
    url: str
    repo: str
    number: int | None
    title: str
    state: str
    body: str
    comments: list[str]

    def as_prompt_text(self, max_chars: int) -> str:
        parts = [f"Title: {self.title}", f"Repository: {self.repo or 'unknown'}", "", self.body or "(empty body)"]
        for i, c in enumerate(self.comments, 1):
            parts += ["", f"--- comment {i} ---", c]
        text = "\n".join(parts)
        return text[:max_chars]

    def to_dict(self) -> dict:
        return {"url": self.url, "repo": self.repo, "number": self.number, "title": self.title, "state": self.state}


def parse_issue_url(url: str) -> tuple[str, str, int]:
    m = ISSUE_URL.match(url.strip())
    if not m:
        raise SourceError("Only public GitHub issue URLs are accepted, e.g. https://github.com/owner/repo/issues/123")
    return m["owner"], m["repo"], int(m["number"])


class GitHubReader:
    def __init__(self, token: str = "", *, transport: httpx.BaseTransport | None = None):
        headers = {"Accept": "application/vnd.github+json", "User-Agent": _UA, "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.Client(base_url="https://api.github.com", headers=headers, timeout=20.0, transport=transport)

    def read(self, url: str, *, max_comments: int = 3) -> Issue:
        owner, repo, number = parse_issue_url(url)
        r = self._client.get(f"/repos/{owner}/{repo}/issues/{number}")
        if r.status_code == 404:
            raise SourceError("Issue not found (or the repository is private).")
        if r.status_code in (403, 429):
            raise SourceError("GitHub rate limit reached; try again later.")
        r.raise_for_status()
        data = r.json()
        if "pull_request" in data:
            raise SourceError("That URL is a pull request, not an issue.")
        comments: list[str] = []
        if max_comments and data.get("comments"):
            c = self._client.get(f"/repos/{owner}/{repo}/issues/{number}/comments", params={"per_page": max_comments})
            if c.status_code == 200:
                comments = [(x.get("body") or "")[:4000] for x in c.json()[:max_comments]]
        return Issue(
            url=f"https://github.com/{owner}/{repo}/issues/{number}",
            repo=f"{owner}/{repo}",
            number=number,
            title=data.get("title") or "",
            state=data.get("state") or "",
            body=data.get("body") or "",
            comments=comments,
        )


@dataclass
class PackageInfo:
    name: str  # canonical PyPI project name as published
    latest: str
    versions: list[str]

    def find(self, version: str | None) -> str | None:
        """The published version string equal to `version` (PEP 440 equality), if any."""
        if not version:
            return None
        try:
            want = Version(version.lstrip("vV"))
        except InvalidVersion:
            return None
        for v in self.versions:
            try:
                if Version(v) == want:
                    return v
            except InvalidVersion:
                continue
        return None


class PyPI:
    def __init__(self, *, transport: httpx.BaseTransport | None = None):
        self._client = httpx.Client(base_url="https://pypi.org", headers={"User-Agent": _UA}, timeout=20.0,
                                    transport=transport, follow_redirects=True)

    def info(self, name: str) -> PackageInfo:
        if not PYPI_NAME.match(name or ""):
            raise SourceError(f"{name!r} is not a valid PyPI project name")
        r = self._client.get(f"/pypi/{canonicalize_name(name)}/json")
        if r.status_code == 404:
            raise SourceError(f"{name!r} is not a package on PyPI")
        r.raise_for_status()
        data = r.json()
        releases = data.get("releases") or {}
        versions = [v for v, files in releases.items() if files and not all(f.get("yanked") for f in files)]
        return PackageInfo(name=data["info"]["name"], latest=data["info"]["version"], versions=versions)
