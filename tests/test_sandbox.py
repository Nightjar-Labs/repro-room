"""Each hostile behaviour is contained by the real sandbox (podman or docker)."""

import json
import os
import subprocess

import pytest

from reproroom import drill
from reproroom.sandbox import SCRIPT_ENV, TIMEOUT_EXIT, cli_env

from .conftest import CANARY, FAKE_LLM_KEY

pytestmark = pytest.mark.sandbox


def test_env_contains_no_host_secrets(run_script):
    assert os.environ["REPRO_ROOM_CANARY_SECRET"] == CANARY
    res = run_script(
        "import os, json\n"
        "print('ENV', json.dumps(dict(os.environ)))\n"
        "print('PID1', open('/proc/1/environ','rb').read().replace(b'\\0', b' ').decode())\n"
    )
    assert res.exit_code == 0, res.stderr
    env = json.loads(next(l for l in res.stdout.splitlines() if l.startswith("ENV "))[4:])
    assert env == SCRIPT_ENV
    blob = res.stdout + res.stderr + " ".join(res.command)
    assert CANARY not in blob
    assert FAKE_LLM_KEY not in blob and os.environ.get("LLM_API_KEY", FAKE_LLM_KEY) not in blob
    assert "REPRO_ROOM_CANARY_SECRET" not in blob


def test_cli_env_is_allowlisted(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_should_not_pass")
    monkeypatch.setenv("HTTPS_PROXY", "http://user:pass@proxy:3128")
    env = cli_env()
    assert "GITHUB_TOKEN" not in env and "LLM_API_KEY" not in env
    assert "REPRO_ROOM_CANARY_SECRET" not in env and "HTTPS_PROXY" not in env


def test_network_unreachable_in_run_phase(run_script):
    res = run_script(
        "import socket, urllib.request\n"
        "for target in (('1.1.1.1', 443), ('8.8.8.8', 53)):\n"
        "    try:\n"
        "        socket.create_connection(target, timeout=3); print('CONNECTED', target)\n"
        "    except OSError as e:\n"
        "        print('BLOCKED', target, e)\n"
        "try:\n"
        "    urllib.request.urlopen('https://pypi.org/', timeout=3); print('CONNECTED https')\n"
        "except Exception as e:\n"
        "    print('BLOCKED https', e)\n"
        "print('IFACES', sorted(n for _, n in socket.if_nameindex()))\n"
    )
    assert res.exit_code == 0, res.stderr
    assert "CONNECTED" not in res.stdout
    assert res.stdout.count("BLOCKED") == 3
    assert "IFACES ['lo']" in res.stdout


def test_read_only_root_and_unprivileged(run_script):
    res = run_script(
        "import os\n"
        "for p in ('/etc/evil', '/usr/local/lib/evil.py', '/repro/evil', '/evil'):\n"
        "    try:\n"
        "        open(p, 'w').write('x'); print('WROTE', p)\n"
        "    except OSError as e:\n"
        "        print('DENIED', p, e.strerror)\n"
        "open(os.path.expanduser('~/ok.txt'), 'w').write('fine'); print('HOME_WRITABLE')\n"
        "print('UID', os.getuid(), os.getgid())\n"
        "status = open('/proc/self/status').read()\n"
        "print([l for l in status.splitlines() if l.startswith(('CapEff', 'CapBnd', 'NoNewPrivs'))])\n"
    )
    assert res.exit_code == 0, res.stderr
    assert "WROTE" not in res.stdout
    assert res.stdout.count("DENIED") == 4
    assert "HOME_WRITABLE" in res.stdout
    assert "UID 65534 65534" in res.stdout
    assert "CapEff:\\t0000000000000000" in res.stdout
    assert "CapBnd:\\t0000000000000000" in res.stdout
    assert "NoNewPrivs:\\t1" in res.stdout


def test_fork_bomb_hits_pids_limit(run_script, sandbox_settings):
    res = run_script(
        "import os, time\n"
        "n = 0\n"
        "try:\n"
        "    while n < 5000:\n"
        "        if os.fork() == 0:\n"
        "            time.sleep(2); os._exit(0)\n"
        "        n += 1\n"
        "except OSError as e:\n"
        "    print('REFUSED', n, type(e).__name__)\n"
        "else:\n"
        "    print('UNLIMITED', n)\n"
    )
    assert "UNLIMITED" not in res.stdout
    line = next(l for l in res.stdout.splitlines() if l.startswith("REFUSED"))
    _, n, exc = line.split()
    assert int(n) < sandbox_settings.pids_limit
    assert exc == "BlockingIOError"


def test_memory_cap_kills(run_script):
    res = run_script(
        "chunks = []\n"
        "for i in range(64):\n"
        "    chunks.append(b'x' * (32 << 20)); print(len(chunks) * 32, flush=True)\n"
        "print('SURVIVED 2 GB')\n"
    )
    assert not res.timed_out
    assert res.exit_code == 137
    assert "SURVIVED" not in res.stdout
    peak = int(res.script_stdout.split()[-1])
    assert 256 <= peak <= 512


def test_timeout_kills_and_container_is_gone(run_script, runner):
    res = run_script("import time\nprint('sleeping', flush=True)\ntime.sleep(600)\n", timeout=4)
    assert res.timed_out
    assert res.exit_code == TIMEOUT_EXIT
    assert res.duration < 20
    assert "sleeping" in res.stdout  # output produced before the kill is kept
    assert res.removed
    assert not runner.container_exists(res.container)
    assert runner.containers_for("test") == []


def test_output_is_capped(run_script, sandbox_settings):
    res = run_script("import sys\nsys.stdout.write('A' * (2 << 20))\nsys.stderr.write('B' * (1 << 20))\n")
    assert res.exit_code == 0
    assert res.truncated
    assert len(res.stdout.encode()) + len(res.stderr.encode()) <= sandbox_settings.output_cap


def test_every_container_is_removed_after_each_step(run_script, runner):
    res = run_script("print('hi')\n")
    assert res.exit_code == 0 and res.removed
    assert runner.containers_for("test") == []


def test_fetch_then_offline_install(runner):
    job = "fetchtest"
    try:
        wheels = runner.wheels_dir(job, "1.17.0")
        f = runner.fetch(job, "six==1.17.0", wheels)
        assert f.exit_code == 0, f.stderr
        assert any(p.name.startswith("six-1.17.0") and p.suffix == ".whl" for p in wheels.iterdir())
        assert "/repro" not in " ".join(f.flags)  # no script is mounted during the networked phase
        assert "--network" not in f.flags
        script = runner.write_script(job, 0, "import six, socket\nprint('six', six.__version__)\n")
        r = runner.run(job, script, wheels_dir=wheels, requirement="six==1.17.0")
        assert r.exit_code == 0, r.stderr
        assert r.installed_version == "1.17.0"
        assert "six 1.17.0" in r.script_stdout
        assert ["--network", "none"] == r.flags[r.flags.index("--network"):r.flags.index("--network") + 2]
        assert f"{wheels}:/wheels:ro".replace(str(runner.work_root), "$WORK_ROOT") in r.flags
    finally:
        runner.cleanup_job(job)
    assert not (runner.work_root / job).exists()


def test_install_failure_is_setup_failure(runner):
    job = "setupfail"
    try:
        wheels = runner.wheels_dir(job, "empty")  # nothing fetched
        script = runner.write_script(job, 0, "print('never runs')\n")
        r = runner.run(job, script, wheels_dir=wheels, requirement="six==1.17.0")
        assert r.setup_failed
        assert not r.script_started
    finally:
        runner.cleanup_job(job)


@pytest.mark.parametrize("bad", ["six", "six>=1", "six==1.0; rm -rf /", "-r/etc/passwd==1", "six==1 --index-url=http://x"])
def test_unpinned_or_malformed_requirements_are_refused(runner, bad):
    with pytest.raises(ValueError):
        runner.fetch("refuse", bad, runner.work_root)


def test_janitor_removes_labelled_leftovers(runner, sandbox_settings):
    name = "reproroom-janitor-test"
    subprocess.run([sandbox_settings.cli, "rm", "-f", name], capture_output=True)
    created = subprocess.run(
        [sandbox_settings.cli, "create", "--name", name, "--label", "reproroom=1", "--label", "reproroom.job=jan",
         sandbox_settings.image, "true"], capture_output=True, text=True)
    assert created.returncode == 0, created.stderr
    (runner.work_root / "stale-job").mkdir(exist_ok=True)
    swept = runner.janitor()
    assert swept["containers_removed"] >= 1
    assert not runner.container_exists(name)
    assert not (runner.work_root / "stale-job").exists()


def test_containment_drill_fixture(runner):
    """The hostile fixture, run for real: every attack is contained and the host keeps its secrets."""
    job = "drilltest"
    try:
        wheels = runner.wheels_dir(job, "drill")
        assert runner.fetch(job, drill.DRILL_PACKAGE, wheels).exit_code == 0
        script = runner.write_script(job, 0, drill.fixture_script())
        res = runner.run(job, script, wheels_dir=wheels, requirement=drill.DRILL_PACKAGE)
    finally:
        runner.cleanup_job(job)
    attacks, interrupted, finished = drill.parse_attacks(res.script_stdout)
    names = {a["attack"] for a in attacks}
    assert finished and interrupted is None, res.stderr[-2000:]
    assert {"Read environment variables", "Phone home", "Fork bomb", "rm -rf ~", "rm -rf /", "Memory bomb"} <= names
    escaped = [a for a in attacks if not a["contained"]]
    assert escaped == []
    by = {a["attack"]: a["observed"] for a in attacks}
    assert "refused" in by["Fork bomb"]
    assert "OOM" in by["Memory bomb"]
    assert "Read-only file system" in by["rm -rf /"]
    assert drill.leaked_secrets(res.stdout, res.stderr) == 0
    assert res.removed
