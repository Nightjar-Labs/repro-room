# Local smoke test: 2026-11-05

Everything below was observed by running the real app (`uv run repro-room`) and submitting jobs over HTTP,
then reading `/api/jobs/<id>`. Nothing is inferred.

**Setup.** NixOS host, rootless Podman 5.8.9 with crun (`SANDBOX_RUNTIME_CLI=podman`, default OCI runtime),
image `docker.io/library/python:3.12-slim@sha256:1148dbb014615300fa7e713b2f94f550c0d1c69780c0805f84f093ceee34dd0b`.
LLM: Gemini's OpenAI-compatible endpoint, model `gemini-3.5-flash-lite` (dev stand-in for Vultr Serverless
Inference; same client code, only `LLM_*` env differs). GitHub unauthenticated. Jobs ran one at a time.
Times are wall clock per job from the job record; "LLM" is the sum of the job's model call durations.

## Final verdict rules: results (job ids `d56a2c1792`, `1b4efe4a65`, `fcc7e484fd`, `6e096ca37e`, `e789309b88`)

| Issue | Expected (SHORTLIST.md) | Observed verdict | Runs | Job time | LLM |
|---|---|---|---|---|---|
| python-poetry/tomlkit#442 | Reproduced at 0.13.3, fixed in 0.15.x | **Already fixed in v0.15.2** | 0.13.3: `REPRO: BUG` (2.7 s); 0.15.2: `REPRO: OK` (2.6 s) | 27.1 s | 17.5 s |
| jd/tenacity#658 | Reproduced at 9.1.4, fixed in 9.2.1 | **Already fixed in v9.2.1** | 9.1.4: killed by the 60 s wall clock, exit 124 (60.1 s); 9.2.1: finished, exit 0 (2.8 s) | 102.5 s | 28.7 s |
| Textualize/rich#4234 | Reproduced on latest (15.0.0); open | **Still present on latest v15.0.0** | 15.0.0: `REPRO: BUG` (3.4 s) | 16.0 s | 8.7 s |
| marshmallow-code/marshmallow#2831 | Not reproduced at 3.23.1 | **Still present on latest v4.4.0** (disagrees, see below) | 3.23.1: `REPRO: BUG` (5.7 s); 4.4.0: `REPRO: BUG` (6.6 s) | 32.9 s | 15.5 s |
| Containment drill | all attacks contained | **Contained**: 11/11 attacks, 5/5 host checks | hostile run exit 0 (8.9 s) | 15.1 s | none |

Stability with the final verdict rules (4 rounds; every completed job listed):

| Issue | Verdicts observed | Job times |
|---|---|---|
| tomlkit#442 | Already fixed in v0.15.2 ×3 | 27.1, 35.3, 82.2 s; a 4th submission was lost to an LLM 503 (below) |
| tenacity#658 | Already fixed in v9.2.1 ×4 | 98.5, 102.5, 106.5, 114.5 s |
| rich#4234 | Still present on latest v15.0.0 ×4 | 16.0, 20.2, 28.0, 30.0 s |
| marshmallow#2831 | Still present on latest v4.4.0 ×4 | 14.4, 32.9, 61.7, 75.9 s; 2 more submissions lost to LLM 503s |
| Containment drill | Contained in all 5 drills of the session (the drill path did not change between rounds) | 7.9, 9.1, 11.9, 15.1, 15.1 s |

The repair loop did not trigger in any live run: the script writer stripped the `>>>` prompts of tomlkit#442
itself (as the spec's step 3 asks) and marked those lines, so the first script already ran. The repair path is
covered by `tests/test_pipeline.py`, which feeds a script with `>>>` prompts through the real sandbox: attempt 1
fails with `SyntaxError` at 0.13.3, one repair, then `bug` at 0.13.3 and `ok` at 0.15.2 → "Already fixed in v0.15.2".

## Containment drill (job `e789309b88`, attacker's view, verbatim from the sandbox)

| Attack | Observed inside the sandbox |
|---|---|
| Read environment variables | 5 variables: HOME, LANG, PATH, PYTHONDONTWRITEBYTECODE, PYTHONUNBUFFERED. Control-plane secrets present: none |
| Read /proc/1/environ | PID 1 is the sandbox's own init (`/run/podman-init`), 13 image/setup variables, no control-plane secrets |
| Phone home | DNS: `Temporary failure in name resolution`; TCP 1.1.1.1:443: `Network is unreachable`; urllib: name resolution failure; `curl … \| sh`: `curl: not found` |
| Look for the host | no runtime sockets, `/home` empty, hostname is the container's |
| Become root | uid 65534; `setuid(0)`: Operation not permitted; `/etc/shadow`: Permission denied; `mount`: must be superuser |
| Tamper with the system | `/etc/passwd`, `os.py`, `/repro/repro.py`: Permission denied; `/wheels`, `/`: Read-only file system |
| Fill the disk | stopped after 255 MB: No space left on device (256 MB tmpfs) |
| Fork bomb | fork #126 refused: `BlockingIOError` (pids limit 128) |
| rm -rf ~ | `/work` emptied (2 entries → 0), `/work` itself: Read-only file system; throwaway tmpfs |
| rm -rf / | 69 530 "Read-only file system" and 1 043 "Permission denied" errors; `/usr/local/bin/python3`, `/etc/passwd`, `/bin/sh` still present |
| Memory bomb | killed by SIGKILL (OOM killer) after ~448 MB, in 0.3 s |

Host's view: container gone after the step; 0 leftover labelled containers; 4 secret values held by the control
plane (env + key file), 0 found in sandbox output; host canary file sha256 `2670c3e4ea15bf60` before and after;
`/healthz` 200 before (140 ms) and after (8 ms).

## Where the agent disagreed, and what was done

1. **tenacity#658, rounds 1 and 3 (our fault, fixed).** Round 1: at 9.2.1 the call ends by re-raising
   `ValueError: inner` (intended, `reraise=True`), the script did not catch it, and the old rules called that
   "inconclusive" → verdict "Reproduced" instead of "Already fixed". Round 3: the model printed `REPRO: BUG`
   unconditionally after the call returned → "Still present". Fix in `verdict.py`: for a claimed hang the
   observable is termination (killed by the wall clock = bug, finished in time = no hang) and markers are
   ignored; the prompt was clarified too. Every later round: "Already fixed in v9.2.1".
2. **marshmallow#2831, rounds 2 and 3 (our fault, fixed).** The reporter's last snippet line,
   `field.deserialize("yes")  # Expect: ValidationError`, raises by design; the model kept it unguarded, the script
   died before its check and the verdict was "Inconclusive". Fixes: the prompt now requires guarding lines the
   reporter marks as expected to raise, and a wrong-output script stopped by an uncaught exception before printing
   a marker is now a repairable script error (repair loop, max 2) instead of a final "inconclusive".
3. **marshmallow#2831, the expected verdict itself (SHORTLIST.md is wrong).** Repro Room says the claimed
   behaviour *is* present at 3.23.1 and at 4.4.0: `deserialize(1)` returns `True` and `deserialize(0)` returns
   `False` (`1 in {True}` is true in Python). I re-ran the October `logs/marshmallow-2831/fixed.py` by hand in
   `python:3.12-slim` with marshmallow 3.23.1: it prints `True`, `False`, `True`, `False`, then the
   `ValidationError` comes from the `"yes"` line, which the reporter expects. The October logs only contain the
   `SyntaxError` from the unstripped `> ` prompts, so the "both reject 1 with ValidationError" note was a
   misreading. The verdict "Still present on latest v4.4.0" matches the observed behaviour; whether maintainers
   consider it a bug (the issue is closed) is a separate question. This issue no longer demonstrates
   "not reproduced"; another example is needed for that beat of the demo.
4. **rich#4234 version.** The issue reports "Rich master (declared version 15.0.0)", so extraction returned no
   released version and only latest (15.0.0) ran. Verdict as expected.
5. **Draft comments (fixed).** The model wrapped the `{{SCRIPT}}` placeholder in a code fence, giving nested
   fences; fenced placeholders are now unwrapped before filling (test added).
6. **Added-line marking.** The model sometimes marks verbatim snippet lines as added or forgets to mark
   prompt-stripped lines. Line kinds are now computed by diffing against the snippet, not taken from the model.

## Failures not caused by Repro Room

- 3 jobs failed at "Extract facts" with `HTTP 503: This model is currently experiencing high demand` from the
  Gemini endpoint after all retries. They are recorded as failed/inconclusive with the provider message; the
  client now retries 3 times with 3/6/12 s backoff. Re-submitting succeeded.

## UI

Headless Chromium (CDP): clicked "Run containment drill" on the home page; the job page opened with 1 timeline
step and "Running", then updated itself by polling to 6 steps and the "Contained" badge without a reload, with
no JavaScript errors (CSP `script-src 'self'`). On a finished job, "Copy comment" put the 1 068-character draft
on the clipboard and showed "Copied. Review it before posting."

## Test suite

- `uv run pytest`: 108 passed, 1 deselected (live), ~50 s, real Podman sandboxes.
- `uv run pytest -m live` (Gemini, tomlkit#442 end to end): first run failed (`draft_comment` was `None`, i.e.
  the explanation call failed; its cause was not captured, during the same period as the 503s above); second
  run passed in 17.6 s. The assertion now reports the failed timeline step.

## Not covered here

- Docker/gVisor on the Vultr VM (`deploy/setup-vm.sh` was syntax-checked and shellchecked, the Caddyfile
  template validated with `caddy adapt`, but the script has not been run on a VM).
- The production model `glm-5.3` on Vultr Serverless Inference (no key on this host); prompt behaviour may
  differ from `gemini-3.5-flash-lite`.
