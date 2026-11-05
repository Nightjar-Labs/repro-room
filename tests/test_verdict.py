"""Deterministic verdict rules, table-driven."""

import pytest

from reproroom.verdict import (BUG, INCONCLUSIVE, OK, SCRIPT_ERROR, SETUP_FAILED, RunClass, RunObservation,
                               classify_run, decide, parse_exception)

TB = 'Traceback (most recent call last):\n  File "/repro/repro.py", line {line}, in <module>\n    x()\n'
TB_PKG = TB + '  File "/work/venv/lib/python3.12/site-packages/rich/text.py", line 9, in wrap\n    y()\n'
SYNTAX = '  File "/repro/repro.py", line 1\n    >>> import tomlkit\n    ^^\nSyntaxError: invalid syntax\n'

CLASSIFY = [
    # id, observation, symptom, expected_exception, expected kind
    ("marker-bug", RunObservation(0, stdout="True: false\nREPRO: BUG\n"), "wrong_output", None, BUG),
    ("marker-bug-nonzero-exit", RunObservation(1, stdout="REPRO: BUG\n", stderr=TB.format(line=3) + "KeyError: 'x'\n"), "wrong_output", None, BUG),
    ("marker-ok", RunObservation(0, stdout="REPRO: OK\n"), "wrong_output", None, OK),
    ("marker-ok-but-crashed", RunObservation(1, stdout="REPRO: OK\n", stderr=TB.format(line=3) + "ValueError: x\n"), "wrong_output", None, INCONCLUSIVE),
    ("both-markers", RunObservation(0, stdout="REPRO: BUG\nREPRO: OK\n"), "wrong_output", None, INCONCLUSIVE),
    ("marker-must-be-whole-line", RunObservation(0, stdout="print('REPRO: BUG') would say REPRO: BUG\n"), "wrong_output", None, INCONCLUSIVE),
    ("hang-claimed-timeout", RunObservation(124, timed_out=True), "hang", None, BUG),
    ("hang-not-claimed-timeout", RunObservation(124, timed_out=True), "exception", "ValueError", INCONCLUSIVE),
    ("timeout-before-script", RunObservation(124, timed_out=True, script_started=False), "hang", None, SETUP_FAILED),
    ("timeout-after-bug-marker", RunObservation(124, timed_out=True, stdout="REPRO: BUG\n"), "wrong_output", None, BUG),
    ("hang-claimed-returned", RunObservation(0, stdout="done\n"), "hang", None, OK),
    ("hang-claimed-returned-by-raising", RunObservation(1, stderr=TB_PKG + "ValueError: inner\n"), "hang", None, OK),
    ("hang-claimed-script-error-still-repairable", RunObservation(1, stderr=SYNTAX), "hang", None, SCRIPT_ERROR),
    ("hang-claimed-markers-ignored", RunObservation(0, stdout="REPRO: BUG\n"), "hang", None, OK),
    ("hang-claimed-timeout-markers-ignored", RunObservation(124, timed_out=True, stdout="REPRO: OK\n"), "hang", None, BUG),
    ("wrong-output-stopped-by-uncaught-exception", RunObservation(1, stdout="True\n", stderr=TB_PKG + "ValidationError: Not a valid boolean.\n"), "wrong_output", None, SCRIPT_ERROR),
    ("expected-exception-raised-in-package", RunObservation(1, stderr=TB_PKG + "ValueError: range() arg 3 must not be zero\n"), "exception", "ValueError", BUG),
    ("expected-exception-qualified-name", RunObservation(1, stderr=TB_PKG + "marshmallow.exceptions.ValidationError: bad\n"), "exception", "marshmallow.exceptions.ValidationError", BUG),
    ("other-exception", RunObservation(1, stderr=TB_PKG + "TypeError: nope\n"), "exception", "ValueError", INCONCLUSIVE),
    ("exception-claimed-clean-exit", RunObservation(0, stdout="fine\n"), "exception", "ValueError", OK),
    ("wrong-output-no-marker", RunObservation(0, stdout="fine\n"), "wrong_output", None, INCONCLUSIVE),
    ("syntax-error-in-script", RunObservation(1, stderr=SYNTAX), "wrong_output", None, SCRIPT_ERROR),
    ("name-error-in-script", RunObservation(1, stderr=TB.format(line=4) + "NameError: name 'helper' is not defined\n"), "exception", "ValueError", SCRIPT_ERROR),
    ("name-error-inside-package", RunObservation(1, stderr=TB_PKG + "NameError: name 'q' is not defined\n"), "exception", "ValueError", INCONCLUSIVE),
    ("import-error-unrelated", RunObservation(1, stderr=TB.format(line=1) + "ModuleNotFoundError: No module named 'numpy'\n"), "exception", "ValueError", SCRIPT_ERROR),
    ("import-error-target", RunObservation(1, stderr=TB.format(line=1) + "ModuleNotFoundError: No module named 'rich.foo'\n"), "exception", "ValueError", INCONCLUSIVE),
    ("oom-killed", RunObservation(137), "exception", "ValueError", INCONCLUSIVE),
    ("segfault-claimed", RunObservation(139), "crash", None, BUG),
    ("setup-failed", RunObservation(97, setup_failed=True), "exception", "ValueError", SETUP_FAILED),
    ("runtime-error", RunObservation(125), "exception", "ValueError", INCONCLUSIVE),
]


@pytest.mark.parametrize("obs,symptom,expected_exc,kind", [c[1:] for c in CLASSIFY], ids=[c[0] for c in CLASSIFY])
def test_classify_run(obs, symptom, expected_exc, kind):
    got = classify_run(obs, symptom=symptom, expected_exception=expected_exc, target_modules=["rich", "rich"])
    assert got.kind == kind, got.reason


B, O = RunClass(BUG, "b"), RunClass(OK, "o")
I, S = RunClass(INCONCLUSIVE, "i"), RunClass(SETUP_FAILED, "s")
DECIDE = [
    # affected, latest, affected_version, expected code, label fragment
    (B, O, "0.13.3", "already_fixed", "Already fixed in v0.15.2"),
    (B, B, "0.13.3", "still_present", "Still present on latest v0.15.2"),
    (B, I, "0.13.3", "reproduced", "Reproduced"),
    (B, S, "0.13.3", "reproduced", "Reproduced"),
    (O, O, "0.13.3", "not_reproduced", "Not reproduced"),
    (O, B, "0.13.3", "reproduced", "Reproduced"),
    (O, I, "0.13.3", "not_reproduced", "Not reproduced"),
    (S, B, "0.13.3", "still_present", "Still present"),
    (S, O, "0.13.3", "inconclusive", "Inconclusive"),
    (I, I, "0.13.3", "inconclusive", "Inconclusive"),
    (None, B, None, "still_present", "Still present on latest v0.15.2"),
    (None, O, None, "not_reproduced", "Not reproduced"),
    (None, I, None, "inconclusive", "Inconclusive"),
    (None, B, "0.15.2", "still_present", "Still present"),
]


@pytest.mark.parametrize("affected,latest,av,code,label", DECIDE)
def test_decide(affected, latest, av, code, label):
    v = decide(affected, latest, affected_version=av, latest_version="0.15.2")
    assert v.code == code
    assert label in v.label


def test_decide_without_latest_is_inconclusive():
    assert decide(B, None, affected_version="1", latest_version="2").code == "inconclusive"


def test_parse_exception_variants():
    e = parse_exception(SYNTAX)
    assert e.name == "SyntaxError" and e.in_script
    e = parse_exception(TB_PKG + "ValueError: range() arg 3 must not be zero\n")
    assert (e.name, e.message, e.in_script) == ("ValueError", "range() arg 3 must not be zero", False)
    e = parse_exception(TB.format(line=2) + "KeyError: 'a'\n\nDuring handling of the above exception, another exception occurred:\n\n"
                        + TB_PKG + "RuntimeError\n")
    assert e.name == "RuntimeError" and not e.in_script
    assert parse_exception("just some output\nError: not a traceback\n") is None
    assert parse_exception("") is None
