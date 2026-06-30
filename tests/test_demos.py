"""Tests that exercise the runnable demo scenarios.

Each demo uses the real crackq API offline; these run them as smoke tests
(they must not raise and must exercise the documented code paths) plus a few
direct assertions on the queue/audit behavior the demos rely on.
"""
import hashlib
import importlib
import io
import os
import sys
from contextlib import redirect_stdout

import pytest

DEMOS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "demos")
sys.path.insert(0, DEMOS)

SCENARIOS = [
    "01_red_team_recovery",
    "02_secops_priority_queue",
    "03_ir_audit_chain",
    "04_platform_admin_capacity",
    "05_cli_pipeline",
]


@pytest.mark.parametrize("name", SCENARIOS)
def test_scenario_runs_and_narrates(name):
    mod = importlib.import_module(name)
    buf = io.StringIO()
    with redirect_stdout(buf):
        mod.main()  # must not raise (demos assert their own invariants)
    out = buf.getvalue()
    assert len(out) > 100  # produced narrated output


def test_run_all_returns_zero():
    run_all = importlib.import_module("run_all")
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = run_all.main()
    assert rc == 0
    assert "All demo scenarios completed." in buf.getvalue()


def test_common_helpers_use_real_api():
    common = importlib.import_module("_common")
    q = common.fresh_queue()
    job = q.submit(common.sha256("monkey"), owner="tester")
    q.run_all()
    assert job.state.value == "cracked"
    assert job.plaintext == "monkey"
    # audit chain over the demo wordlist verifies
    assert common.AuditLog(q.audit.path).verify() is True


def test_priority_scheduling_matches_demo_claim():
    common = importlib.import_module("_common")
    q = common.fresh_queue()
    q.submit(common.md5("qwerty"), owner="routine", priority=5)
    incident = q.submit(common.md5("dragon"), owner="ciso", priority=1)
    done = q.run_all()
    assert done[0].id == incident.id  # priority-1 served first
