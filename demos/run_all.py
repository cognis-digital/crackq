"""Run every runnable demo scenario end to end.

    PYTHONUTF8=1 python demos/run_all.py

Each scenario is independent and builds its own throwaway queue + audit log over
the bundled wordlist, so they can be run in any order or on their own. Every
demo is OFFLINE and uses the real crackq API -- no network, no external engine.
"""
import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

SCENARIOS = [
    "01_red_team_recovery",
    "02_secops_priority_queue",
    "03_ir_audit_chain",
    "04_platform_admin_capacity",
    "05_cli_pipeline",
    "06_hash_type_detection",
    "07_job_cancellation",
    "08_queue_metrics",
    "09_algorithm_coverage",
    "10_rules_vs_norules",
    "11_max_candidates_budget",
    "12_error_handling",
    "13_multi_tenant_fairness",
    "14_audit_replay",
    "15_wordlist_file",
    "16_scan_entrypoint",
    "17_cli_detect",
    "18_cli_metrics",
    "19_password_policy_report",
    "20_end_to_end_service",
]


def main() -> int:
    for name in SCENARIOS:
        mod = importlib.import_module(name)
        mod.main()
    print("\n" + "=" * 70)
    print("  All demo scenarios completed.")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
