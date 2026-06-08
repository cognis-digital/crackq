"""Smoke tests for CRACKQ. No network. Pure stdlib."""
import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crackq import (  # noqa: E402
    CrackQ,
    AuditLog,
    AuditError,
    JobState,
    crack_hash,
    supported_algorithms,
    TOOL_NAME,
    TOOL_VERSION,
)
from crackq.cli import main  # noqa: E402


class TestCore(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "crackq")
        self.assertTrue(TOOL_VERSION)
        self.assertIn("sha256", supported_algorithms())

    def test_crack_base_word(self):
        digest = hashlib.md5(b"hunter").hexdigest()
        res = crack_hash(digest, ["admin", "hunter", "root"], rules=False)
        self.assertTrue(res["cracked"])
        self.assertEqual(res["plaintext"], "hunter")
        self.assertEqual(res["algorithm"], "md5")

    def test_crack_with_rules(self):
        # 'letmein!' is reachable only via the append-'!' rule from 'letmein'
        digest = hashlib.sha256(b"letmein!").hexdigest()
        miss = crack_hash(digest, ["letmein"], rules=False)
        self.assertFalse(miss["cracked"])
        hit = crack_hash(digest, ["letmein"], rules=True)
        self.assertTrue(hit["cracked"])
        self.assertEqual(hit["plaintext"], "letmein!")

    def test_exhausted(self):
        digest = hashlib.sha1(b"not-in-list").hexdigest()
        res = crack_hash(digest, ["a", "b", "c"], rules=False)
        self.assertFalse(res["cracked"])
        self.assertIsNone(res["plaintext"])

    def test_unknown_algorithm_raises(self):
        with self.assertRaises(ValueError):
            crack_hash("deadbeef", ["x"])  # length not a known digest

    def test_auto_detect(self):
        digest = hashlib.sha512(b"top").hexdigest()
        res = crack_hash(digest, ["top"], rules=False)
        self.assertEqual(res["algorithm"], "sha512")
        self.assertTrue(res["cracked"])


class TestQueueAndAudit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.audit_path = os.path.join(self.tmp, "audit.jsonl")

    def test_priority_and_run(self):
        q = CrackQ(self.audit_path, wordlist=["alpha", "bravo"])
        low = q.submit(hashlib.md5(b"bravo").hexdigest(), "u1", priority=9)
        high = q.submit(hashlib.md5(b"alpha").hexdigest(), "u2", priority=1)
        done = q.run_all()
        # high priority job runs first
        self.assertEqual(done[0].id, high.id)
        self.assertEqual(done[0].state, JobState.CRACKED)
        self.assertEqual(done[0].plaintext, "alpha")
        self.assertEqual(low.state, JobState.CRACKED)

    def test_audit_chain_verifies(self):
        q = CrackQ(self.audit_path, wordlist=["secret"])
        q.submit(hashlib.sha256(b"secret").hexdigest(), "analyst")
        q.run_all()
        log = AuditLog(self.audit_path)
        self.assertTrue(log.verify())
        self.assertGreaterEqual(len(log.entries()), 3)  # submit, start, crack

    def test_audit_tamper_detected(self):
        q = CrackQ(self.audit_path, wordlist=["secret"])
        q.submit(hashlib.sha256(b"secret").hexdigest(), "analyst")
        q.run_all()
        # tamper: rewrite a user field in the first record
        with open(self.audit_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        lines[0] = lines[0].replace('"analyst"', '"mallory"')
        with open(self.audit_path, "w", encoding="utf-8") as f:
            f.writelines(lines)
        with self.assertRaises(AuditError):
            AuditLog(self.audit_path).verify()


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.audit_path = os.path.join(self.tmp, "audit.jsonl")

    def test_run_json_success(self):
        digest = hashlib.md5(b"welcome").hexdigest()
        rc = main([
            "--format", "json", "--audit-log", self.audit_path,
            "run", "--hash", digest, "--words", "welcome", "admin",
        ])
        self.assertEqual(rc, 0)

    def test_run_no_hashes_fails(self):
        rc = main([
            "--audit-log", self.audit_path, "run", "--words", "x",
        ])
        self.assertEqual(rc, 2)

    def test_algos(self):
        rc = main(["--format", "json", "algos"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
