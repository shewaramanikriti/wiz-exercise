"""Exercise release failure paths using local fake CLIs; no AWS mutations."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
DIGEST = "sha256:" + "a" * 64


class PublishTests(unittest.TestCase):
    def publish(self, attempt="1", corrupt=False, push_exit="0", digest=DIGEST):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)
            artifact = b"this-is-the-scanned-image-archive"
            (path / "image.tar.gz").write_bytes(artifact + (b"modified" if corrupt else b""))
            (path / "image.tar.gz.sha256").write_text(hashlib.sha256(artifact).hexdigest() + "  image.tar.gz\n")
            (path / "docker").write_text('''#!/usr/bin/env python3
import hashlib, json, os, sys
with open(os.environ["CALLS"], "a") as f:
    f.write(json.dumps(["docker", *sys.argv[1:]]) + "\\n")
if sys.argv[1] == "load":
    data = sys.stdin.buffer.read()
    with open(os.environ["LOADED_SHA"], "w") as f: f.write(hashlib.sha256(data).hexdigest())
if sys.argv[1] == "push": sys.exit(int(os.environ["PUSH_EXIT"]))
''')
            (path / "aws").write_text('''#!/usr/bin/env python3
import json, os, sys
with open(os.environ["CALLS"], "a") as f:
    f.write(json.dumps(["aws", *sys.argv[1:]]) + "\\n")
print(os.environ["DIGEST"])
''')
            (path / "docker").chmod(0o700)
            (path / "aws").chmod(0o700)
            env = dict(os.environ, PATH=f"{d}:{os.environ['PATH']}", CALLS=str(path / "calls"),
                       LOADED_SHA=str(path / "loaded"), PUSH_EXIT=push_exit, DIGEST=digest,
                       REPO_URI="123456789012.dkr.ecr.us-east-1.amazonaws.com/wiz/tasky",
                       PROJECT="wiz", LOCAL_IMAGE="tasky:test", GITHUB_ENV=str(path / "env"),
                       SOURCE_SHA="b" * 40, GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT=attempt)
            result = subprocess.run(["bash", str(ROOT / "scripts/publish-image.sh")],
                                    cwd=d, env=env, capture_output=True, text=True)
            def read(name):
                p = path / name
                return p.read_text() if p.exists() else ""
            return result.returncode, read("env"), read("calls"), read("loaded")

    def test_scanned_archive_is_loaded_and_result_is_digest_pinned(self):
        code, env, calls, loaded = self.publish()
        self.assertEqual(code, 0)
        self.assertTrue(env.endswith("@" + DIGEST + "\n"))
        self.assertEqual(loaded, hashlib.sha256(b"this-is-the-scanned-image-archive").hexdigest())
        events = [json.loads(line) for line in calls.splitlines()]
        self.assertEqual([e[1] for e in events[:3]], ["load", "tag", "push"])
        self.assertEqual(events[3][0:3], ["aws", "ecr", "describe-images"])

    def test_rerun_of_same_commit_has_a_distinct_tag(self):
        first, second = self.publish(attempt="1"), self.publish(attempt="2")
        self.assertEqual((first[0], second[0]), (0, 0))
        self.assertIn("-123-1", first[2])
        self.assertIn("-123-2", second[2])

    def test_modified_archive_is_rejected_before_docker_or_aws(self):
        code, env, calls, _ = self.publish(corrupt=True)
        self.assertNotEqual(code, 0)
        self.assertEqual((env, calls), ("", ""))

    def test_push_failure_never_emits_deployment_image(self):
        code, env, calls, _ = self.publish(push_exit="17")
        self.assertNotEqual(code, 0)
        self.assertEqual(env, "")
        self.assertNotIn('"aws"', calls)

    def test_invalid_ecr_digest_never_emits_deployment_image(self):
        code, env, _, _ = self.publish(digest="None")
        self.assertNotEqual(code, 0)
        self.assertEqual(env, "")


if __name__ == "__main__":
    unittest.main()
