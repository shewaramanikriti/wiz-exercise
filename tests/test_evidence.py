import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("checks", ROOT / "scripts/evidence_checks.py")
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)

NODE = {"spec": {"providerID": "aws:///us-east-1a/i-abc123"}, "status": {
    "conditions": [{"type": "Ready", "status": "True"}],
    "addresses": [{"type": "InternalIP", "address": "10.0.16.5"}]}}
INSTANCE = {"InstanceId": "i-abc123", "SubnetId": "subnet-private-a"}
CIDRS = {"10.0.16.0/20", "10.0.32.0/20"}


class EvidenceTests(unittest.TestCase):
    def helper(self, node_data, instances=None, kubectl_exit=0, aws_exit=0):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "nodes.json").write_text(json.dumps(node_data))
            (p / "instances.json").write_text(json.dumps({
                "Reservations": [{"Instances": instances if instances is not None else [INSTANCE]}]}))
            for name, body in {
                "kubectl": 'cat "$FIXTURES/nodes.json"; exit "$KUBECTL_EXIT"',
                "aws": 'cat "$FIXTURES/instances.json"; exit "$AWS_EXIT"',
            }.items():
                f = p / name
                f.write_text("#!/bin/sh\n" + body + "\n")
                f.chmod(0o700)
            env = dict(os.environ, PATH=f"{d}:{os.environ['PATH']}", FIXTURES=d,
                       KUBECTL_EXIT=str(kubectl_exit), AWS_EXIT=str(aws_exit),
                       PRIVATE_SUBNET_1="subnet-private-a", PRIVATE_SUBNET_2="subnet-private-b")
            return subprocess.run(["bash", "-c", 'source "$1"; nodes_private', "test",
                                   str(ROOT / "scripts/verify_helpers.sh")],
                                  env=env, capture_output=True).returncode

    def test_ready_private_node_with_matching_ec2_evidence_passes(self):
        self.assertEqual(self.helper({"items": [NODE]}), 0)

    def test_failed_kubectl_with_even_valid_output_does_not_pass(self):
        self.assertNotEqual(self.helper({"items": [NODE]}, kubectl_exit=1), 0)

    def test_failed_aws_with_even_valid_output_does_not_pass(self):
        self.assertNotEqual(self.helper({"items": [NODE]}, aws_exit=1), 0)

    def test_empty_cluster_is_not_evidence_of_private_nodes(self):
        self.assertNotEqual(self.helper({"items": []}), 0)

    def test_missing_kubernetes_evidence_does_not_pass(self):
        self.assertNotEqual(self.helper({"message": "Forbidden"}), 0)

    def test_public_ec2_ip_is_detected_without_kubernetes_externalip(self):
        self.assertNotEqual(self.helper({"items": [NODE]}, [dict(INSTANCE, PublicIpAddress="192.0.2.5")]), 0)

    def test_wrong_subnet_does_not_pass(self):
        self.assertNotEqual(self.helper({"items": [NODE]}, [dict(INSTANCE, SubnetId="subnet-public")]), 0)

    def test_unready_node_does_not_pass(self):
        node = copy.deepcopy(NODE)
        node["status"]["conditions"][0]["status"] = "False"
        self.assertNotEqual(self.helper({"items": [node]}), 0)

    def sg(self, extra=None):
        rules = [{"IpProtocol": "tcp", "FromPort": 27017, "ToPort": 27017,
                  "IpRanges": [{"CidrIp": c} for c in sorted(CIDRS)]}]
        groups = [{"IpPermissions": rules}]
        if extra:
            groups.append({"IpPermissions": [extra]})
        return {"SecurityGroups": groups}

    def test_database_private_cidrs_pass(self):
        self.assertTrue(checks.mongo_sg_is_restricted(self.sg(), CIDRS))

    def test_second_security_group_cannot_open_database(self):
        extra = {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        self.assertFalse(checks.mongo_sg_is_restricted(self.sg(extra), CIDRS))

    def test_ipv6_bypass_is_detected(self):
        extra = {"IpProtocol": "tcp", "FromPort": 27017, "ToPort": 27017,
                 "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}
        self.assertFalse(checks.mongo_sg_is_restricted(self.sg(extra), CIDRS))

    def test_empty_security_group_result_fails(self):
        self.assertFalse(checks.mongo_sg_is_restricted({"SecurityGroups": []}, CIDRS))

    def test_empty_or_zero_byte_backup_is_not_readability_evidence(self):
        for data in [{}, {"Contents": []}, {"Contents": [{"Key": "backups/a.archive.gz", "Size": 0}]}]:
            result = subprocess.run(["python3", str(ROOT / "scripts/evidence_checks.py"), "backup-key"],
                                    input=json.dumps(data), text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
