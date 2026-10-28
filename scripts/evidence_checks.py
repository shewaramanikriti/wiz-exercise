"""Validate positive evidence; empty or malformed responses never count as PASS."""
import json
import re
import sys


def nodes_are_ready_and_private(data):
    nodes = data["items"]
    return bool(nodes) and all(
        any(c["type"] == "Ready" and c["status"] == "True"
            for c in n["status"]["conditions"])
        and not any(a["type"] == "ExternalIP" for a in n["status"]["addresses"])
        and re.fullmatch(r"aws:///[^/]+/i-[0-9a-f]+", n["spec"]["providerID"])
        for n in nodes
    )


def instances_are_private(data, subnets, expected_ids):
    instances = [i for r in data["Reservations"] for i in r["Instances"]]
    return (bool(instances)
            and {i["InstanceId"] for i in instances} == set(expected_ids)
            and all(i["SubnetId"] in subnets and not i.get("PublicIpAddress")
                    and not any(eni.get("Association", {}).get("PublicIp")
                                for eni in i.get("NetworkInterfaces", []))
                    for i in instances))


def mongo_sg_is_restricted(data, allowed_cidrs):
    permitted = set()
    groups = data["SecurityGroups"]
    if not groups:
        return False
    for group in groups:
        for rule in group["IpPermissions"]:
            protocol = rule["IpProtocol"]
            opens_mongo = protocol == "-1" or (
                protocol in ("tcp", "6") and rule["FromPort"] <= 27017 <= rule["ToPort"])
            if not opens_mongo:
                continue
            # This implementation deliberately uses exactly the two private CIDRs.
            if rule.get("Ipv6Ranges") or rule.get("UserIdGroupPairs") or rule.get("PrefixListIds"):
                return False
            for entry in rule.get("IpRanges", []):
                permitted.add(entry["CidrIp"])
    return permitted == set(allowed_cidrs)


def main():
    try:
        data = json.load(sys.stdin)
        mode, *args = sys.argv[1:]
        if mode == "nodes":
            result = nodes_are_ready_and_private(data)
        elif mode == "instance-ids":
            if not nodes_are_ready_and_private(data):
                return 1
            print(" ".join(n["spec"]["providerID"].rsplit("/", 1)[1] for n in data["items"]))
            return 0
        elif mode == "instances":
            result = instances_are_private(data, set(args[:2]), args[2:])
        elif mode == "mongo-sg":
            result = mongo_sg_is_restricted(data, set(args))
        elif mode == "backup-key":
            keys = [o["Key"] for o in data.get("Contents", [])
                    if o["Key"].startswith("backups/") and o["Key"].endswith(".archive.gz")
                    and o["Size"] > 0]
            if not keys:
                return 1
            print(sorted(keys)[-1])
            return 0
        else:
            return 2
        return 0 if result else 1
    except (KeyError, ValueError, TypeError, IndexError):
        return 2


if __name__ == "__main__":
    sys.exit(main())
