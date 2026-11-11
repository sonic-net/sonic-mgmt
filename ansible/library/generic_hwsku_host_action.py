#!/usr/bin/python
"""Own one fresh Generic PTF namespace and its exact VLANs; never adopt legacy host state."""

import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess

from generic_hwsku_device_action import atomic_bytes, atomic_json, digest, write_result


OWNER = "sonic.generic.scenario"
OPERATION = "sonic.generic.operation"
NAMESPACE_SYSCTLS = {
    "net.ipv6.conf.all.disable_ipv6": "0",
    "net.ipv6.conf.all.accept_ra": "0", "net.ipv6.conf.default.accept_ra": "0",
    "net.ipv4.conf.all.arp_ignore": "1", "net.ipv4.conf.default.arp_ignore": "1",
    "net.ipv4.conf.all.arp_announce": "2", "net.ipv4.conf.default.arp_announce": "2",
    "net.ipv4.conf.all.rp_filter": "0", "net.ipv4.conf.default.rp_filter": "0",
}


class HostActionError(ValueError):
    """Unverified host identity, ownership, or network state blocks an operation."""


def command(arguments, directory):
    result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        atomic_bytes(directory / "command-stderr.log", result.stderr)
        raise HostActionError("Host command failed (rc {}); private evidence: {}".format(
            result.returncode, directory / "command-stderr.log"))
    return result.stdout


def inspect_container(spec, directory):
    listing = command(["docker", "container", "ls", "--all", "--filter",
                       "name=^/" + re.escape(spec["container"]) + "$", "--format", "{{.ID}}"], directory)
    ids = listing.decode().splitlines()
    if not ids:
        return None
    if len(ids) != 1:
        raise HostActionError("The exact PTF name did not resolve uniquely")
    values = json.loads(command(["docker", "inspect", ids[0]], directory))
    if len(values) != 1 or values[0]["Name"].lstrip("/") != spec["container"]:
        raise HostActionError("Docker returned a different container identity")
    return values[0]


def addresses(rows):
    return sorted(
        "{}/{}".format(ipaddress.ip_address(address["local"]), address["prefixlen"])
        for row in rows for address in row.get("addr_info", []) if address.get("scope") == "global"
    )


def candidate_state(spec):
    """Build desired persistent state; capture() independently reads all corresponding values."""
    management = spec["management"]
    gateways = [{"family": family, "gateway": management[key], "dev": "mgmt"}
                for family, key in (("inet", "gateway"), ("inet6", "gateway_v6")) if management.get(key)]
    return {
        "container": {"name": spec["container"], "image_id": spec["image_id"],
                      "scenario": spec["scenario"], "running": True},
        "management": {"addresses": sorted(management["addresses"]), "gateways": gateways,
                       "bridge": management["bridge"], "mtu": management["mtu"], "paired": True, "up": True},
        "endpoints": sorted(
            [{"ptf_index": row["ptf_index"], "name": "eth" + str(row["ptf_index"]), "vlan": row["vlan"],
              "parent": spec["parent"], "mac": row["mac"], "mtu": spec["mtu"], "up": True,
              "addresses": [row["ptf_address"]]} for row in spec["endpoints"]],
            key=lambda row: row["ptf_index"]),
        "root_interfaces": [spec["management_root"]],
        "unowned_interfaces": [],
        "sysctls": dict(NAMESPACE_SYSCTLS),
    }


def validate_spec(spec):
    traffic = spec.get("traffic_available", spec.get("admission_level") != "deployment_smoke")
    if type(traffic) is not bool:
        raise HostActionError("Traffic availability must be a frozen boolean")
    if not traffic and (spec["endpoints"] or spec["traffic_cases"]):
        raise HostActionError("A no-path layout must not allocate traffic endpoints or cases")
    if re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", spec["scenario"]) is None:
        raise HostActionError("Invalid host scenario identity")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", spec["image_id"]) is None:
        raise HostActionError("PTF creation requires a verified installed immutable image ID")
    if traffic and re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", spec["router_mac"]) is None:
        raise HostActionError("The live DUT router MAC was not collected")
    if not isinstance(spec["mtu"], int) or not 576 <= spec["mtu"] <= 65535:
        raise HostActionError("A reviewed transport MTU is required")
    names = [spec["parent"], spec["management_root"], spec["management_peer"]]
    names += [row["host_interface"] for row in spec["endpoints"]]
    if len(names) != len(set(names)) or any(re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name) is None for name in names):
        raise HostActionError("Host interface identities must be unique Linux interface names")
    if ((not spec["endpoints"] and traffic)
            or len({row["mac"] for row in spec["endpoints"]}) != len(spec["endpoints"])):
        raise HostActionError("Every transport endpoint requires an independent PTF MAC")
    for field in ("ptf_index", "vlan"):
        if len({row[field] for row in spec["endpoints"]}) != len(spec["endpoints"]):
            raise HostActionError("Transport endpoints require distinct " + field)
    management = [ipaddress.ip_interface(value) for value in spec["management"]["addresses"]]
    if not management:
        raise HostActionError("PTF management addresses were not supplied")
    for row in spec["endpoints"]:
        if type(row["ptf_index"]) is not int or row["ptf_index"] < 0 or not 1 <= row["vlan"] <= 4094:
            raise HostActionError("Invalid reserved VLAN or logical PTF index")
        address = ipaddress.ip_interface(row["ptf_address"])
        if any(address.version == other.version and address.network.overlaps(other.network) for other in management):
            raise HostActionError("Data and management networks overlap")
        if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", row["mac"]) is None:
            raise HostActionError("Invalid deterministic PTF MAC")


def capture(spec, directory):
    container = inspect_container(spec, directory)
    root = json.loads(command(["ip", "-j", "-d", "link", "show"], directory))
    root_by_name = {row["ifname"]: row for row in root}
    requested = {spec["management_root"], spec["management_peer"]}
    requested.update(row["host_interface"] for row in spec["endpoints"])
    present = sorted(requested.intersection(root_by_name))
    if container is None and not present:
        return None, None
    owner_prefix = "sonic-generic:" + spec["scenario"] + ":"
    unowned = [name for name in present if not root_by_name[name].get("ifalias", "").startswith(owner_prefix)]
    if container is None:
        labels, running, namespace, namespace_addresses = {}, False, [], []
    else:
        labels = container["Config"].get("Labels") or {}
        if labels.get(OWNER) != spec["scenario"]:
            raise HostActionError("The baseline PTF name is occupied by a container this scenario does not own")
        running = container["State"].get("Running") is True
        prefix = ["nsenter", "-t", str(container["State"]["Pid"]), "-n"] if running else []
        namespace = json.loads(command(prefix + ["ip", "-j", "-d", "link", "show"], directory)) if running else []
        namespace_addresses = (
            json.loads(command(prefix + ["ip", "-j", "address", "show"], directory)) if running else [])
    by_name = {row["ifname"]: row for row in namespace}
    address_by_name = {row["ifname"]: row for row in namespace_addresses}
    for name, row in by_name.items():
        if name != "lo" and not row.get("ifalias", "").startswith(owner_prefix):
            unowned.append("ptf:" + name)
    management_root, management_peer = root_by_name.get(spec["management_root"], {}), by_name.get("mgmt", {})
    master = next((row["ifname"] for row in root if row["ifindex"] == management_root.get("master")), None)
    if isinstance(management_root.get("master"), str):
        master = management_root["master"]
    gateways = []
    sysctls = {}
    if running:
        for family, option in (("inet", "-4"), ("inet6", "-6")):
            routes = json.loads(command(prefix + ["ip", "-j", option, "route", "show", "default"], directory))
            gateways.extend({"family": family, "gateway": row.get("gateway"), "dev": row.get("dev")} for row in routes)
        keys = sorted(NAMESPACE_SYSCTLS)
        values = command(prefix + ["sysctl", "-n"] + keys, directory).decode().splitlines()
        if len(values) != len(keys):
            raise HostActionError("Namespace neighbor/routing policy readback is incomplete")
        sysctls = dict(zip(keys, values))
    endpoints = []
    parent_index = root_by_name.get(spec["parent"], {}).get("ifindex")
    for row in sorted(spec["endpoints"], key=lambda item: item["ptf_index"]):
        name = "eth" + str(row["ptf_index"])
        observed = by_name.get(name)
        if observed is None:
            continue
        endpoints.append({
            "ptf_index": row["ptf_index"], "name": observed["ifname"],
            "vlan": observed.get("linkinfo", {}).get("info_data", {}).get("id"),
            "parent": spec["parent"] if observed.get("link_index") == parent_index else None,
            "mac": observed.get("address"), "mtu": observed["mtu"], "up": "UP" in observed.get("flags", []),
            "addresses": addresses([address_by_name.get(name, {})]),
        })
    value = {
        "container": (None if container is None else {
            "name": container["Name"].lstrip("/"), "image_id": container["Image"],
            "scenario": labels.get(OWNER), "running": running}),
        "management": {
            "addresses": addresses([address_by_name.get("mgmt", {})]), "gateways": gateways, "bridge": master,
            "mtu": (management_root.get("mtu") if management_root.get("mtu") == management_peer.get("mtu") else None),
            "paired": bool(management_peer and management_root
                           and management_root.get("link_index") == management_peer.get("ifindex")
                           and management_peer.get("link_index") == management_root.get("ifindex")),
            "up": "UP" in management_root.get("flags", []) and "UP" in management_peer.get("flags", []),
        },
        "endpoints": endpoints, "root_interfaces": present, "unowned_interfaces": sorted(unowned),
        "sysctls": sysctls,
    }
    observed_operations = {item["ifalias"][len(owner_prefix):] for item in root if item["ifname"] in present
                           and item.get("ifalias", "").startswith(owner_prefix)}
    if labels.get(OPERATION):
        observed_operations.add(labels[OPERATION])
    intent = directory / "host-intent.json"
    if intent.is_file():
        latest = json.loads(intent.read_text())["operation_id"]
        if latest in observed_operations and not unowned:
            return value, latest
    receipt = directory / "host-receipt.json"
    if receipt.is_file():
        recorded = json.loads(receipt.read_text())
        if recorded["observed_sha256"] == digest(value):
            return value, recorded["operation_id"]
    return value, next(iter(observed_operations)) if len(observed_operations) == 1 and not unowned else None


def stage(spec, directory):
    validate_spec(spec)
    path = directory / "request.json"
    if path.exists():
        if json.loads(path.read_text()) != spec:
            raise HostActionError("The native host stage belongs to different immutable inputs")
        return
    value, _ = capture(spec, directory)
    if value is not None:
        raise HostActionError("Legacy topology or an owned resource remains; original cleanup must finish first")
    links = json.loads(command(["ip", "-j", "-d", "link", "show"], directory))
    by_name = {row["ifname"]: row for row in links}
    if spec["parent"] not in by_name or by_name[spec["parent"]]["mtu"] < spec["mtu"]:
        raise HostActionError("The existing shared transport parent cannot support the reviewed MTU")
    reserved = {row["vlan"] for row in spec["endpoints"]}
    if any(row.get("link_index") == by_name[spec["parent"]]["ifindex"]
           and row.get("linkinfo", {}).get("info_kind") == "vlan"
           and row["linkinfo"]["info_data"]["id"] in reserved for row in links):
        raise HostActionError("Original topology VLAN remnants still occupy reserved transport resources")
    bridge = by_name.get(spec["management"]["bridge"], {})
    if (bridge.get("linkinfo", {}).get("info_kind") != "bridge"
            or bridge.get("mtu") != spec["management"]["mtu"]):
        raise HostActionError("This adapter requires an existing Linux management bridge")
    images = json.loads(command(["docker", "image", "inspect", spec["image_id"]], directory))
    if len(images) != 1 or images[0]["Id"] != spec["image_id"]:
        raise HostActionError("The immutable original PTF image is not installed")
    atomic_json(path, spec)


def perform(before, after, operation_id, spec, directory):
    current, _ = capture(spec, directory)
    if current != before:
        raise HostActionError("Unexplained host/PTF drift blocks the conditional operation")
    if after is not None and (before is not None or after != candidate_state(spec)):
        raise HostActionError("Only a fresh, exact scenario-owned PTF deployment is permitted")
    if current is not None and current["unowned_interfaces"]:
        raise HostActionError("Another owner's interface prevents destructive namespace cleanup")
    tag = "sonic-generic:" + spec["scenario"] + ":" + operation_id
    if len(tag.encode()) > 255:
        raise HostActionError("Operation ownership marker exceeds the kernel interface-alias limit")
    atomic_json(directory / "host-intent.json", {"operation_id": operation_id, "before": before, "after": after})
    try:
        if after is None:
            root = json.loads(command(["ip", "-j", "-d", "link", "show"], directory))
            selected = set(current["root_interfaces"]) if current is not None else set()
            for row in root:
                if row["ifname"] in selected:
                    command(["ip", "link", "set", "dev", row["ifname"], "alias", tag], directory)
            container = inspect_container(spec, directory)
            if container is not None:
                if container["Config"].get("Labels", {}).get(OWNER) != spec["scenario"]:
                    raise HostActionError("Container ownership changed before removal")
                command(["docker", "rm", "--force", container["Id"]], directory)
            remaining = json.loads(command(["ip", "-j", "-d", "link", "show"], directory))
            for row in remaining:
                if row["ifname"] in selected:
                    if row.get("ifalias") != tag:
                        raise HostActionError("Host interface ownership changed before removal")
                    command(["ip", "link", "delete", "dev", row["ifname"]], directory)
        else:
            command(["docker", "create", "--pull", "never", "--name", spec["container"],
                     "--network", "none", "--privileged",
                     "--memory", "32g", "--memory-swap", "64g", "--label", OWNER + "=" + spec["scenario"],
                     "--label", OPERATION + "=" + operation_id, spec["image_id"]], directory)
            command(["docker", "start", spec["container"]], directory)
            container = inspect_container(spec, directory)
            if container["Config"].get("Labels", {}).get(OWNER) != spec["scenario"]:
                raise HostActionError("New PTF container ownership changed")
            pid = str(container["State"]["Pid"])
            namespace = ["nsenter", "-t", pid, "-n"]
            command(namespace + ["sysctl", "-w"] + [
                key + "=" + value for key, value in sorted(NAMESPACE_SYSCTLS.items())], directory)
            command(["ip", "link", "add", "name", spec["management_root"], "alias", tag,
                     "mtu", str(spec["management"]["mtu"]), "type", "veth", "peer", "name",
                     spec["management_peer"], "alias", tag, "mtu", str(spec["management"]["mtu"])], directory)
            command(["ip", "link", "set", "dev", spec["management_root"], "alias", tag], directory)
            command(["ip", "link", "set", "dev", spec["management_peer"], "alias", tag], directory)
            command(["ip", "link", "set", "dev", spec["management_peer"], "netns", pid], directory)
            command(namespace + ["ip", "link", "set", "dev", spec["management_peer"], "name", "mgmt"], directory)
            command(namespace + ["ip", "link", "set", "dev", "mgmt", "alias", tag], directory)
            command(["ip", "link", "set", "dev", spec["management_root"], "master",
                     spec["management"]["bridge"]], directory)
            command(["ip", "link", "set", "dev", spec["management_root"], "alias", tag, "up"], directory)
            command(namespace + ["ip", "link", "set", "dev", "mgmt", "alias", tag, "up"], directory)
            for address in spec["management"]["addresses"]:
                command(namespace + ["ip", "address", "add", address, "dev", "mgmt"], directory)
            for key, option in (("gateway", "-4"), ("gateway_v6", "-6")):
                if spec["management"].get(key):
                    command(namespace + ["ip", option, "route", "add", "default", "via",
                                         spec["management"][key], "dev", "mgmt"], directory)
            for row in spec["endpoints"]:
                command(["ip", "link", "add", "link", spec["parent"], "name", row["host_interface"], "alias",
                         tag, "mtu", str(spec["mtu"]), "address", row["mac"],
                         "type", "vlan", "id", str(row["vlan"])], directory)
                command(["ip", "link", "set", "dev", row["host_interface"], "alias", tag], directory)
                command(["ip", "link", "set", "dev", row["host_interface"], "netns", pid], directory)
                name = "eth" + str(row["ptf_index"])
                command(namespace + ["ip", "link", "set", "dev", row["host_interface"], "name", name], directory)
                command(namespace + ["ip", "link", "set", "dev", name, "alias", tag, "up"], directory)
                command(namespace + ["ip", "address", "add", row["ptf_address"], "dev", name], directory)
    except (OSError, ValueError, KeyError, TypeError):
        actual, _ = capture(spec, directory)
        atomic_json(directory / "host-receipt.json", {
            "operation_id": operation_id, "observed_sha256": digest(actual), "completed": False})
        raise
    actual, _ = capture(spec, directory)
    atomic_json(directory / "host-receipt.json", {
        "operation_id": operation_id, "observed_sha256": digest(actual), "completed": actual == after})
    if actual != after:
        raise HostActionError("Observed PTF namespace/VLAN configuration did not match the declared candidate")


def smoke(spec, directory):
    import generic_hwsku_packet_smoke

    if not spec.get("traffic_available", spec.get("admission_level") != "deployment_smoke"):
        raise HostActionError("The frozen layout has no independent packet paths")
    current, _ = capture(spec, directory)
    if current != candidate_state(spec):
        raise HostActionError("Owned Generic transport is not ready for packet smoke")
    source = Path(generic_hwsku_packet_smoke.__file__).read_text()
    request = {key: spec[key] for key in ("endpoints", "traffic_cases", "router_mac")}
    completed = subprocess.run(
        ["docker", "exec", "-i", spec["container"], "python3", "-c", source],
        input=json.dumps(request).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1800, check=False)
    atomic_bytes(directory / "packet-smoke-stderr.log", completed.stderr)
    if completed.returncode:
        raise HostActionError("Initial packet smoke failed (rc {}); private evidence: {}".format(
            completed.returncode, directory / "packet-smoke-stderr.log"))
    return json.loads(completed.stdout)


def main():
    import fcntl
    from ansible.module_utils.basic import AnsibleModule

    module = AnsibleModule(argument_spec={
        "action": {"type": "str", "choices": ["stage", "perform", "capture", "smoke"], "required": True},
        "request": {"type": "dict", "required": True, "no_log": True},
        "before": {"type": "raw", "no_log": True}, "after": {"type": "raw", "no_log": True},
        "operation_id": {"type": "str"},
        "destination": {"type": "path", "required": True},
    })
    try:
        spec = module.params["request"]
        validate_spec(spec)
        if socket.gethostname().lower() != spec["hostname"].lower():
            raise HostActionError("Actual VM host identity differs from collection")
        root = Path("/var/lib/sonic-generic")
        directory = root / spec["scenario"] / "host"
        if any(path.is_symlink() for path in [directory] + list(directory.parents)):
            raise HostActionError("Host recovery paths must not traverse symlinks")
        for path in (root, directory.parent, directory):
            path.mkdir(mode=0o700, exist_ok=True)
            os.chmod(str(path), 0o700)
        with open(str(root / ".host-action.lock"), "a") as lock:
            os.chmod(str(root / ".host-action.lock"), 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if module.params["action"] == "stage":
                stage(spec, directory)
            elif json.loads((directory / "request.json").read_text()) != spec:
                raise HostActionError("The host request differs from the original native stage")
            if module.params["action"] == "perform":
                operation = module.params["operation_id"]
                if not isinstance(operation, str) or not operation.startswith(spec["scenario"] + ":"):
                    raise HostActionError("Host operation identity belongs to a different scenario")
                perform(module.params["before"], module.params["after"], operation, spec, directory)
            if module.params["action"] == "smoke":
                write_result(module.params["destination"], smoke(spec, directory))
                module.exit_json(changed=False, artifact_written=True)
            value, ownership = capture(spec, directory)
            write_result(module.params["destination"], {"value": value, "owned_by": ownership})
            module.exit_json(changed=module.params["action"] == "perform", artifact_written=True)
    except (OSError, ValueError, KeyError, TypeError, ImportError, subprocess.SubprocessError) as error:
        module.fail_json(msg="Generic host action failed; recovery artifacts retained: {}".format(error))


if __name__ == "__main__":
    main()
