"""Shared helpers for request construction and device resource collection."""

import json
import ipaddress
import logging
import shlex
import uuid
from contextlib import contextmanager, ExitStack

import grpc
from pygnmi.spec.v080 import gnmi_pb2, gnmi_pb2_grpc

from tests.common.gcu_utils import apply_gcu_patch
from tests.common.utilities import wait_until

BYPASS_METADATA = (("x-sonic-ss-bypass-validation", "true"),)
logger = logging.getLogger(__name__)


@contextmanager
def gnmi_connection(fixture):
    """Open one shared TLS connection and close it even if stub creation fails."""
    certs = fixture.pygnmi_client
    with open(certs.ca_cert, "rb") as stream:
        ca = stream.read()
    with open(certs.client_key, "rb") as stream:
        key = stream.read()
    with open(certs.client_cert, "rb") as stream:
        certificate = stream.read()
    credentials = grpc.ssl_channel_credentials(root_certificates=ca, private_key=key, certificate_chain=certificate)
    host = fixture.host
    if ":" in host and not host.startswith("["):
        host = "[{}]".format(host)
    with grpc.secure_channel("{}:{}".format(host, fixture.port), credentials,
                             options=(("grpc.enable_retries", 0),)) as channel:
        yield channel, gnmi_pb2_grpc.gNMIStub(channel)


def build_native_set_request(parts, value):
    request = gnmi_pb2.SetRequest()
    update = request.update.add()
    update.path.origin = "sonic-db"
    for name in parts:
        update.path.elem.add(name=name)
    update.val.json_ietf_val = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return request


def collect_resource_snapshot(host):
    """Read boundary samples outside measured calls; host=None supports offline runs."""
    if host is None:
        return []
    monit = host.monit_process(iterations=1, delay_interval=1).get("monit_results", [])
    if not monit:
        raise RuntimeError("DUT resource snapshot returned no samples")
    container = host.shell(
        r"docker stats --no-stream --format \{\{.CPUPerc\}\}\ \{\{.MemUsage\}\} gnmi",
        module_ignore_errors=True)
    if container.get("rc") != 0 or not container.get("stdout", "").strip():
        raise RuntimeError("gNMI container resource snapshot failed: {}".format(container))
    return [{"monit": monit, "container": {"raw": container["stdout"].strip()}}]


def _vnet_namespace(run_id, vnet_count):
    # VNETs become Linux VRFs; reserve the largest index within IFNAMSIZ - 1.
    suffix = "_{}".format(vnet_count - 1)
    return ("Vnet" + run_id)[:15 - len(suffix)]


@contextmanager
def route_resources(host, distribution, routes_per_request, stub, timeout):
    """Prepare all VNETs/routes before measurement and remove only this run's keys."""
    if host.is_multi_asic:
        raise ValueError("generated VNET routes require a single-ASIC DUT")
    total = sum(routes * count for routes, count in distribution.items())
    existing = host.shell(
        "python3 -c " + shlex.quote(
            "import redis; r=redis.Redis(unix_socket_path='/var/run/redis/redis.sock',db=4); "
            "print(sum(1 for _ in r.scan_iter(match='VNET_ROUTE_TUNNEL|*')))"))
    if existing.get("rc") != 0:
        raise RuntimeError("Unable to count existing VNET routes")
    if int(existing["stdout"].strip()) + total > 256000:
        raise ValueError("existing plus generated VNET_ROUTE_TUNNEL routes would exceed 256000")
    facts = host.get_running_config_facts()
    loopbacks = facts.get("LOOPBACK_INTERFACE", {}).get("Loopback0", {})
    addresses = [str(ipaddress.ip_interface(address).ip) for address in loopbacks if ":" not in address]
    if not addresses:
        raise ValueError("VNET setup requires Loopback0 IPv4 address")
    used_vnis = {str(entry.get("vni")) for entry in facts.get("VNET", {}).values()}
    available_vnis = (str(v) for v in range(10001, 16777216) if str(v) not in used_vnis)
    run_id = uuid.uuid4().hex
    namespace = _vnet_namespace(run_id, sum(distribution.values()))
    tunnel = "Tunnel" + namespace
    backup = "/tmp/VnetBenchmark" + run_id + ".config_db.json"
    vnets = [("{}_{}".format(namespace, index), routes)
             for index, routes in enumerate(routes for routes, count in distribution.items() for _ in range(count))]
    collision = host.shell(
        "python3 -c " + shlex.quote(
            "import redis; r=redis.Redis(unix_socket_path='/var/run/redis/redis.sock',db=4); "
            "print(int(any(r.scan_iter(match=" + repr("VNET_ROUTE_TUNNEL|" + namespace + "_*") + ")) or "
            "any(r.scan_iter(match=" + repr("VNET|" + namespace + "_*") + ")) or "
            "r.exists(" + repr("VXLAN_TUNNEL|" + tunnel) + ")))"))
    if collision.get("rc") != 0:
        raise RuntimeError("Unable to check generated benchmark namespace")
    if int(collision["stdout"].strip()):
        raise ValueError("Generated benchmark namespace {} overlaps existing resources".format(namespace))
    with ExitStack() as cleanup:
        host.shell("cp -a /etc/sonic/config_db.json " + shlex.quote(backup))
        cleanup.callback(_restore_config, host, backup)
        cleanup.callback(_remove_routes, host, namespace, tunnel)
        # Seed empty tables once, then add each VNET without overwriting other entries.
        patch = [{"op": "add", "path": "/" + table, "value": {}}
                 for table in ("VXLAN_TUNNEL", "VNET") if not facts.get(table)]
        tunnel_entry = {"src_ip": addresses[0]}
        # Match the base topology's pipe-mode IP-in-IP decap tunnels on cisco-8000.
        if host.facts.get("asic_type") == "cisco-8000":
            tunnel_entry["ttl_mode"] = "pipe"
        patch.append({"op": "add", "path": "/VXLAN_TUNNEL/" + tunnel, "value": tunnel_entry})
        for name, _ in vnets:
            patch.append({"op": "add", "path": "/VNET/" + name,
                          "value": {"vxlan_tunnel": tunnel, "vni": next(available_vnis)}})
        apply_gcu_patch(host, patch)
        prepared = []
        # Prefixes may repeat across isolated VNETs; compound table keys remain unique.
        base = int(ipaddress.IPv4Address("198.18.0.0"))
        for name, routes in vnets:
            payload = {"{}|{}/32".format(name, ipaddress.IPv4Address(base + i)): {"endpoint": "198.19.0.1"}
                       for i in range(routes)}
            write = build_native_set_request(("CONFIG_DB", "localhost", "VNET_ROUTE_TUNNEL"), payload)
            response = stub.Set(write, timeout=timeout, metadata=BYPASS_METADATA)
            if response.message.code or any(item.message.code for item in response.response):
                raise RuntimeError("Route preload failed for {}".format(name))
            # Smaller VNETs remain background inventory for every request-size comparison.
            if routes != max(distribution):
                continue
            keys = list(payload)
            batches = []
            for offset in range(0, routes, routes_per_request):
                batch = {key: payload[key] for key in keys[offset:offset + routes_per_request]}
                read = gnmi_pb2.GetRequest(type=gnmi_pb2.GetRequest.ALL, encoding=gnmi_pb2.JSON_IETF)
                for key in batch:
                    path = read.path.add(origin="sonic-db")
                    for element in ("CONFIG_DB", "localhost", "VNET_ROUTE_TUNNEL", key):
                        path.elem.add(name=element)
                write_batch = build_native_set_request(("CONFIG_DB", "localhost", "VNET_ROUTE_TUNNEL"), batch)
                batches.append((read, write_batch))
            prepared.append(batches)
        # Visit each measured VNET before moving to its next disjoint route batch.
        yield tuple(pair for batch_index in zip(*prepared) for pair in batch_index)


def _routes_removed(host, name):
    script = (
        "import json,redis; "
        "r=redis.Redis(unix_socket_path='/var/run/redis/redis.sock',db=4); "
        "s=redis.Redis(unix_socket_path='/var/run/redis/redis.sock',db=6); "
        "print(json.dumps({'route_state_present': "
        "any(s.scan_iter(match=" + repr("VNET_ROUTE_TUNNEL_TABLE|" + name + "_*") + ",count=1000)), "
        "'config_subscriber_omem': sum(int(c['omem']) for c in r.client_list() "
        "if int(c['db']) == 4 and 'P' in c['flags'])}))"
    )
    result = host.shell("python3 -c " + shlex.quote(script), module_ignore_errors=True)
    if result.get("rc") != 0:
        raise RuntimeError("Unable to check generated route cleanup: {}".format(result))
    pending = json.loads(result["stdout"])
    logger.info("Benchmark route cleanup for %s: %s", name, pending)
    return not pending["route_state_present"] and pending["config_subscriber_omem"] == 0


def _remove_routes(host, name, tunnel):
    prefix = "VNET_ROUTE_TUNNEL|" + name + "_*"
    script = (
        "import redis; r=redis.Redis(unix_socket_path='/var/run/redis/redis.sock',db=4); "
        "keys=list(r.scan_iter(match=" + repr(prefix) + ")); "
        "[r.delete(*keys[i:i+500]) for i in range(0,len(keys),500)]; "
        "assert not list(r.scan_iter(match=" + repr(prefix) + "))"
    )
    removed = host.shell("python3 -c " + shlex.quote(script), module_ignore_errors=True)
    if removed.get("rc") != 0:
        raise RuntimeError("Unable to remove generated benchmark routes: {}".format(removed))
    # CONFIG_DB deletion is asynchronous; keep dependencies until consumers finish.
    if not wait_until(600, 5, 0, _routes_removed, host, name):
        raise RuntimeError("Generated benchmark routes and notifications did not drain for {}".format(name))
    script = (
        "import redis; r=redis.Redis(unix_socket_path='/var/run/redis/redis.sock',db=4); "
        "vnets=list(r.scan_iter(match=" + repr("VNET|" + name + "_*") + ")); "
        "[r.delete(*vnets[i:i+500]) for i in range(0,len(vnets),500)]; "
        "r.delete(" + repr("VXLAN_TUNNEL|" + tunnel) + ")"
    )
    removed = host.shell("python3 -c " + shlex.quote(script), module_ignore_errors=True)
    if removed.get("rc") != 0:
        raise RuntimeError("Unable to remove generated benchmark VNETs and tunnel: {}".format(removed))


def _restore_config(host, backup):
    restored = host.shell(
        "cp -a --remove-destination {0} /etc/sonic/config_db.json && "
        "cmp -s {0} /etc/sonic/config_db.json && rm {0}".format(shlex.quote(backup)),
        module_ignore_errors=True)
    if restored.get("rc") != 0:
        raise RuntimeError("Unable to restore persistent config backup {}".format(backup))
