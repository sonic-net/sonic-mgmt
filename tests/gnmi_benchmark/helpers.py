"""Shared helpers for request construction and device resource collection."""

import json
import ipaddress
import shlex
import uuid
import logging
import re
from contextlib import contextmanager, ExitStack

import grpc
from pygnmi.spec.v080 import gnmi_pb2, gnmi_pb2_grpc

from tests.common.gcu_utils import apply_gcu_patch
from tests.common.utilities import wait_until

BYPASS_METADATA = (("x-sonic-ss-bypass-validation", "true"),)


def recover_consumer(host, consumer_service=None, timeout_seconds=60):
    """After rollback, optionally restart the identified consumer and wait for Redis drain."""
    if consumer_service is not None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]*", consumer_service):
            raise ValueError("consumer_service must be one systemd unit name")
        if consumer_service.removesuffix(".service") in ("redis", "redis-server", "database", "gnmi"):
            raise ValueError("Restart only the identified consumer, not Redis/database/gNMI")

    def drained():
        if not host.asics:
            raise RuntimeError("No Redis instances found")
        for asic in host.asics:
            response = asic.run_redis_cli_cmd("client list")
            lines = response.get("stdout_lines", [])
            if response.get("rc", 0) != 0 or not lines:
                raise RuntimeError("Cannot inspect Redis client output buffers")
            total = sum(int(dict(field.split("=", 1) for field in line.split() if "=" in field)["omem"])
                        for line in lines)
            logging.info("Benchmark Redis output memory namespace=%s bytes=%s", asic.namespace, total)
            if total > 10 * 1024 * 1024:
                return False
        return True

    if drained():
        return
    if consumer_service:
        logging.info("Benchmark recovery: restarting consumer %s after rollback", consumer_service)
        host.command("sudo systemctl restart " + consumer_service)
        host.command("systemctl is-active " + consumer_service)
    if not wait_until(timeout_seconds, 2, 0, drained):
        raise RuntimeError("Redis output buffers remain above 10 MiB after benchmark recovery")


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
    namespace = "VnetBenchmark" + uuid.uuid4().hex
    tunnel = "Tunnel" + namespace
    backup = "/tmp/" + namespace + ".config_db.json"
    vnets = [("{}_{}".format(namespace, index), routes)
             for index, routes in enumerate(routes for routes, count in distribution.items() for _ in range(count))]
    with ExitStack() as cleanup:
        host.shell("cp -a /etc/sonic/config_db.json " + shlex.quote(backup))
        cleanup.callback(_restore_config, host, backup)
        cleanup.callback(_remove_routes, host, namespace, tunnel)
        # Seed empty tables once, then add each VNET without overwriting other entries.
        patch = [{"op": "add", "path": "/" + table, "value": {}}
                 for table in ("VXLAN_TUNNEL", "VNET") if not facts.get(table)]
        patch.append({"op": "add", "path": "/VXLAN_TUNNEL/" + tunnel, "value": {"src_ip": addresses[0]}})
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


def _remove_routes(host, name, tunnel):
    prefix = "VNET_ROUTE_TUNNEL|" + name + "_*"
    script = (
        "import redis; r=redis.Redis(unix_socket_path='/var/run/redis/redis.sock',db=4); "
        "keys=list(r.scan_iter(match=" + repr(prefix) + ")); "
        "[r.delete(*keys[i:i+500]) for i in range(0,len(keys),500)]; "
        "assert not list(r.scan_iter(match=" + repr(prefix) + ")); "
        "vnets=list(r.scan_iter(match=" + repr("VNET|" + name + "_*") + ")); "
        "[r.delete(*vnets[i:i+500]) for i in range(0,len(vnets),500)]; "
        "r.delete(" + repr("VXLAN_TUNNEL|" + tunnel) + ")"
    )
    removed = host.shell("python3 -c " + shlex.quote(script), module_ignore_errors=True)
    if removed.get("rc") != 0:
        raise RuntimeError("Unable to remove generated benchmark routes: {}".format(removed))


def _restore_config(host, backup):
    restored = host.shell(
        "cp -a --remove-destination {0} /etc/sonic/config_db.json && "
        "cmp -s {0} /etc/sonic/config_db.json && rm {0}".format(shlex.quote(backup)),
        module_ignore_errors=True)
    if restored.get("rc") != 0:
        raise RuntimeError("Unable to restore persistent config backup {}".format(backup))
