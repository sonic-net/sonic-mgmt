"""Benchmark unary gNMI Get or Set calls with one persistent connection."""

import json
import logging
import math
import os
import shlex
import ipaddress
import uuid
from dataclasses import dataclass

import pytest
from google.protobuf.json_format import ParseError

from tests.gnmi_benchmark.scenarios import load_scenario
from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.helpers.custom_msg_utils import add_custom_msg
from tests.gnmi_benchmark.benchmark_runner import (
    CLIENT_NAME,
    prepare_runner,
    run_benchmark,
)
from tests.gnmi_benchmark.operation_results import (
    build_benchmark_report,
    write_benchmark_report,
)

logger = logging.getLogger(__name__)
BYPASS_SKU_PREFIXES = ("Cisco-8101", "Cisco-8102", "Cisco-8223")
pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.stress_test,
    pytest.mark.disable_loganalyzer,
    pytest.mark.disable_memory_utilization,
    pytest.mark.skip_check_dut_health,
]


@dataclass(frozen=True)
class BenchmarkOptions:
    """Read and validate CLI options before preparing a workload."""

    operation: str
    concurrency: int
    logical_requests: int
    timeout_seconds: int
    bypass_requested: bool
    workload_name: str
    workload_params: dict
    duration_seconds: float
    warmup_seconds: float
    output_dir: str
    traffic_pattern: str = "closed-loop"
    rate: float = 0
    scenario_file: str = None

    @classmethod
    def from_pytest(cls, config, is_multi_asic):
        scenario_file = config.getoption("--benchmark-scenario")
        operation = config.getoption("--benchmark-operation")
        workload_name = config.getoption("--benchmark-workload") or (
            "empty" if operation == "get" else "port-description")
        try:
            workload_params = json.loads(config.getoption("--benchmark-workload-params"))
        except (ValueError, TypeError) as error:
            raise pytest.UsageError("benchmark workload-params must be a valid JSON object") from error
        options = cls(
            operation="scenario" if scenario_file else operation,
            concurrency=config.getoption("--benchmark-concurrency"),
            logical_requests=config.getoption("--benchmark-logical-requests"),
            timeout_seconds=config.getoption("--benchmark-timeout"),
            bypass_requested=config.getoption("--benchmark-bypass"),
            workload_name="scenario" if scenario_file else workload_name,
            workload_params=workload_params,
            duration_seconds=config.getoption("--benchmark-duration"),
            warmup_seconds=config.getoption("--benchmark-warmup"),
            output_dir=os.path.abspath(config.getoption("--benchmark-output-dir")),
            traffic_pattern=config.getoption("--benchmark-traffic"),
            rate=config.getoption("--benchmark-rate"),
            scenario_file=scenario_file,
        )
        if scenario_file and (config.getoption("--benchmark-workload") or workload_params
                              or config.getoption("--benchmark-bypass") or operation != "get"):
            raise pytest.UsageError("scenario defines methods, requests and metadata; do not combine workload flags")
        options.validate(is_multi_asic)
        return options

    @property
    def workers(self):
        return (self.concurrency if self.duration_seconds or self.traffic_pattern == "open-loop"
                else min(self.concurrency, self.logical_requests))

    def validate(self, is_multi_asic):
        # Keep input errors explicit: assertions can be disabled with python -O.
        rules = (
            (math.isfinite(self.warmup_seconds) and self.warmup_seconds >= 0,
             "benchmark warmup must be finite and nonnegative"),
            (math.isfinite(self.duration_seconds) and self.duration_seconds >= 0,
             "benchmark duration must be finite and nonnegative"),
            (min(self.concurrency, self.logical_requests, self.timeout_seconds) > 0,
             "benchmark concurrency, logical requests, and timeout must be positive"),
            (self.logical_requests <= 1_000_000, "benchmark supports at most 1000000 logical requests"),
            (self.concurrency <= 500, "benchmark supports at most 500 concurrent workers"),
        )
        for valid, message in rules:
            if not valid:
                raise pytest.UsageError(message)
        if self.traffic_pattern not in ("closed-loop", "open-loop"):
            raise pytest.UsageError("Unknown benchmark traffic pattern")
        if not math.isfinite(self.rate) or (self.traffic_pattern == "open-loop" and not 0 < self.rate <= 1_000_000):
            raise pytest.UsageError("open-loop requires a finite rate in (0, 1000000]")
        if self.traffic_pattern == "closed-loop" and self.rate:
            raise pytest.UsageError("benchmark-rate requires open-loop")
        _validate_workload(self, is_multi_asic)


def _validate_workload(options, is_multi_asic):
    """Delegate payload options to the selected workload, not the load runner."""
    name, params = options.workload_name, options.workload_params
    if not isinstance(params, dict):
        raise pytest.UsageError("benchmark workload-params must be a JSON object")
    if name == "scenario":
        if options.operation != "scenario" or not options.scenario_file or params or options.bypass_requested:
            raise pytest.UsageError("scenario requires a file and cannot be combined with workload parameters")
        return
    if name not in ("empty", "port-description", "vnet-route-tunnel"):
        raise pytest.UsageError("Unknown benchmark workload: {}".format(name))
    if options.operation not in ("get", "set", "get-set"):
        raise pytest.UsageError("Unsupported benchmark operation: {}".format(options.operation))
    if (options.operation == "get") != (name == "empty"):
        raise pytest.UsageError("empty workload requires Get; write workloads require Set or Get-Set")
    if options.bypass_requested and name != "vnet-route-tunnel":
        raise pytest.UsageError("benchmark bypass requires the vnet-route-tunnel workload")
    allowed = {"entry_count", "prepare", "payload_file"} if name == "vnet-route-tunnel" else set()
    unknown = set(params) - allowed
    if unknown:
        raise pytest.UsageError("Unknown {} workload parameters: {}".format(name, ", ".join(sorted(unknown))))
    if name != "vnet-route-tunnel":
        return
    if ("entry_count" in params) == ("payload_file" in params):
        raise pytest.UsageError("vnet-route-tunnel requires exactly one of entry_count or payload_file")
    if "prepare" in params and type(params["prepare"]) is not bool:
        raise pytest.UsageError("workload prepare must be a boolean")
    if "entry_count" in params:
        count = params["entry_count"]
        if type(count) is not int or not 1 <= count <= 20000:
            raise pytest.UsageError("vnet-route-tunnel entry_count must be an integer in 1..20000")
        if is_multi_asic or not (params.get("prepare", False) or options.bypass_requested):
            raise pytest.UsageError("generated VNET entries require prepare=true or bypass on a single-ASIC DUT")
    else:
        if not isinstance(params["payload_file"], str) or not params["payload_file"].strip():
            raise pytest.UsageError("workload payload_file must be a nonempty path")
        if params.get("prepare", False):
            raise pytest.UsageError("workload prepare=true requires generated entry_count, not payload_file")


def _prepare_workload(duthost, request, options):
    """Keep workload-specific preparation separate from RPC execution."""
    if options.workload_name == "scenario":
        try:
            steps, descriptor = load_scenario(options.scenario_file)
        except (ValueError, OSError, ParseError) as error:
            raise pytest.UsageError("Invalid benchmark scenario: {}".format(error)) from error
        return {"steps": steps, "scenario": descriptor}
    if options.workload_name == "empty":
        return None
    if options.workload_name == "port-description":
        return _set_workload(duthost)
    params = options.workload_params
    if "entry_count" in params:
        return _generated_workload(duthost, request, params["entry_count"],
                                   valid_routes=params.get("prepare", False))
    with open(params["payload_file"]) as stream:
        payload = json.load(stream)
    if not isinstance(payload, dict) or not payload or any(not isinstance(v, dict) for v in payload.values()):
        raise pytest.UsageError("Set payload must be a nonempty JSON object mapping route keys to field objects")
    asic = duthost.frontend_asics[0] if duthost.is_multi_asic else None
    return {"instance": asic.namespace if asic is not None else "localhost", "payload": payload}


def _workload_load(options, workload):
    """Record effective workload inputs alongside existing schema-compatible fields."""
    params = dict(options.workload_params)
    if options.workload_name == "vnet-route-tunnel":
        params.setdefault("prepare", False)
    load = {"workload": {"type": options.workload_name, "params": params}}
    if options.workload_name == "scenario":
        load["workload"] = {"type": "scenario", "scenario": workload["scenario"]}
    if workload and "payload" in workload:
        # Retain legacy VNET fields for existing report consumers.
        load["routes_per_rpc"] = len(workload["payload"])
        load["payload_bytes"] = len(json.dumps(workload["payload"], sort_keys=True, separators=(",", ":")).encode())
        if "entry_count" in params:
            load["valid_route_prerequisites"] = params["prepare"]
    return load


def _set_workload(duthost):
    asic = duthost.frontend_asics[0] if duthost.is_multi_asic else None
    facts = (asic.config_facts(source="running") if asic is not None
             else duthost.config_facts(host=duthost.hostname, source="running"))["ansible_facts"]
    ports = sorted(facts.get("PORT", {}))
    if not ports:
        raise RuntimeError("CONFIG_DB does not contain PORT entries")
    return {"port": ports[0], "instance": asic.namespace if asic is not None else "localhost"}


def _resource_snapshot(duthost):
    monit = duthost.monit_process(iterations=1, delay_interval=1).get("monit_results", [])
    if not monit:
        raise RuntimeError("DUT resource snapshot returned no samples")
    container = duthost.shell(
        r"docker stats --no-stream --format \{\{.CPUPerc\}\}\ \{\{.MemUsage\}\} gnmi",
        module_ignore_errors=True,
    )
    if container.get("rc") != 0 or not container.get("stdout", "").strip():
        raise RuntimeError("gNMI container resource snapshot failed: {}".format(container))
    return monit, [{"raw": container["stdout"].strip(), "rc": container["rc"]}]


def _generated_workload(duthost, request, count, valid_routes=False):
    """Use a unique test namespace and remove its keys before gnmi_tls rollback."""
    name = "VnetBenchmark" + uuid.uuid4().hex
    tunnel = "Tunnel" + name
    backup = "/tmp/" + name + ".config_db.json"
    prefix = "VNET_ROUTE_TUNNEL|" + name + "|"
    cleanup_script = (
        "import redis; r=redis.Redis(unix_socket_path='/var/run/redis/redis.sock',db=4); "
        "keys=list(r.scan_iter(match=" + repr(prefix + "*") + ")); "
        "[r.delete(*keys[i:i+500]) for i in range(0,len(keys),500)]; "
        "assert not list(r.scan_iter(match=" + repr(prefix + "*") + "))"
    )
    if valid_routes:
        cleanup_script += "; r.delete(" + repr("VNET|" + name) + "); r.delete(" + repr("VXLAN_TUNNEL|" + tunnel) + ")"

    def cleanup():
        result = duthost.shell("python3 -c " + shlex.quote(cleanup_script), module_ignore_errors=True)
        if result.get("rc") != 0:
            pytest.fail("Unable to remove generated benchmark routes: {}".format(result))
        if valid_routes:
            restored = duthost.shell(
                "cp -a --remove-destination {0} /etc/sonic/config_db.json && "
                "cmp -s {0} /etc/sonic/config_db.json && rm {0}".format(shlex.quote(backup)),
                module_ignore_errors=True,
            )
            if restored.get("rc") != 0:
                pytest.fail("Unable to restore persistent config backup {}".format(backup))

    if valid_routes:
        duthost.shell("cp -a /etc/sonic/config_db.json " + shlex.quote(backup))
    request.addfinalizer(cleanup)
    if valid_routes:
        facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
        loopbacks = facts.get("LOOPBACK_INTERFACE", {}).get("Loopback0", {})
        addresses = [str(ipaddress.ip_interface(address).ip) for address in loopbacks if ":" not in address]
        if not addresses:
            raise RuntimeError("Valid route setup requires Loopback0 IPv4 address")
        used_vnis = {str(entry.get("vni")) for entry in facts.get("VNET", {}).values()}
        vni = next(str(value) for value in range(10001, 16777216) if str(value) not in used_vnis)
        patch = []
        for table, key, value in (
            ("VXLAN_TUNNEL", tunnel, {"src_ip": addresses[0]}),
            ("VNET", name, {"vxlan_tunnel": tunnel, "vni": vni}),
        ):
            patch.append({"op": "add", "path": "/" + table + ("/" + key if facts.get(table) else ""),
                          "value": value if facts.get(table) else {key: value}})
        setup = duthost.shell("config apply-patch /dev/stdin", stdin=json.dumps(patch), module_ignore_errors=True)
        if setup.get("rc") != 0:
            raise RuntimeError("Valid route prerequisites failed: {}".format(setup))
    base = int(ipaddress.IPv4Address("198.18.0.0"))
    payload = {"{}|{}/32".format(name, ipaddress.IPv4Address(base + i)): {"endpoint": "198.19.0.1"}
               for i in range(count)}
    return {"instance": "localhost", "payload": payload}


def _emit_report(request, report):
    logger.info("GNMI_BENCHMARK_JSON %s", json.dumps(report, separators=(",", ":"), sort_keys=True))
    key = "gnmi_benchmark.{}".format(report["cid"])
    if request.node is request.session.items[-1]:
        add_custom_msg(request, key, report)
    else:
        request.node.user_properties.append(
            (
                "CustomMsg",
                json.dumps({"gnmi_benchmark": {report["cid"]: report}}),
            )
        )


def test_gnmi_benchmark(
    gnmi_tls,  # noqa: F811
    pytestconfig,
    request,
    duthosts,
    enum_rand_one_per_hwsku_frontend_hostname,
):
    """Run Get or idempotent native Set and write one combined report."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    options = BenchmarkOptions.from_pytest(pytestconfig, duthost.is_multi_asic)
    operation = options.operation
    concurrency = options.workers
    logical_requests = options.logical_requests
    timeout_seconds = options.timeout_seconds
    bypass_requested = options.bypass_requested
    duration_seconds = options.duration_seconds
    warmup_seconds = options.warmup_seconds
    if gnmi_tls.transport != "tls" or gnmi_tls.pygnmi_client is None:
        pytest.skip("The benchmark requires the TLS transport")

    output_dir = options.output_dir
    workload = _prepare_workload(duthost, request, options)
    sku_result = duthost.shell("sonic-db-cli CONFIG_DB HGET 'DEVICE_METADATA|localhost' hwsku")
    device_sku = sku_result["stdout"].strip()
    logger.info("Benchmark operation=%s bypass_requested=%s sku=%s", operation, bypass_requested, device_sku)
    boundary_samples = {}

    def capture_before_benchmark():
        boundary_samples["before"] = _resource_snapshot(duthost)

    result = run_benchmark(
        prepare_runner(output_dir),
        gnmi_tls,
        operation,
        output_dir,
        concurrency,
        logical_requests,
        timeout_seconds,
        start_hook=capture_before_benchmark,
        workload=workload,
        bypass_requested=bypass_requested,
        duration_seconds=duration_seconds,
        warmup_seconds=warmup_seconds,
        traffic_pattern=options.traffic_pattern,
        rate=options.rate,
    )
    after_monit, after_container = _resource_snapshot(duthost)
    before_monit, before_container = boundary_samples["before"]

    cid = str(uuid.uuid4())
    load = {"logical_requests": result["counts"]["started"], "concurrency": concurrency}
    if duration_seconds:
        load["duration_seconds"] = duration_seconds
    load["warmup_seconds"] = warmup_seconds
    if options.traffic_pattern == "open-loop":
        load["scheduled_iterations"] = result["execution"]["scheduling"]["scheduled"]
    load.update(_workload_load(options, workload))
    report = build_benchmark_report(
        cid=cid,
        client=CLIENT_NAME,
        operation=operation,
        connection_type=gnmi_tls.transport.upper(),
        # gnmi_tls explicitly enables client_auth and user_auth=cert.
        auth_mode="normal",
        load=load,
        result=result,
        device={
            "hostname": duthost.hostname,
            "os_version": duthost.os_version,
            "sku": device_sku,
            "bypass_eligible": device_sku.startswith(BYPASS_SKU_PREFIXES),
            "platform": duthost.facts.get("platform", "unknown"),
            "asic_type": duthost.facts.get("asic_type", "unknown"),
            "asic_count": duthost.num_asics(),
        },
        monit_results=before_monit + after_monit,
        container_samples=before_container + after_container,
    )
    path = write_benchmark_report(output_dir, report)
    _emit_report(request, report)
    logger.info("gNMI benchmark report: %s", path)

    counts = result["counts"]
    scheduling = result["execution"].get("scheduling", {})
    if (counts["successful"] != counts["planned"] or counts["failed"] or counts["unfinished"]
            or scheduling.get("dropped_capacity", 0) or scheduling.get("dropped_late", 0)):
        pytest.fail(
            "gNMI benchmark failures: counts={}, statuses={}, dropped_capacity={}, dropped_late={}".format(
                counts, result["grpc_status_counts"], scheduling.get("dropped_capacity", 0),
                scheduling.get("dropped_late", 0))
        )
