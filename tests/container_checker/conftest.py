"""Temporary, read-only VPP readiness capture for this diagnostic branch."""

import json
import logging
import os
import shlex
import time
from concurrent.futures import ThreadPoolExecutor
from functools import wraps
from importlib import import_module
from unittest.mock import patch

import pytest

from tests.common.errors import RunAnsibleModuleFail


logger = logging.getLogger(__name__)

KERNEL_PORTS = """
ip -details link show
for p in /sys/class/net/Ethernet*; do
    test -d "$p" || continue
    printf "%s " "${p##*/}"
    for field in ifindex flags operstate carrier; do
        if value=$(cat "$p/$field" 2>&1); then
            printf "%s=%s\\n" "$field" "$value"
        else
            printf "%s_READ_ERROR=%s\\n" "$field" "$value"
        fi
    done
done
"""

PORT_DATABASES = """
redis-cli -e --raw -n 2 HGETALL COUNTERS_PORT_NAME_MAP
ports=$(redis-cli -e --raw -n 4 --scan --pattern 'PORT|*' | sed 's/^PORT|//')
if test -z "$ports"; then
    printf "No configured PORT entries found\\n" >&2
    exit 1
fi
for db in 4 0 6; do
    printf "\\nDATABASE %s\\n" "$db"
    {
        for p in $ports; do
            printf 'ECHO "PORT %s"\\n' "$p"
            case "$db" in
                4) printf 'HGET "PORT|%s" admin_status\\n' "$p" ;;
                0) printf 'HGETALL "PORT_TABLE:%s"\\n' "$p" ;;
                6) printf 'HGETALL "PORT_TABLE|%s"\\n' "$p" ;;
            esac
        done
    } | redis-cli -e --raw -n "$db"
done
for kind in PORT HOSTIF; do
    printf "\\nASIC %s\\n" "$kind"
    redis-cli -e --raw -n 1 --scan --pattern "ASIC_STATE:SAI_OBJECT_TYPE_$kind:*" |
    while IFS= read -r key; do
        printf 'ECHO "%s"\\nHGETALL "%s"\\n' "$key" "$key"
    done | redis-cli -e --raw -n 1
done
"""

DUT_PROBES = [
    "show version; show interfaces status",
    KERNEL_PORTS,
    PORT_DATABASES,
    "docker exec syncd timeout -k 1 2 vppctl show interface; "
    "docker exec syncd timeout -k 1 2 vppctl show hardware-interfaces; "
    "docker exec syncd timeout -k 1 2 vppctl show lcp",
    "tail -n 500 /var/log/syslog",
    "tail -c 1048576 /var/log/swss/sairedis.rec",
    "ps -eLo pid,tid,psr,pcpu,stat,wchan:32,comm; "
    "cat /proc/stat /proc/loadavg /proc/pressure/cpu /proc/pressure/io",
]

HOST_PROBES = [
    "ip -details link show; cat /proc/stat /proc/loadavg /proc/pressure/cpu",
    "ovs-vsctl show",
    "ovs-vsctl --columns=name,type,options,admin_state,link_state,ifindex,error list Interface",
]

COMPUTE_PROBE = """
import json
import urllib.request
request = urllib.request.Request(
    "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01",
    headers={"Metadata": "true"},
)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(request, timeout=3) as response:
    data = json.load(response)
print(json.dumps({key: data[key] for key in ("vmSize", "location", "vmScaleSetName")}))
"""


def _bounded(probe):
    body = "set -eo pipefail\ndate -u +%FT%T.%N%z\n" + probe + "\ndate -u +%FT%T.%N%z"
    # shell_cmds' own timeout is disabled by quoted commands, so bound the process explicitly.
    return "timeout -k 2 8 bash -c {}".format(shlex.quote(body))


def _capture(stage, nodes):
    started = time.monotonic()
    errors = []
    with ThreadPoolExecutor(max_workers=len(nodes)) as executor:
        futures = {
            executor.submit(
                node.shell_cmds,
                cmds=[_bounded(probe) for probe in probes],
                continue_on_fail=True,
                module_ignore_errors=True,
            ): label
            for label, node, probes in nodes
        }
        for future, label in futures.items():
            try:
                result = future.result()
            except RunAnsibleModuleFail:
                logger.exception("VPP_READINESS stage=%s node=%s capture failed", stage, label)
                errors.append(label)
                continue
            logger.info("VPP_READINESS stage=%s node=%s result=%s", stage, label, result)
            if result.get("failed") or result.get("failed_cmds") or not result.get("results"):
                logger.error("VPP_READINESS stage=%s node=%s capture incomplete", stage, label)
                errors.append(label)
    logger.info(
        "VPP_READINESS stage=%s capture_status=%s elapsed_seconds=%.3f",
        stage, "incomplete" if errors else "complete", time.monotonic() - started,
    )


def _observe_reload(original_reload, reload_module, nodes):
    @wraps(original_reload)
    def observed(duthost, *args, **kwargs):
        if not kwargs.get("check_intf_up_ports"):
            return original_reload(duthost, *args, **kwargs)

        _capture("before-final-reload", nodes)
        original_check = reload_module.check_interface_status_of_up_ports
        captured = False

        def observed_check(*check_args, **check_kwargs):
            nonlocal captured
            ready = original_check(*check_args, **check_kwargs)
            if not ready and not captured:
                captured = True
                _capture("first-negative-readiness", nodes)
            return ready

        with patch.object(reload_module, "check_interface_status_of_up_ports", observed_check):
            try:
                result = original_reload(duthost, *args, **kwargs)
            except (pytest.fail.Exception, AssertionError, RunAnsibleModuleFail):
                _capture("reload-error-before-cleanup", nodes)
                raise
        _capture("reload-returned", nodes)
        return result

    return observed


@pytest.fixture(scope="module", autouse=True)
def capture_vpp_readiness(request):
    if not request.module.__name__.endswith("test_container_checker"):
        return
    duthosts = request.getfixturevalue("duthosts")
    names = request.getfixturevalue("selected_rand_one_per_hwsku_hostname")
    duts = [duthosts[name] for name in names]
    if not any(dut.facts["asic_type"] == "vpp" for dut in duts):
        return
    if len(duts) != 1 or duts[0].is_multi_asic:
        pytest.fail("The diagnostic requires one single-ASIC VPP DUT")
    if request.getfixturevalue("tbinfo")["topo"]["type"] != "t0":
        pytest.fail("The diagnostic requires the original t0 topology")
    vmhost = request.getfixturevalue("vmhost")
    ptfhost = request.getfixturevalue("ptfhost")
    if vmhost is None or ptfhost is None:
        pytest.fail("Host and PTF access are required for cross-layer capture")
    compute = vmhost.shell(
        _bounded("python3 -c {}".format(shlex.quote(COMPUTE_PROBE))),
        module_ignore_errors=True,
    )
    if compute.get("rc") != 0:
        pytest.fail("Cannot verify the Azure VM allocation: {}".format(compute))
    lines = compute["stdout"].splitlines()
    profile = json.loads(lines[1])
    logger.info("VPP_READINESS allocation=%s", profile)
    if profile["vmSize"] != "Standard_D8s_v5":
        pytest.fail("Expected D8s-v5, got {}".format(profile))
    expected_region = os.environ.get("VPP_CAPTURE_REGION")
    if expected_region and profile["location"] != expected_region:
        pytest.fail("Expected region {}, got {}".format(expected_region, profile))
    nodes = [("dut", duts[0], DUT_PROBES), ("vmhost", vmhost, HOST_PROBES),
             ("ptf", ptfhost, ["ip -details link show"])]
    _capture("module-start", nodes)
    module = request.module
    original_reload = module.config_reload
    module.config_reload = _observe_reload(
        original_reload, import_module("tests.common.config_reload"), nodes,
    )
    # Keep the wrapper installed through module-fixture teardown.
    request.config.add_cleanup(lambda: setattr(module, "config_reload", original_reload))
