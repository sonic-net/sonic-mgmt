"""Explicit IS-IS namespace acceptance on a matching multi-ASIC image.

Run this module by its file path; see README.md for the image prerequisites.
"""
import json
import logging
import re
import shlex

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

pytestmark = [pytest.mark.topology("any")]
logger = logging.getLogger(__name__)


def _run(node, command):
    result = node.shell(command, module_ignore_errors=True)
    pytest_assert(result.get("rc", 1) == 0, "Command failed: {}: {}".format(command, result))
    logger.info("%s\n%s", command, result)
    return result.get("stdout", "").strip()


def _snapshot(node, namespace):
    return json.loads(_run(node, "sudo sonic-cfggen -n {} -d --print-data".format(shlex.quote(namespace))))


def _installed(node, container):
    output = _run(node, "sudo docker exec {} vtysh -c 'show running-config isisd'".format(container))
    return bool(re.search(r"(?m)^router isis ISIS_NS_TEST\n(?:[ \t].*\n)*[ \t]+lsp-mtu 1380(?:\n|$)", output))


def _neighbors(node, container):
    command = "sudo docker exec {} pgrep -x isisd".format(container)
    result = node.shell(command, module_ignore_errors=True)
    # Native pgrep returns 1 with no diagnostic when no process matches.
    absent = result.get("rc") == 1 and not result.get("stdout", "").strip() and not result.get("stderr", "").strip()
    pytest_assert(result.get("rc") == 0 or absent, "Command failed: {}: {}".format(command, result))
    if absent:
        return None
    return json.loads(_run(node, "sudo docker exec {} vtysh -c 'show isis neighbor json'".format(container)))


@pytest.fixture
def isis_namespace(rand_selected_dut, request):
    node = rand_selected_dut
    if not node.is_multi_asic:
        pytest.skip("IS-IS namespace device coverage requires a multi-ASIC testbed")
    namespaces = node.get_frontend_asic_namespace_list()
    if len(namespaces) < 2:
        pytest.skip("IS-IS namespace isolation requires two frontend ASIC namespaces")
    namespace = namespaces[0]
    pytest_assert(re.fullmatch(r"asic[0-9]+", namespace), "Unexpected ASIC namespace: " + namespace)
    asic = node.asic_instance_from_namespace(namespace)
    before = {name: _snapshot(node, name) for name in namespaces}
    pytest_assert("default|ISIS_NS_TEST" not in before[namespace].get("ISIS_GLOBALS", {}),
                  "Temporary namespace instance already exists")
    original = before[namespace]["DEVICE_METADATA"]["localhost"].get("frr_mgmt_framework_config")

    def restart_bgp():
        asic.restart_service("bgp")
        pytest_assert(wait_until(100, 10, 0, node.sonichost.is_service_fully_started,
                                 asic.get_docker_name("bgp")), "BGP not started.")

    def restore():
        if original != "true":
            if original is None:
                asic.run_sonic_db_cli_cmd(
                    'CONFIG_DB HDEL "DEVICE_METADATA|localhost" "frr_mgmt_framework_config"')
            else:
                asic.run_sonic_db_cli_cmd(
                    'CONFIG_DB HSET "DEVICE_METADATA|localhost" "frr_mgmt_framework_config" {}'.format(
                        shlex.quote(original)))
            restart_bgp()
        for name in namespaces:
            pytest_assert(_snapshot(node, name) == before[name], "Namespace cleanup changed existing ConfigDB")

    # Register before setup so a failed restart also restores the original mode.
    request.addfinalizer(restore)
    if original != "true":
        asic.run_sonic_db_cli_cmd(
            'CONFIG_DB HSET "DEVICE_METADATA|localhost" "frr_mgmt_framework_config" "true"')
        restart_bgp()
    return node, namespaces, asic


def test_isis_cli_namespace_isolation(isis_namespace):
    node, namespaces, asic = isis_namespace
    namespace = asic.namespace
    container = asic.get_docker_name("bgp")
    before = {name: _snapshot(node, name) for name in namespaces}
    other_neighbors = {
        name: _neighbors(node, "bgp" + name[4:])
        for name in namespaces[1:]
    }
    try:
        _run(node, "sudo config isis -n {} add ISIS_NS_TEST".format(namespace))
        _run(node, "sudo config isis -n {} lsp-mtu ISIS_NS_TEST 1380".format(namespace))
        pytest_assert(wait_until(45, 2, 0, _installed, node, container), "Instance missing from selected container")
        shown = json.loads(_run(node, "sudo show isis -n {} configuration --instance ISIS_NS_TEST".format(namespace)))
        pytest_assert(shown["ISIS_GLOBALS"]["default|ISIS_NS_TEST"]["explicit"] == {"lsp_mtu": "1380"},
                      "Selected namespace query returned incorrect ConfigDB fields")
        actual = json.loads(_run(node, "sudo show isis -n {} interface --json".format(namespace)))
        native = json.loads(_run(node, "sudo docker exec {} vtysh -c 'show isis interface json'".format(container)))
        pytest_assert(actual == native, "Namespace show wrapper selected the wrong daemon")
        for name in namespaces[1:]:
            pytest_assert(_snapshot(node, name) == before[name], "IS-IS changed another ASIC's ConfigDB")
            current = _neighbors(node, "bgp" + name[4:])
            # Neighbor JSON has live uptime/hold timers. Compare identities and states.
            pytest_assert(_neighbor_states(current) == _neighbor_states(other_neighbors[name]),
                          "IS-IS changed another ASIC's daemon or neighbors")
    finally:
        _run(node, "sudo config isis -n {} del ISIS_NS_TEST".format(namespace))
    pytest_assert(_snapshot(node, namespace) == before[namespace], "Namespace cleanup changed existing ConfigDB")


def _neighbor_states(data):
    volatile = {"uptime", "up-time", "holdtime", "hold-time", "expires-in",
                "lastUpdate", "lastUpdated", "last-updated"}
    if isinstance(data, dict):
        return {key: _neighbor_states(value) for key, value in data.items() if key not in volatile}
    if isinstance(data, list):
        return [_neighbor_states(value) for value in data]
    return data
