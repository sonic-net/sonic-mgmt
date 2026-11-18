"""Installed IS-IS namespace selection on multi-ASIC SONiC."""
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


def test_isis_cli_namespace_isolation(rand_selected_dut):
    node = rand_selected_dut
    if not node.is_multi_asic:
        pytest.skip("IS-IS namespace device coverage requires a multi-ASIC testbed")
    namespaces = node.get_frontend_asic_namespace_list()
    if len(namespaces) < 2:
        pytest.skip("IS-IS namespace isolation requires two frontend ASIC namespaces")
    namespace = namespaces[0]
    pytest_assert(re.fullmatch(r"asic[0-9]+", namespace), "Unexpected ASIC namespace: " + namespace)
    container = "bgp" + namespace[4:]
    before = {name: _snapshot(node, name) for name in namespaces}
    pytest_assert(before[namespace].get("DEVICE_METADATA", {}).get("localhost", {}).get(
        "frr_mgmt_framework_config") == "true", "FRR management framework is disabled")
    pytest_assert("default|ISIS_NS_TEST" not in before[namespace].get("ISIS_GLOBALS", {}),
                  "Temporary namespace instance already exists")
    other_neighbors = {
        name: json.loads(_run(node, "sudo docker exec bgp{} vtysh -c 'show isis neighbor json'".format(name[4:])))
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
            current = json.loads(_run(
                node, "sudo docker exec bgp{} vtysh -c 'show isis neighbor json'".format(name[4:])))
            # Neighbor JSON has live uptime/hold timers. Compare identities and states.
            pytest_assert(_neighbor_states(current) == _neighbor_states(other_neighbors[name]),
                          "IS-IS changed another ASIC's neighbors")
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
