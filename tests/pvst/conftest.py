import pytest
import logging
from tests.common.helpers.assertions import pytest_assert as py_assert

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module", autouse=True)
def check_stp_feature_status(duthost):
    feature_status_output = duthost.show_and_parse("show feature status")
    stp_feature = next((feature for feature in feature_status_output if feature["feature"] == "stp"), None)
    if not stp_feature or stp_feature["state"] != "enabled":
        pytest.skip("STP feature is either not present or not enabled")


@pytest.fixture(scope="class", autouse=True)
def enable_pvst_and_verify(duthosts, rand_one_dut_hostname):

    """
    Enable PVST using CLI and verify 'STP|GLOBAL' exists in Redis DB 4.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Step 1: Enable PVST
    duthost.shell("config spanning-tree enable pvst", module_ignore_errors=True)

    # Step 2: Validate STP|GLOBAL exists in Redis DB 4
    redis_check = duthost.shell("redis-cli -n 4 keys 'STP|GLOBAL'", module_ignore_errors=True)

    py_assert("STP|GLOBAL" in redis_check["stdout"],
              "Failed to find 'STP|GLOBAL' in Redis DB 4 — PVST not applied.")

    yield

    duthost.shell("config spanning-tree disable pvst", module_ignore_errors=True)


@pytest.fixture(scope="module", autouse=True)
def setup_pvst_test_data(duthosts, rand_one_dut_hostname, ptfhost, tbinfo):
    """
    Fixture that gathers and returns a structured dictionary with:
    - DUT/PTF port mappings
    - VLAN ID
    - Loopback info
    - MACs, interface details, etc.
    Used for PVST protocol validation.
    """
    duthost = duthosts[rand_one_dut_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    # Step 1: Gather VLAN members (Ethernet only)
    vlan_name, vlan_info = list(mg_facts["minigraph_vlans"].items())[0]
    vlan_members = [port for port in vlan_info["members"] if "Ethernet" in port]

    dut_port_1 = sorted(vlan_members, key=lambda x: int(x.replace("Ethernet", "")))[0]
    dut_port_2 = sorted(vlan_members, key=lambda x: int(x.replace("Ethernet", "")))[1]

    # Step 2: Get PTF port indices
    ptf_indices = mg_facts["minigraph_ptf_indices"]
    ptf_port_1 = ptf_indices[dut_port_1]
    ptf_port_2 = ptf_indices[dut_port_2]

    # Step 3: Get VLAN ID
    vlan_id = vlan_info["vlanid"]

    # Step 4: Get port MAC
    host_facts = duthost.setup()['ansible_facts']

    intf_mac_map = {
        k.replace('ansible_', ''): v['macaddress']
        for k, v in host_facts.items()
        if k.startswith('ansible_') and isinstance(v, dict) and 'macaddress' in v
    }

    mac_address = intf_mac_map.get(dut_port_1)

    # Build result
    pvst_data = {
        "vlan": {
            "id": vlan_id,
        },
        "dut_ports": {
            "dut_port_1": dut_port_1, "mac": mac_address, "ptf_port_1": ptf_port_1,
            "dut_port_2": dut_port_2, "ptf_port_2": ptf_port_2
        }
    }

    return pvst_data
