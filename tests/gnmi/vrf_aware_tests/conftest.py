import pytest

from tests.common.utilities import DEFAULT_VRF_NAME, MGMT_VRF_NAME
from tests.gnmi.helper import find_unused_subnet, get_intfs_pair_with_vlan, is_mgmt_vrf_enabled


CUSTOM_VRF_NAME = "Vrf-FOO"
VRF_SCENARIOS = [
    {"name": "default_1", "vrf": None, "description": "Default (no VRF)"},
    {"name": "default_2", "vrf": DEFAULT_VRF_NAME, "description": f"Default (explicit '{DEFAULT_VRF_NAME}')"},
    {"name": "mgmt", "vrf": MGMT_VRF_NAME, "description": "Management VRF"},
    {"name": "custom", "vrf": CUSTOM_VRF_NAME, "description": f"Custom VRF ({CUSTOM_VRF_NAME})"}
]
DEFAULT_SNMP_PORT = 161


@pytest.fixture(scope="module", params=VRF_SCENARIOS, ids=lambda scenario: f"vrf_{scenario['name']}")
def vrf_config(request, duthost, ptfhost):
    tbname = request.config.getoption("--testbed")
    vrf_cfg = request.param.copy()
    vrf_name = vrf_cfg["vrf"]
    if (not tbname or "t0" not in tbname) and vrf_name == CUSTOM_VRF_NAME:
        pytest.skip("Skipping custom VRF test on non-T0 topology")
    if vrf_name and vrf_name == CUSTOM_VRF_NAME:
        # Use a new subnet for VRF paths
        subnet = find_unused_subnet(duthost, ptfhost)
        assert subnet, "Failed to find an unused subnet"
        dut_intf, dut_vlan, ptf_intf = get_intfs_pair_with_vlan(duthost)
        assert None not in (dut_intf, ptf_intf), "Failed to find available DUT interfaces"
        vrf_cfg.update({
            "custom_subnet": subnet,
            "dut_ip": f"{subnet.network_address + 1}",
            "ptf_ip": f"{subnet.network_address + 2}",
            "dut_intf": dut_intf,
            "ptf_intf": ptf_intf,
            "vlan_id": dut_vlan
        })
    else:
        vrf_cfg.update({
            "custom_subnet": None,
            "dut_ip": duthost.mgmt_ip,
            "ptf_ip": ptfhost.mgmt_ip,
            "dut_intf": "eth0",
            "ptf_intf": "mgmt",
            "vlan_id": None
        })
    return vrf_cfg


def setup_vrf_route(duthost, ptfhost, vrf_name, subnet, dut_ip, ptf_ip, dut_intf, ptf_intf, vlan_id):
    if vlan_id:
        duthost.shell(
            f"sudo config vlan member del {vlan_id} {dut_intf}",
            module_ignore_errors=True
        )
    duthost.shell(f"sudo config interface vrf bind {dut_intf} {vrf_name}", module_ignore_errors=True)
    duthost.shell(f"sudo config interface ip add {dut_intf} {dut_ip}/{subnet.prefixlen}")
    ptfhost.shell(f"ip addr add {ptf_ip}/{subnet.prefixlen} dev {ptf_intf}")


def teardown_vrf_route(duthost, ptfhost, subnet, ptf_ip, dut_intf, ptf_intf, vlan_id):
    duthost.shell(f"sudo config interface vrf unbind {dut_intf}", module_ignore_errors=True)
    if vlan_id:
        duthost.shell(f"sudo config vlan member add {vlan_id} {dut_intf} -u", module_ignore_errors=True)
    ptfhost.shell(f"ip addr del {ptf_ip}/{subnet.prefixlen} dev {ptf_intf}")


def configure_snmp_with_vrf(duthost, agent_ip, vrf_name):
    """
    Configures SNMP agent address with VRF.
    Misconfigured snmp agent address causes snmpd and snmp-subagent to fail
    during startup.
    While the GNMI tests do not depend directly on SNMP, some tests fail while
    waiting for all critical processes to be up and running.
    """
    output = duthost.shell(
        f'sudo sonic-db-cli CONFIG_DB KEYS "SNMP_AGENT_ADDRESS_CONFIG|{agent_ip}|*"'
    )
    output = output['stdout'].split("|")
    if len(output) < 4:
        duthost.shell(
            f'sonic-db-cli CONFIG_DB HSET '
            f'"SNMP_AGENT_ADDRESS_CONFIG|{agent_ip}|{DEFAULT_SNMP_PORT}|{vrf_name}" '
            f'"agent_ip" "{agent_ip}" "port" "{DEFAULT_SNMP_PORT}" "vrf_name" "{vrf_name}"'
        )
    else:
        port = output[2]
        duthost.shell(
            f'sonic-db-cli CONFIG_DB DEL '
            f'"SNMP_AGENT_ADDRESS_CONFIG|{agent_ip}|{port}|{output[3]}"'
        )
        duthost.shell(
            f'sonic-db-cli CONFIG_DB HSET '
            f'"SNMP_AGENT_ADDRESS_CONFIG|{agent_ip}|{port}|{vrf_name}" '
            f'"agent_ip" "{agent_ip}" "port" "{port}" "vrf_name" "{vrf_name}"'
        )


@pytest.fixture(scope="module", autouse=True)
def setup_vrf_configuration(duthosts, rand_one_dut_hostname, ptfhost, vrf_config):
    """
    This fixture runs before setup_gnmi_server to ensure VRF config is in place.
    """
    duthost = duthosts[rand_one_dut_hostname]
    vrf_name = vrf_config["vrf"]
    mgmt_vrf_enabled = is_mgmt_vrf_enabled(duthost)
    custom_subnet = vrf_config["custom_subnet"]
    dut_intf = vrf_config["dut_intf"]
    ptf_intf = vrf_config["ptf_intf"]
    dut_ip = vrf_config["dut_ip"]
    ptf_ip = vrf_config["ptf_ip"]
    vlan_id = vrf_config["vlan_id"]

    try:
        if vrf_name == MGMT_VRF_NAME and not mgmt_vrf_enabled:
            duthost.shell('sonic-db-cli CONFIG_DB hset "MGMT_VRF_CONFIG|vrf_global" "mgmtVrfEnabled" "true"')
            configure_snmp_with_vrf(duthost, duthost.mgmt_ip, vrf_name)
            configure_snmp_with_vrf(duthost, duthost.mgmt_ipv6, vrf_name)
        elif vrf_name and vrf_name not in {DEFAULT_VRF_NAME, MGMT_VRF_NAME}:
            duthost.shell(f'sonic-db-cli CONFIG_DB hset "VRF|{vrf_name}" "NULL" "NULL"')
            setup_vrf_route(duthost, ptfhost, vrf_name, custom_subnet, dut_ip, ptf_ip, dut_intf, ptf_intf, vlan_id)
        yield vrf_config

    finally:
        if vrf_name == MGMT_VRF_NAME and not mgmt_vrf_enabled:
            duthost.shell('sonic-db-cli CONFIG_DB hset "MGMT_VRF_CONFIG|vrf_global" "mgmtVrfEnabled" "false"')
            duthost.shell('sonic-db-cli CONFIG_DB hdel "MGMT_VRF_CONFIG|vrf_global" "mgmtVrfEnabled"')
            configure_snmp_with_vrf(duthost, duthost.mgmt_ip, "")
            configure_snmp_with_vrf(duthost, duthost.mgmt_ipv6, "")
        elif vrf_name and vrf_name not in {DEFAULT_VRF_NAME, MGMT_VRF_NAME}:
            teardown_vrf_route(duthost, ptfhost, custom_subnet, ptf_ip, dut_intf, ptf_intf, vlan_id)
            duthost.shell(f'sonic-db-cli CONFIG_DB del "VRF|{vrf_name}"', module_ignore_errors=True)
