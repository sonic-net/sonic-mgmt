import logging
from mx_utils import remove_all_vlans
import json
import jsonpatch
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require
from tests.common.utilities import wait_until
from tests.dhcp_server.dhcp_server_test_common import verify_discover_and_request_then_release, \
    apply_dhcp_server_config_gcu, clean_dhcp_server_config


pytestmark = [
    pytest.mark.topology('mx')
]


DHCP_RELAY_CONTAINER_NAME = "dhcp_relay"
DHCP_SERVER_CONTAINER_NAME = "dhcp_server"
DHCP_SERVER_FEATRUE_NAME = "dhcp_server"
DHCP_SERVER_CONFIG_INTERFACE_KEY = "DHCP_SERVER_IPV4"
DHCP_SERVER_CONFIG_PORT_KEY = "DHCP_SERVER_IPV4_PORT"
MX_VLAN_AND_DHCP_SERVER_CONF_PATH = "mx/config/mx_vlan_dhcp_server_conf.json"


@pytest.fixture(scope="module", autouse=True)
def dhcp_server_setup_teardown(duthost):
    features_state, _ = duthost.get_feature_status()
    pytest_require(DHCP_SERVER_FEATRUE_NAME in features_state, "Skip on testbed without dhcp server feature")
    restore_state_flag = False
    if "enabled" not in features_state.get(DHCP_SERVER_FEATRUE_NAME, ""):
        restore_state_flag = True
        duthost.shell("config feature state dhcp_server enabled")
        duthost.shell("sudo systemctl restart dhcp_relay.service")

    def is_supervisor_subprocess_running(duthost, container_name, app_name):
        return "RUNNING" in duthost.shell(f"docker exec {container_name} supervisorctl status {app_name}")["stdout"]
    pytest_assert(
        wait_until(60, 1, 1,
                   is_supervisor_subprocess_running,
                   duthost,
                   DHCP_SERVER_CONTAINER_NAME,
                   "dhcp-server-ipv4:kea-dhcp4"),
        'feature dhcp_server is enabled but container is not running'
    )
    pytest_assert(
        wait_until(60, 1, 1,
                   is_supervisor_subprocess_running,
                   duthost,
                   DHCP_RELAY_CONTAINER_NAME,
                   "dhcp-relay:dhcprelayd"),
        'dhcprelayd in container dhcp_relay is not running'
    )

    yield

    if restore_state_flag:
        duthost.shell("config feature state dhcp_server disabled", module_ignore_errors=True)
        duthost.shell("sudo systemctl restart dhcp_relay.service")
        duthost.shell("docker rm dhcp_server", module_ignore_errors=True)


@pytest.mark.parametrize("vlan_count", ["1", "4"])
def test_dhcp_server_ip_assignment(
    duthost,
    ptfhost,
    ptfadapter,
    vlan_count,
    mx_common_setup_teardown
):
    _, ptf_index_port, _ = mx_common_setup_teardown
    #  We don't restore vlan config after tests for mx, we remove all vlans before tests
    remove_all_vlans(duthost)
    clean_dhcp_server_config(duthost)
    dhcp_server_config = json.load(open(MX_VLAN_AND_DHCP_SERVER_CONF_PATH, "r")).get(vlan_count, [])
    gcu_patch = jsonpatch.make_patch({}, dhcp_server_config).patch
    apply_dhcp_server_config_gcu(duthost, gcu_patch)

    test_sets = []
    test_xid = 1
    dhcp_ints_config = dhcp_server_config.get(DHCP_SERVER_CONFIG_INTERFACE_KEY)
    for name, conf in dhcp_server_config.get(DHCP_SERVER_CONFIG_PORT_KEY).items():
        vlan_name = name.split("|")[0]
        dut_port_name = name.split("|")[1]
        dut_port_number = int(dut_port_name.replace("Ethernet", ""))
        ptf_port_index = int(ptf_index_port[dut_port_number])
        gateway = dhcp_ints_config.get(vlan_name).get("gateway")
        net_mask = dhcp_ints_config.get(vlan_name).get("netmask")
        lease_time = int(dhcp_ints_config.get(vlan_name).get("lease_time"))
        exp_assigned_ip = conf["ips"][0]
        test_sets.append((vlan_name, gateway, net_mask, dut_port_name,
                          ptf_port_index, exp_assigned_ip, lease_time, test_xid))
        test_xid += 1

    for vlan_name, gateway, net_mask, dut_port, ptf_port_index, exp_assigned_ip, exp_lease_time, test_xid in test_sets:
        logging.info("Testing for vlan %s, gateway %s, net_mask %s dut_port %s, ptf_port_index %s, \
                        expected_assigned_ip %s, test_xid %s" % (vlan_name, gateway, net_mask, dut_port,
                                                                 ptf_port_index, exp_assigned_ip, test_xid))
        verify_discover_and_request_then_release(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            dut_port_to_capture_pkt=dut_port,
            ptf_port_index=ptf_port_index,
            ptf_mac_port_index=ptf_port_index,
            test_xid=test_xid,
            dhcp_interface=vlan_name,
            expected_assigned_ip=exp_assigned_ip,
            exp_gateway=gateway,
            server_id=gateway,
            net_mask=net_mask,
            exp_lease_time=exp_lease_time
        )
