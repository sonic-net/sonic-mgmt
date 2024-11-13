import logging
from mx_utils import remove_all_vlans
import json
import jsonpatch
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require
from tests.common.utilities import wait_until
from tests.dhcp_server.dhcp_server_test_common import verify_discover_and_request_then_release, \
    apply_dhcp_server_config_gcu, clean_dhcp_server_config, DHCP_SERVER_CONFIG_TOOL_GCU

pytestmark = [
    pytest.mark.topology('mx')
]


DHCP_SERVER_CONFIG_TOOL_GOLDEN = 'golden'
DHCP_RELAY_CONTAINER_NAME = "dhcp_relay"
DHCP_SERVER_CONTAINER_NAME = "dhcp_server"
DHCP_SERVER_FEATRUE_NAME = "dhcp_server"
DHCP_SERVER_CONFIG_INTERFACE_KEY = "DHCP_SERVER_IPV4"
DHCP_SERVER_CONFIG_PORT_KEY = "DHCP_SERVER_IPV4_PORT"
MX_VLAN_AND_DHCP_SERVER_CONF_PATH = "mx/config/mx_vlan_dhcp_server_conf.json"


@pytest.fixture(scope="function", autouse=True)
def clean_dhcp_server_config_after_test(duthost, mx_common_setup_teardown):
    clean_dhcp_server_config(duthost)

    yield

    clean_dhcp_server_config(duthost)


def is_supervisor_subprocess_running(duthost, container_name, app_name):
    return "RUNNING" in duthost.shell(f"docker exec {container_name} supervisorctl status {app_name}")["stdout"]


@pytest.fixture(scope="module", autouse=True)
def dhcp_server_setup_teardown(duthost):
    features_state, _ = duthost.get_feature_status()
    pytest_require(DHCP_SERVER_FEATRUE_NAME in features_state, "Skip on testbed without dhcp server feature")
    restore_state_flag = False
    if "enabled" not in features_state.get(DHCP_SERVER_FEATRUE_NAME, ""):
        restore_state_flag = True
        duthost.shell("config feature state dhcp_server enabled")
        duthost.shell("sudo systemctl restart dhcp_relay.service")

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


def apply_dhcp_server_config_golden(duthost, config_to_apply):
    logging.info("The dhcp_server_config: %s" % config_to_apply)
    tmpfile = duthost.shell('mktemp')['stdout']
    try:
        duthost.copy(content=json.dumps(config_to_apply, indent=4), dest=tmpfile)
        output = duthost.shell('config load_minigraph --override_config --golden_config_path {} -y'
                               .format(tmpfile), module_ignore_errors=True)
        pytest_assert(not output['rc'], "Command is not running successfully")
    finally:
        duthost.file(path=tmpfile, state='absent')


@pytest.mark.parametrize("vlan_count", ["1", "4"])
@pytest.mark.parametrize("config_tool", [DHCP_SERVER_CONFIG_TOOL_GCU, DHCP_SERVER_CONFIG_TOOL_GOLDEN])
def test_dhcp_server_ip_assignment(
    duthost,
    ptfhost,
    ptfadapter,
    vlan_count,
    mx_common_setup_teardown,
    config_tool,
    loganalyzer
):
    #  We don't restore vlan config after tests for mx, we remove all vlans before tests
    loganalyzer[duthost.hostname].ignore_regex.append(".*processFlexCounterEvent: port VID oid:.*, " +
                                                      "was not found \(probably port was removed\/splitted\).*")
    dhcp_server_config = json.load(open(MX_VLAN_AND_DHCP_SERVER_CONF_PATH, "r")).get(vlan_count, [])
    loganalyzer[duthost.hostname].add_start_ignore_mark()
    if config_tool == DHCP_SERVER_CONFIG_TOOL_GCU:
        remove_all_vlans(duthost)
        gcu_patch = jsonpatch.make_patch({}, dhcp_server_config).patch
        apply_dhcp_server_config_gcu(duthost, gcu_patch)
    elif config_tool == DHCP_SERVER_CONFIG_TOOL_GOLDEN:
        dhcp_server_config['FEATURE'] = duthost.get_running_config_facts()['FEATURE']
        dhcp_server_config['FEATURE']['dhcp_server'] = {
            'auto_restart': 'enabled', 'check_up_status': 'False', 'delayed': 'False',
            'has_global_scope': 'True', 'has_per_asic_scope': 'False', 'high_mem_alert': 'disabled',
            'set_owner': 'local', 'state': 'enabled', 'support_syslog_rate_limit': 'False'
        }
        dhcp_server_config['PORT'] = duthost.get_running_config_facts()['PORT']
        apply_dhcp_server_config_golden(duthost, dhcp_server_config)
        pytest_assert(
            wait_until(300, 15, 30, lambda: len(duthost.shell('show int st')['stdout_lines']) > 2),
            "intfaces count is abnormal after applying golden config"
        )
        pytest_assert(
            wait_until(
                60, 1, 1,
                is_supervisor_subprocess_running,
                duthost,
                DHCP_SERVER_CONTAINER_NAME,
                "dhcp-server-ipv4:kea-dhcp4"
            ),
            'kea-dhcp4 in container dhcp_server is not running'
        )
        pytest_assert(
            wait_until(
                100, 1, 1,
                is_supervisor_subprocess_running,
                duthost,
                DHCP_RELAY_CONTAINER_NAME,
                "dhcp-relay:dhcprelayd"
            ),
            'dhcprelayd in container dhcp_relay is not running'
        )
    else:
        pytest.fail("Invalid config tool %s" % config_tool)
    loganalyzer[duthost.hostname].add_end_ignore_mark()

    pytest_assert(
        wait_until(
            60, 1, 1,
            lambda _duthost: "docker0:67" in _duthost.shell("ss -tunlp | grep :67")["stdout"],
            duthost
        ),
        'dhcprelay did not listen on docker0:67'
    )

    _, ptf_index_port, _ = mx_common_setup_teardown
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
