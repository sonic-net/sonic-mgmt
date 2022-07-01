import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.fixtures.duthost_utils import utils_vlan_intfs_dict_orig, utils_vlan_intfs_dict_add, utils_create_test_vlans
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_res_success, expect_op_failure
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload, rollback

pytestmark = [
    pytest.mark.topology('t0'),
]

logger = logging.getLogger(__name__)

DHCP_RELAY_TIMEOUT   = 120
DHCP_RELAY_INTERVAL  = 10
SETUP_ENV_CP         = "test_setup_checkpoint"
CONFIG_ADD_DEFAULT   = "config_add_default"


@pytest.fixture(scope="module")
def vlan_intfs_dict(utils_vlan_intfs_dict_orig):
    """ Add two new vlan for test

    If added vlan_id is 108 and 109, it will add a dict as below
    {108: {'ip': u'192.168.8.1/24', 'orig': False},
     109: {'ip': u'192.168.9.1/24', 'orig': False}}
    """
    logger.info("vlan_intrfs_dict ORIG {}".format(utils_vlan_intfs_dict_orig))
    vlan_intfs_dict = utils_vlan_intfs_dict_add(utils_vlan_intfs_dict_orig, 2)
    logger.info("vlan_intrfs_dict FINAL {}".format(vlan_intfs_dict))
    return vlan_intfs_dict


@pytest.fixture(scope="module")
def first_avai_vlan_port(rand_selected_dut, tbinfo):
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    logger.info("Find a vlan port for new created vlan member")

    for v in mg_facts['minigraph_vlans'].values():
        for p in v['members']:
            if p.startswith("Ethernet"):
                return p

    logger.error("No vlan port member ready for test")
    pytest_assert(False, "No vlan port member ready for test")


def ensure_dhcp_relay_running(duthost):
    if not duthost.is_service_fully_started('dhcp_relay'):
        duthost.shell('sudo systemctl start dhcp_relay')
        pytest_assert(
            duthost.is_service_fully_started('dhcp_relay'),
            "dhcp_relay service is not running before test dhcp servers"
        )


def create_test_vlans(duthost, cfg_facts, vlan_intfs_dict, first_avai_vlan_port):
    """Generate two vlan config for testing

    This function should generate two VLAN detail shown below
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    |   VLAN ID | IP Address       | Ports     | Port Tagging   | Proxy ARP   | DHCP Helper Address   |
    +===========+==================+===========+================+=============+=======================+
    |       108 | 192.168.8.1/24   | Ethernet4 | tagged         | disabled    |                       |
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    |       109 | 192.168.9.1/24   | Ethernet4 | tagged         | disabled    |                       |
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    """

    logger.info("CREATE TEST VLANS START")
    vlan_ports_list = [{
        'dev': first_avai_vlan_port,
        'port_index' : 'unused',
        'permit_vlanid' : [ key for key, value in vlan_intfs_dict.items() ],
        'pvid': 0
    }]

    utils_create_test_vlans(duthost, cfg_facts, vlan_ports_list, vlan_intfs_dict, delete_untagged_vlan=False)
    logger.info("CREATE TEST VLANS DONE")


def default_setup(duthost, vlan_intfs_list):
    """Generate 4 dhcp server for each vlan

    This VLAN detail shows below
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    |   VLAN ID | IP Address       | Ports     | Port Tagging   | Proxy ARP   | DHCP Helper Address   |
    +===========+==================+===========+================+=============+=======================+
    |       108 | 192.168.108.1/24 | Ethernet4 | tagged         | disabled    | 192.0.108.1           |
    |           |                  |           |                |             | 192.0.108.2           |
    |           |                  |           |                |             | 192.0.108.3           |
    |           |                  |           |                |             | 192.0.108.4           |
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    |       109 | 192.168.109.1/24 | Ethernet4 | tagged         | disabled    | 192.0.109.1           |
    |           |                  |           |                |             | 192.0.109.2           |
    |           |                  |           |                |             | 192.0.109.3           |
    |           |                  |           |                |             | 192.0.109.4           |
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    """
    cmds = []
    expected_content_dict = {}
    logger.info("default_setup is initiated")
    # Generate 4 dhcp servers for each new created vlan
    for vlan in vlan_intfs_list:
        expected_content_dict[vlan] = []
        for i in range(1, 5):
            cmds.append('config vlan dhcp_relay add {} 192.0.{}.{}'.format(vlan, vlan, i))
            expected_content_dict[vlan].append('192.0.{}.{}'.format(vlan, i))

    duthost.shell_cmds(cmds=cmds)

    pytest_assert(
        duthost.is_service_fully_started('dhcp_relay'),
        "dhcp_relay service is not running during setup"
    )

    logger.info("default setup expected_content_dict {}".format(expected_content_dict))
    for vlanid in expected_content_dict:
        expect_res_success_by_vlanid(duthost, vlanid, expected_content_dict[vlanid], [])

    logger.info("default_setup DONE")


def get_dhcp_relay_info_from_all_vlans(duthost):
    """ Get dhcp relay info from all vlans

    Sample output for CONFIG_ADD_DEFAULT:
    admin@vlab-01:~$ sonic-db-cli CONFIG_DB keys "VLAN|*" | xargs -I {} sonic-db-cli CONFIG_DB hgetall "{}"
    {'vlanid': '108', 'dhcp_servers@': '192.0.108.1,192.0.108.2,192.0.108.3,192.0.108.4'}
    {'dhcp_servers@': '192.0.0.1,192.0.0.2,192.0.0.3,192.0.0.4', 'dhcpv6_servers@': 'fc02:2000::1,fc02:2000::2,fc02:2000::3,fc02:2000::4', 'vlanid': '1000'}
    {'vlanid': '109', 'dhcp_servers@': '192.0.109.1,192.0.109.2,192.0.109.3,192.0.109.4'}
    """
    cmds = 'sonic-db-cli CONFIG_DB keys "VLAN|*" | xargs -I {} sonic-db-cli CONFIG_DB hgetall "{}"'
    dhcp_server_info = duthost.shell(cmds)
    pytest_assert(not dhcp_server_info['rc'],
        "Failed to get dhcp relay info from all vlan"
    )
    return dhcp_server_info['stdout']


@pytest.fixture(autouse=True)
def setup_vlan(duthosts, rand_one_dut_hostname, vlan_intfs_dict, first_avai_vlan_port, cfg_facts, vlan_intfs_list):
    duthost = duthosts[rand_one_dut_hostname]
    create_checkpoint(duthost)

    # --------------------- Setup -----------------------
    create_test_vlans(duthost, cfg_facts, vlan_intfs_dict, first_avai_vlan_port)
    ensure_dhcp_relay_running(duthost)

    default_setup(duthost, vlan_intfs_list)

    dhcp_relay_info_before_test = get_dhcp_relay_info_from_all_vlans(duthost)
    create_checkpoint(duthost, SETUP_ENV_CP)
    # --------------------- Testing -----------------------
    yield

    # --------------------- Teardown -----------------------
    # Rollback twice. First rollback to checkpoint just before 'yield'
    # Second rollback is to back to original setup
    try:
        output = rollback(duthost, SETUP_ENV_CP)
        pytest_assert(
            not output['rc'] and "Config rolled back successfull" in output['stdout'],
            "Rollback to previous setup env failed."
        )

        dhcp_relay_info_after_test = get_dhcp_relay_info_from_all_vlans(duthost)
        pytest_assert(
            dhcp_relay_info_before_test == dhcp_relay_info_after_test,
            "dhcp relay info should be the same after rollback"
        )

        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost, SETUP_ENV_CP)
        delete_checkpoint(duthost)


@pytest.fixture(scope="module")
def vlan_intfs_list(vlan_intfs_dict):
    return [ key for key, value in vlan_intfs_dict.items() if not value['orig'] ]


def ensure_dhcp_server_up(duthost):
    """Wait till dhcp-relay server is setup

    Sample output
    admin@vlab-01:~$ docker exec dhcp_relay supervisorctl status | grep ^dhcp-relay
    dhcp-relay:isc-dhcpv4-relay-Vlan100    RUNNING   pid 72, uptime 0:00:09
    dhcp-relay:isc-dhcpv4-relay-Vlan1000   RUNNING   pid 73, uptime 0:00:09

    """
    def _dhcp_server_up():
        cmds = 'docker exec dhcp_relay supervisorctl status | grep ^dhcp-relay'
        output = duthost.shell(cmds)
        pytest_assert(
            not output['rc'],
            "'{}' is not running successfully".format(cmds)
        )

        return 'RUNNING' in output['stdout']

    pytest_assert(
        wait_until(DHCP_RELAY_TIMEOUT, DHCP_RELAY_INTERVAL, 0, _dhcp_server_up),
        "The dhcp relay server is not running"
    )


def dhcp_severs_by_vlanid(duthost, vlanid):
    """Get pid and then only output the related dhcp server info for that pid

    Sample output
    admin@vlab-01:~$ docker exec dhcp_relay ps -fp 73
    UID          PID    PPID  C STIME TTY          TIME CMD
    root          73       1  0 06:39 pts/0    00:00:00 /usr/sbin/dhcrelay -d -m discard -a %h:%p %P --name-alias-map-file /tmp/port-name-alias-map.txt -id Vlan1000 -iu Vlan100 -iu PortChannel0001 -iu PortChannel0002 -iu PortChannel0003 -iu PortChannel0004 192.0.0.1 192.0.0.2 192.0.0.3 192.0.0.4
    """
    cmds = "docker exec dhcp_relay supervisorctl status \
        | grep 'dhcpv4-relay-Vlan{} ' | awk '{{print $4}}'".format(vlanid)
    output = duthost.shell(cmds)
    pytest_assert(
        not output['rc'],
        "'{}' is not running successfully".format(cmds)
    )

    pid = output['stdout'].strip(",")
    logger.info("pid {} for Vlan{}".format(pid, vlanid))

    cmds = 'docker exec dhcp_relay ps -fp {} | sed "1d"'.format(pid)
    output = duthost.shell(cmds)
    pytest_assert(
        not output['rc'],
        "'{}' is not running successfully".format(cmds)
    )

    return output


def expect_res_success_by_vlanid(duthost, vlanid, expected_content_list, unexpected_content_list):
    ensure_dhcp_server_up(duthost)
    output = dhcp_severs_by_vlanid(duthost, vlanid)
    expect_res_success(duthost, output, expected_content_list, unexpected_content_list)


# DHCP_RELAY TEST
def test_dhcp_relay_tc1_rm_nonexist(rand_selected_dut, vlan_intfs_list):
    """Test remove nonexisted dhcp server on default setup
    """
    dhcp_rm_nonexist_json = [
        {
            "op": "remove",
            "path": "/VLAN/Vlan"+ str(vlan_intfs_list[0]) + "/dhcp_servers/5"
        }]

    tmpfile = generate_tmpfile(rand_selected_dut)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(rand_selected_dut, json_data=dhcp_rm_nonexist_json, dest_file=tmpfile)
        expect_op_failure(output)
    finally:
        delete_tmpfile(rand_selected_dut, tmpfile)


def test_dhcp_relay_tc2_add_exist(rand_selected_dut, vlan_intfs_list):
    """Test add existed dhcp server on default setup
    """
    dhcp_add_exist_json = [
        {
            "op": "add",
            "path": "/VLAN/Vlan" + str(vlan_intfs_list[0]) + "/dhcp_servers/0",
            "value": "192.0." + str(vlan_intfs_list[0]) + ".1"
        }]

    tmpfile = generate_tmpfile(rand_selected_dut)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(rand_selected_dut, json_data=dhcp_add_exist_json, dest_file=tmpfile)
        expect_op_failure(output)
    finally:
        delete_tmpfile(rand_selected_dut, tmpfile)


def test_dhcp_relay_tc3_add_and_rm(rand_selected_dut, vlan_intfs_list):
    """Test mixed add and rm ops for dhcp server on default setup

    This VLAN detail should show below after test
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    |   VLAN ID | IP Address       | Ports     | Port Tagging   | Proxy ARP   | DHCP Helper Address   |
    +===========+==================+===========+================+=============+=======================+
    |       108 | 192.168.108.1/24 | Ethernet4 | tagged         | disabled    | 192.0.108.1           |
    |           |                  |           |                |             | 192.0.108.2           |
    |           |                  |           |                |             | 192.0.108.3           |
    |           |                  |           |                |             | 192.0.108.4           |
    |           |                  |           |                |             | 192.0.108.5           |
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    |       109 | 192.168.109.1/24 | Ethernet4 | tagged         | disabled    | 192.0.109.1           |
    |           |                  |           |                |             | 192.0.109.2           |
    |           |                  |           |                |             | 192.0.109.3           |
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    """
    dhcp_add_rm_json = [
        {
            "op": "remove",
            "path": "/VLAN/Vlan" + str(vlan_intfs_list[1]) + "/dhcp_servers/3"
        },
        {
            "op": "add",
            "path": "/VLAN/Vlan" + str(vlan_intfs_list[0]) + "/dhcp_servers/4",
            "value": "192.0." + str(vlan_intfs_list[0]) + ".5"
        }]

    tmpfile = generate_tmpfile(rand_selected_dut)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(rand_selected_dut, json_data=dhcp_add_rm_json, dest_file=tmpfile)
        expect_op_success(rand_selected_dut, output)
        pytest_assert(
            rand_selected_dut.is_service_fully_started('dhcp_relay'),
            "dhcp_relay service is not running"
        )

        expected_content_list = ["192.0." + str(vlan_intfs_list[0]) + ".5"]
        unexpected_content_list = ["192.0." + str(vlan_intfs_list[1]) + ".4"]
        expect_res_success_by_vlanid(rand_selected_dut, vlan_intfs_list[0], expected_content_list, [])
        expect_res_success_by_vlanid(rand_selected_dut, vlan_intfs_list[1], [], unexpected_content_list)
    finally:
        delete_tmpfile(rand_selected_dut, tmpfile)


def test_dhcp_relay_tc4_replace(rand_selected_dut, vlan_intfs_list):
    """Test replace dhcp server on default setup

    This VLAN detail should show below after test
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    |   VLAN ID | IP Address       | Ports     | Port Tagging   | Proxy ARP   | DHCP Helper Address   |
    +===========+==================+===========+================+=============+=======================+
    |       108 | 192.168.108.1/24 | Ethernet4 | tagged         | disabled    | 192.0.108.2           |
    |           |                  |           |                |             | 192.0.108.3           |
    |           |                  |           |                |             | 192.0.108.4           |
    |           |                  |           |                |             | 192.0.108.8           |
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    |       109 | 192.168.109.1/24 | Ethernet4 | tagged         | disabled    | 192.0.109.1           |
    |           |                  |           |                |             | 192.0.109.2           |
    |           |                  |           |                |             | 192.0.109.3           |
    |           |                  |           |                |             | 192.0.109.4           |
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    """
    dhcp_replace_json = [
        {
            "op": "replace",
            "path": "/VLAN/Vlan" + str(vlan_intfs_list[0]) + "/dhcp_servers/0",
            "value": "192.0." + str(vlan_intfs_list[0]) + ".8"
        }]

    tmpfile = generate_tmpfile(rand_selected_dut)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(rand_selected_dut, json_data=dhcp_replace_json, dest_file=tmpfile)
        expect_op_success(rand_selected_dut, output)
        pytest_assert(
            rand_selected_dut.is_service_fully_started('dhcp_relay'),
            "dhcp_relay service is not running"
        )

        expected_content_list = ["192.0." + str(vlan_intfs_list[0]) + ".8"]
        unexpected_content_list = ["192.0." + str(vlan_intfs_list[0]) + ".1"]
        expect_res_success_by_vlanid(rand_selected_dut, vlan_intfs_list[0], expected_content_list, unexpected_content_list)
    finally:
        delete_tmpfile(rand_selected_dut, tmpfile)
