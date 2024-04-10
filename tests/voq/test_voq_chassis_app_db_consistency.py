import time
from tests.common.helpers.sonic_db import VoqDbCli, redis_get_keys
import pytest
import logging
from tests.common.reboot import reboot
from tests.common import config_reload
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from tests.common.platform.processes_utils import wait_critical_processes
import tests.common.helpers.voq_lag as voq_lag

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2')
]


def verify_data_in_db(post_change_db_dump, tmp_pc, pc_members, duthosts, pc_nbr_ip, duthost, pc_nbr_ipv6):
    '''
    Verification of additon of tmp_portchannel data in chassis_app_db tables and set
    '''
    # Verification on SYSTEM_LAG_TABLE and SYSTEM_LAG_ID_TABLE
    lag_id = voq_lag.get_lag_id_from_chassis_db(duthosts)
    pytest_assert(lag_id,
                  "Lag Id in Chasiss_APP_DB is missing for portchannel {}".format(tmp_pc))
    # Verifcation on SYSTEM_LAG_MEMBER_TABLE
    voq_lag.verify_lag_member_in_chassis_db(duthosts, pc_members)
    # Verification on SYSTEM_NEIGH for pc_nbr_ip
    voqdb = VoqDbCli(duthosts.supervisor_nodes[0])
    neigh_key = voqdb.get_neighbor_key_by_ip(pc_nbr_ip)
    if tmp_pc not in neigh_key:
        pytest.fail("Portchannel Neigh ip {} is not allocatioed to tmp portchannel {}".format(pc_nbr_ip, tmp_pc))
    # Verification on SYSTEM_NEIGH for pc_nbr_ipv6
    neigh_key = voqdb.get_neighbor_key_by_ip(pc_nbr_ipv6)
    if tmp_pc not in neigh_key:
        pytest.fail("Portchannel Neigh ip {} is not allocatioed to tmp portchannel {}".format(pc_nbr_ipv6, tmp_pc))
    # Verfication on SYSTEM_INTERFACE
    key = "SYSTEM_INTERFACE|{}*{}".format(duthost.sonichost.hostname, tmp_pc)
    pytest_assert(voqdb.get_keys(key),
                  "SYSTEM_INTERFACE in Chasiss_APP_DB is missing for portchannel {}".format(tmp_pc))
    # Verfication on SYSTEM_LAG_ID_SET
    if lag_id not in post_change_db_dump["SYSTEM_LAG_ID_SET"]:
        pytest.fail(
            "Portchannel Lag id {} is not allocatioed to tmp portchannel {} in SYSTEM_LAG_ID_SET".format(pc_nbr_ip,
                                                                                                         tmp_pc))


@pytest.mark.parametrize("test_case", ["dut_reboot", "config_reload_with_config_save", "config_reload_no_config_save"])
def test_voq_chassis_app_db_consistency(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_rand_one_asic_index,
                                        tbinfo, test_case,
                                        localhost):
    """
    The test_voq_chassis_app_db_consistency function validates the data consistency
    within the CHASSIS_APP_DB. This test do dynamic alterations to port channel
    configurations and IP address assignments, followed by system-level events
    like config_reload and dut_reboot. During these events, the test  verifies
    CHASSIS_APP_DB consistency by comparing the initial and current database dumps.
    In scenarios involving port channel configuration changes, the test ensures that,
    after a dut_reboot and config_reload, the port channel configuration reverts
    to its original state. Conversely, in the case of config_save_reload, where
    a configuration save is succeeded by a reload, the test verifies that the
    changes in port channel configuration persist consistently.
   """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_rand_one_asic_index)
    int_facts = asichost.interface_facts()['ansible_facts']
    port_channels_data = asichost.get_portchannels_and_members_in_ns(tbinfo)
    if not port_channels_data:
        pytest.skip(
            "Skip test as there are no port channels on asic {} on dut {}".format(enum_rand_one_asic_index, duthost))
    bgp_facts = asichost.bgp_facts()['ansible_facts']
    pc = None
    pc_members = None
    pc_nbr_ip = None
    pc_nbr_ipv6 = None
    for pc in port_channels_data:
        logging.info('Trying to get PortChannel: {} for test'.format(pc))
        if int_facts['ansible_interface_facts'][pc].get('ipv4') and int_facts['ansible_interface_facts'][pc].get(
                'ipv6'):
            pc_values = asichost.show_ip_interface()["ansible_facts"]["ip_interfaces"][pc]
            if pc_values.get('peer_ipv4'):
                pc_nbr_ip = pc_values['peer_ipv4']
                pc_neigh = pc_values.get('bgp_neighbor')
                pc_nbr_ipv6 = next((key for key, value in bgp_facts['bgp_neighbors'].items() if
                                    value.get('ip_version') == 6 and value.get('description') == pc_neigh), None)
                pc_members = port_channels_data[pc]
            break

    pytest_assert(pc and pc_members and pc_nbr_ip and pc_nbr_ipv6, 'Can not get PortChannel interface for test')

    tmp_portchannel = "PortChannel999"
    # Initialize portchannel_ip and portchannel_members
    pc_ip = int_facts['ansible_interface_facts'][pc]['ipv4']['address']
    pc_ipv6 = int_facts['ansible_interface_facts'][pc]['ipv6'][0]['address']
    init_dump = get_db_dump(duthosts, duthost)
    # Initialize flags
    remove_pc_members = False
    remove_pc_ip = False
    remove_pc_ipv6 = False
    create_tmp_pc = False
    add_tmp_pc_members = False
    add_tmp_pc_ip = False
    add_tmp_pc_ipv6 = False

    logging.info("portchannel=%s" % pc)
    logging.info("portchannel_ip=%s" % pc_ip)
    logging.info("portchannel_ipv6=%s" % pc_ipv6)
    logging.info("portchannel_nbr_ip=%s" % pc_nbr_ip)
    logging.info("portchannel_nbr_ipv6=%s" % pc_nbr_ipv6)
    logging.info("portchannel_members=%s" % pc_members)

    try:
        # Step 1: Remove portchannel members from portchannel
        for member in pc_members:
            asichost.config_portchannel_member(pc, member, "del")
        remove_pc_members = True

        # Step 2: Remove portchannel ip and ipv6 from portchannel
        asichost.config_ip_intf(pc, pc_ip + "/31", "remove")
        remove_pc_ip = True
        asichost.config_ip_intf(pc, pc_ipv6 + "/126", "remove")
        remove_pc_ipv6 = True

        time.sleep(30)
        int_facts = asichost.interface_facts()['ansible_facts']
        pytest_assert(not int_facts['ansible_interface_facts'][pc]['link'])
        pytest_assert(wait_until(120, 10, 0, asichost.check_bgp_statistic, 'ipv4_idle', 1))
        pytest_assert(wait_until(120, 10, 0, asichost.check_bgp_statistic, 'ipv6_idle', 1))

        # Step 3: Create tmp portchannel
        asichost.config_portchannel(tmp_portchannel, "add")
        create_tmp_pc = True

        # Step 4: Add portchannel member to tmp portchannel
        for member in pc_members:
            asichost.config_portchannel_member(tmp_portchannel, member, "add")
        add_tmp_pc_members = True

        # Step 5: Add portchannel ip to tmp portchannel
        asichost.config_ip_intf(tmp_portchannel, pc_ip + "/31", "add")
        int_facts = asichost.interface_facts()['ansible_facts']
        pytest_assert(int_facts['ansible_interface_facts'][tmp_portchannel]['ipv4']['address'] == pc_ip)
        add_tmp_pc_ip = True

        # Step 6: Add portchannel ipv6 to tmp portchannel
        asichost.config_ip_intf(tmp_portchannel, pc_ipv6 + "/126", "add")
        int_facts = asichost.interface_facts()['ansible_facts']
        pytest_assert(int_facts['ansible_interface_facts'][tmp_portchannel]['ipv6'][0]['address'] == pc_ipv6)
        add_tmp_pc_ipv6 = True

        time.sleep(30)
        int_facts = asichost.interface_facts()['ansible_facts']
        pytest_assert(int_facts['ansible_interface_facts'][tmp_portchannel]['link'])
        post_change_db_dump = get_db_dump(duthosts, duthost)
        verify_data_in_db(post_change_db_dump, tmp_portchannel, pc_members, duthosts, pc_nbr_ip, duthost, pc_nbr_ipv6)
        # Setting Flags as false as config reload or dut reboot reverts the changes
        remove_pc_members = False
        remove_pc_ip = False
        remove_pc_ipv6 = False
        create_tmp_pc = False
        add_tmp_pc_members = False
        add_tmp_pc_ip = False
        add_tmp_pc_ipv6 = False
        if test_case == "config_reload_no_config_save":
            logging.info("Reloading config")
            config_reload(duthost, safe_reload=True)
            pytest_assert(wait_until(600, 30, 0, check_db_consistency, duthosts, duthost, init_dump),
                          "DB_Consistency Failed")
        elif test_case == "config_reload_with_config_save":
            duthost.shell('sudo config save -y')
            config_reload(duthost, safe_reload=True)
            pytest_assert(wait_until(600, 30, 0, check_db_consistency, duthosts, duthost, post_change_db_dump),
                          "DB_Consistency Failed")
        else:
            logging.info("Rebooting dut {}".format(duthost))
            reboot(duthost, localhost, wait_for_ssh=False)
            localhost.wait_for(host=duthost.mgmt_ip, port=22, state="stopped", delay=1, timeout=60)
            pytest_assert(check_db_consistency(duthosts, duthost, post_change_db_dump),
                          "DB_Consistency Failed During Reboot")
            localhost.wait_for(host=duthost.mgmt_ip, port=22, state="started", delay=10, timeout=300)
            pytest_assert(wait_until(330, 20, 0, duthost.critical_services_fully_started),
                          "All critical services should fully started!")
            pytest_assert(wait_until(600, 30, 0, check_db_consistency, duthosts, duthost, init_dump),
                          "DB_Consistency Failed After Reboot")

    finally:
        # Recover all states
        if test_case == "config_reload_with_config_save":
            logger.info("Restore config from minigraph.")
            config_reload(duthost, config_source='minigraph', safe_reload=True, check_intf_up_ports=True)
            wait_critical_processes(duthost)
            pytest_assert(wait_until(300, 20, 0, check_interface_status_of_up_ports, duthost),
                          "Not all ports that are admin up on are operationally up")
            duthost.shell_cmds(cmds=["config save -y"])
        if add_tmp_pc_ip:
            asichost.config_ip_intf(tmp_portchannel, pc_ip + "/31", "remove")
        if add_tmp_pc_ipv6:
            asichost.config_ip_intf(tmp_portchannel, pc_ipv6 + "/126", "remove")

        time.sleep(5)
        if add_tmp_pc_members:
            for member in pc_members:
                asichost.config_portchannel_member(tmp_portchannel, member, "del")
        pytest_assert(wait_until(30, 5, 5, lambda: not asichost.get_portchannel_members(tmp_portchannel)),
                      "Portchannel members are not removed from {}".format(tmp_portchannel))
        if create_tmp_pc:
            asichost.config_portchannel(tmp_portchannel, "del")
        if remove_pc_ip:
            asichost.config_ip_intf(pc, pc_ip + "/31", "add")
        if remove_pc_ipv6:
            asichost.config_ip_intf(pc, pc_ipv6 + "/126", "add")
        if remove_pc_members:
            for member in pc_members:
                asichost.config_portchannel_member(pc, member, "add")

        pytest_assert(wait_until(220, 10, 0, asichost.check_bgp_statistic, 'ipv4_idle', 0))
        pytest_assert(wait_until(220, 10, 0, asichost.check_bgp_statistic, 'ipv6_idle', 0))


def check_db_consistency(duthosts, duthost, expected_dump):
    """
    Args:
        expected_dump: The CHASSIS_APP_DB *System* table and set dump
    Returns: Boolean of Comparision between the expected and current db_dumps
    """
    curr_dump = get_db_dump(duthosts, duthost)

    if not expected_dump == curr_dump:
        differences = {key: (expected_dump.get(key), curr_dump.get(key)) for key in set(expected_dump) | set(curr_dump)
                       if
                       expected_dump.get(key) != curr_dump.get(key)}
        logging.info("The Difference between the initial DB_DUMP and Current DB_DUMP : {}".format((differences)))
        return False
    else:
        return True


def get_db_dump(duthosts, duthost):
    """
    Args:
        duthost: The dut being tested
    Returns:chassis_app_db_sysparams: Dictionary with CHASSIS_APP_DB DB
    dump of impacted Tables and Sets from the supervisor node
    SYSTEM_INTERFACE
    SYSTEM_LAG_ID_SET
    SYSTEM_LAG_ID_TABLE
    SYSTEM_LAG_MEMBER_TABLE
    SYSTEM_LAG_TABLE
    SYSTEM_NEIGH
    """

    chassis_app_db_sysparams = {}
    key = "*SYSTEM*|*" + duthost.sonichost.hostname + "*"
    chassis_app_db_result = redis_get_keys(duthosts.supervisor_nodes[0], "CHASSIS_APP_DB", key)
    if chassis_app_db_result is not None:
        chassis_app_db_sysparams["CHASSIS_APP_DB"] = chassis_app_db_result
    voqdb = VoqDbCli(duthosts.supervisor_nodes[0])
    chassis_app_db_sysparams["SYSTEM_LAG_ID_TABLE"] = voqdb.dump("SYSTEM_LAG_ID_TABLE")["SYSTEM_LAG_ID_TABLE"]['value']
    chassis_app_db_sysparams["SYSTEM_LAG_ID_SET"] = voqdb.dump("SYSTEM_LAG_ID_SET")["SYSTEM_LAG_ID_SET"]['value']
    return {k: sorted(v) for k, v in chassis_app_db_sysparams.items()}
