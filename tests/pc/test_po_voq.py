import pytest
import tests.common.helpers.voq_lag as voq_lag
from tests.common.helpers.voq_helpers import verify_no_routes_from_nexthop
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
import logging
logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2')
]


def get_asic_with_pc(duthost):
    """
    Returns Asic with portchannel

    Args:
        duthost <obj>: The duthost object

    Returns:
        asic <obj> : Asic object

    """
    for asic in duthost.asics:
        config_facts = duthost.config_facts(source='persistent',
                                            asic_index=asic.asic_index)['ansible_facts']
        if 'PORTCHANNEL' in config_facts:
            return asic


@pytest.fixture(scope='module')
def setup_teardown(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
     Prepares dut for the testcase by deleting the existing port channel members and ip,
     adds a new portchannel and assignes port channel members and ip
      from the previous port channel

     Args:
         duthosts <list>: The duthosts object
         enum_rand_one_per_hwsku_frontend_hostname <int>:
          random per fromtend per hwsku duthost

    Returns:
        portchannel_ip <str> : portchannel ip address
        portchannle_members <list> : portchannel members

    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic = get_asic_with_pc(duthost)
    config_facts = duthost.config_facts(source='persistent',
                                        asic_index=asic.asic_index)['ansible_facts']

    portchannel = list(config_facts['PORTCHANNEL'].keys())[0]
    portchannel_members = config_facts['PORTCHANNEL'][portchannel].get('members')

    portchannel_ip = None
    if 'PORTCHANNEL_INTERFACE' in config_facts:
        portchannel_ips = list(config_facts['PORTCHANNEL_INTERFACE'][portchannel].keys())
        for ip in portchannel_ips:
            if '.' in ip:
                portchannel_ip = ip

    for addr in config_facts['BGP_NEIGHBOR']:
        if portchannel_ip.split('/')[0] == config_facts['BGP_NEIGHBOR'][addr]['local_addr']:
            nbr_addr = addr

    voq_lag.delete_lag_members_ip(duthost, asic, portchannel_members, portchannel_ip, portchannel)
    verify_no_routes_from_nexthop(duthosts, nbr_addr)
    voq_lag.add_lag(duthost, asic, portchannel_members, portchannel_ip)

    yield asic, portchannel_ip, portchannel_members

    voq_lag.delete_lag_members_ip(duthost, asic, portchannel_members, portchannel_ip)
    # remove tmp portchannel
    voq_lag.delete_lag(duthost, asic)
    verify_no_routes_from_nexthop(duthosts, nbr_addr)
    # add only lag members and ip since lag already exist
    voq_lag.add_lag(duthost, asic, portchannel_members, portchannel_ip, portchannel, add=False)


def test_voq_po_update(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    test to verify when a LAG is added/deleted via CLI on an ASIC,
     It is populated in remote ASIC_DB.
    Steps:
        1. On any ASIC, add a new LAG
        2. verify added lag gets a unique lag id in chassis app db
        3. verify added lag exist in app db
        4. verify lag exist in asic db on remote and local asic db
        5. delete the added lag
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic = get_asic_with_pc(duthost)
    try:
        voq_lag.verify_lag_id_is_unique_in_chassis_db(duthosts, duthost, asic)
        voq_lag.verify_lag_in_app_db(asic)
        tmp_lag_id = voq_lag.get_lag_id_from_chassis_db(duthosts)
        voq_lag.verify_lag_in_asic_db(duthost.asics, tmp_lag_id)
        # to verify lag in remote asic db
        remote_duthosts = [dut_host for dut_host in duthosts.frontend_nodes if dut_host != duthost]
        voq_lag.verify_lag_in_remote_asic_db(remote_duthosts, tmp_lag_id)
        voq_lag.verify_lag_id_deleted_in_chassis_db(duthosts, duthost, asic, tmp_lag_id)
        voq_lag.verify_lag_in_app_db(asic, deleted=True)
        voq_lag.verify_lag_in_asic_db(duthost.asics, tmp_lag_id, deleted=True)
        remote_duthosts = [dut_host for dut_host in duthosts.frontend_nodes if dut_host != duthost]
        voq_lag.verify_lag_in_remote_asic_db(remote_duthosts, tmp_lag_id, deleted=True)
    finally:
        if voq_lag.is_lag_in_app_db(asic):
            voq_lag.delete_lag(duthost, asic)


def test_voq_po_member_update(duthosts, enum_rand_one_per_hwsku_frontend_hostname, setup_teardown):
    """
    Test to verify when a LAG members is added/deleted via CLI on an ASIC,
     It is synced to remote ASIC_DB.
    Steps:
        1. On any ASIC, add LAG members to a lag
        2. verify lag members exist in local asic app db
        3. verify lag members exist in chassis app db
        4. verify lag members exist in local and remote asic db
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic, portchannel_ip, portchannel_members = setup_teardown
    tmp_lag_id = voq_lag.get_lag_id_from_chassis_db(duthosts)
    voq_lag.verify_lag_member_in_app_db(asic, portchannel_members)
    voq_lag.verify_lag_member_in_chassis_db(duthosts, portchannel_members)
    voq_lag.verify_lag_member_in_asic_db(duthost.asics, tmp_lag_id, portchannel_members)
    remote_duthosts = [dut_host for dut_host in duthosts.frontend_nodes if dut_host != duthost]
    voq_lag.verify_lag_member_in_remote_asic_db(remote_duthosts, tmp_lag_id, portchannel_members, deleted=True)


def test_voq_po_down_via_cli_update(duthosts, enum_rand_one_per_hwsku_frontend_hostname, setup_teardown):
    """Test to verify when a LAG goes down on an ASIC via CLI, it is synced across all DBs

    All DBs = local app db, chassis app db, local & remote asic db
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    remote_duthosts = [dut_host for dut_host in duthosts.frontend_nodes if dut_host != duthost]
    asic, portchannel_ip, portchannel_members = setup_teardown
    tmp_lag_id = voq_lag.get_lag_id_from_chassis_db(duthosts)
    num_portchannels = len(portchannel_members)

    # Make sure LAG is up across all DBs (all PC members are up across all DBs)
    for portchannel_member in portchannel_members:
        voq_lag.verify_lag_member_status_in_app_db(asic, portchannel_member, enabled=True)
        voq_lag.verify_lag_member_status_in_chassis_db(duthosts, portchannel_member, enabled=True)
    # For checking LAG member status in ASIC_DB,
    # we check how many members are disabled in a LAG since we can't identify individual members
    voq_lag.verify_lag_member_status_in_asic_db(duthost.asics, tmp_lag_id, exp_disabled=0)
    for remote_duthost in remote_duthosts:
        voq_lag.verify_lag_member_status_in_asic_db(remote_duthost.asics, tmp_lag_id, exp_disabled=0)

    try:
        # Bring down LAG, check that LAG down is synced across all DBs (all PC members are down across all DBs)
        logging.info("Disabling {}".format(voq_lag.TMP_PC))
        duthost.shell("config interface {} shutdown {}".format(asic.cli_ns_option, voq_lag.TMP_PC))
        pytest_assert(wait_until(30, 5, 0, lambda: not duthost.check_intf_link_state(voq_lag.TMP_PC)),
                      "{} is not disabled".format(voq_lag.TMP_PC))

        for portchannel_member in portchannel_members:
            voq_lag.verify_lag_member_status_in_app_db(asic, portchannel_member, enabled=False)
            voq_lag.verify_lag_member_status_in_chassis_db(duthosts, portchannel_member, enabled=False)
        voq_lag.verify_lag_member_status_in_asic_db(duthost.asics, tmp_lag_id, exp_disabled=num_portchannels)
        for remote_duthost in remote_duthosts:
            voq_lag.verify_lag_member_status_in_asic_db(remote_duthost.asics, tmp_lag_id, exp_disabled=num_portchannels)
    finally:
        # Bring LAG back up
        logging.info("Enabling {}".format(voq_lag.TMP_PC))
        duthost.shell("config interface {} startup {}".format(asic.cli_ns_option, voq_lag.TMP_PC))
        pytest_assert(wait_until(30, 5, 0, lambda: duthost.check_intf_link_state(voq_lag.TMP_PC)),
                      "{} is not enabled".format(voq_lag.TMP_PC))
