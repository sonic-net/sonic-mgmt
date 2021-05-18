import pytest
import tests.common.helpers.voq_lag as voq_lag

pytestmark = [
    pytest.mark.topology('t2')
]


@pytest.fixture(scope='module')
def setup_teardown(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                   enum_rand_one_asic_index):
    """
     Prepares dut for the testcase by deleting the existing port channel members and ip,
     adds a new portchannel and assignes port channel members and ip
      from the previous port channel

     Args:
         duthosts <list>: The duthosts object
         enum_rand_one_per_hwsku_frontend_hostname <int>:
          random per fromtend per hwsku duthost
         enum_rand_one_asic_index<int>: random asic index

    Returns:
        portchannel_ip <str> : portchannel ip address
        portchannle_members <list> : portchannel members

    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic = duthost.asics[enum_rand_one_asic_index if enum_rand_one_asic_index else 0]

    config_facts = duthost.config_facts(source='persistent',
                                        asic_index=asic.asic_index)['ansible_facts']
    portchannel_members = None
    if 'PORTCHANNEL' in config_facts:
        portchannel = config_facts['PORTCHANNEL'].keys()[0]
        portchannel_members = config_facts['PORTCHANNEL'][portchannel].get('members')

    else:
        pytest.skip('Skip test since there is no portchannel configured. ')

    portchannel_ip = None
    if 'PORTCHANNEL_INTERFACE' in config_facts:
        portchannel_ips = config_facts['PORTCHANNEL_INTERFACE'][portchannel].keys()
        for ip in portchannel_ips:
            if '.' in ip:
                portchannel_ip = ip

    if len(portchannel_members) == 0:
        pytest.skip("Skip test due to there is no portchannel member exists in current topology.")

    voq_lag.delete_lag_members_ip(duthost, asic, portchannel_members, portchannel_ip, portchannel)
    voq_lag.add_lag(duthost, asic, portchannel_members, portchannel_ip)

    yield portchannel_ip, portchannel_members

    voq_lag.delete_lag_members_ip(duthost, asic, portchannel_members, portchannel_ip)
    # remove tmp portchannel
    voq_lag.delete_lag(duthost, asic)
    # add only lag members and ip since lag already exist
    voq_lag.add_lag(duthost, asic, portchannel_members, portchannel_ip, portchannel, add=False)


def test_voq_po_update(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                       enum_rand_one_asic_index):
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
    asic = duthost.asics[enum_rand_one_asic_index if enum_rand_one_asic_index else 0]
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


def test_voq_po_member_update(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                              enum_rand_one_asic_index, setup_teardown):
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
    asic = duthost.asics[enum_rand_one_asic_index if enum_rand_one_asic_index else 0]
    portchannel_ip, portchannel_members = setup_teardown
    tmp_lag_id = voq_lag.get_lag_id_from_chassis_db(duthosts)
    voq_lag.verify_lag_member_in_app_db(asic, portchannel_members)
    voq_lag.verify_lag_member_in_chassis_db(duthosts, portchannel_members)
    voq_lag.verify_lag_member_in_asic_db(duthost.asics, tmp_lag_id,portchannel_members)
    remote_duthosts = [dut_host for dut_host in duthosts.frontend_nodes if dut_host != duthost]
    voq_lag.verify_lag_member_in_remote_asic_db(remote_duthosts, tmp_lag_id, portchannel_members, deleted=True)
