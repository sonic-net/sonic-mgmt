import time
import pytest
import logging

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(enum_rand_one_per_hwsku_frontend_hostname, loganalyzer):
    """
        Ignore expected failures logs during test execution.

        LAG tests are triggering following syncd complaints but the don't cause
        harm to DUT.

        Args:
            duthost: DUT fixture
            loganalyzer: Loganalyzer utility fixture
    """
    # when loganalyzer is disabled, the object could be None
    if loganalyzer:
        ignoreRegex = [
            ".*ERR syncd#syncd: :- process_on_fdb_event: invalid OIDs in fdb notifications, NOT translating and NOT storing in ASIC DB.*",
            ".*ERR syncd#syncd: :- process_on_fdb_event: FDB notification was not sent since it contain invalid OIDs, bug.*",
            ".*ERR syncd#syncd: :- translate_vid_to_rid: unable to get RID for VID.*",
        ]
        loganalyzer[enum_rand_one_per_hwsku_frontend_hostname].ignore_regex.extend(ignoreRegex)

    yield

def test_po_update(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
    """
    test port channel add/deletion as well ip address configuration
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    int_facts = duthost.interface_facts()['ansible_facts']

    # Initialize portchannel
    if len(mg_facts['minigraph_portchannels'].keys()) == 0:
        pytest.skip("Skip test due to there is no portchannel exists in current topology.")

    portchannel = mg_facts['minigraph_portchannels'].keys()[0]
    tmp_portchannel = "PortChannel999"
    # Initialize portchannel_ip and portchannel_members
    portchannel_ip = int_facts['ansible_interface_facts'][portchannel]['ipv4']['address']
    portchannel_members = mg_facts['minigraph_portchannels'][portchannel]['members']
    # Initialize flags
    remove_portchannel_members = False
    remove_portchannel_ip = False
    create_tmp_portchannel = False
    add_tmp_portchannel_members = False
    add_tmp_portchannel_ip = False

    logging.info("portchannel=%s" % portchannel)
    logging.info("portchannel_ip=%s" % portchannel_ip)
    logging.info("portchannel_members=%s" % portchannel_members)

    try:
        if len(portchannel_members) == 0:
            pytest.skip("Skip test due to there is no portchannel member exists in current topology.")

        # Step 1: Remove portchannel members from portchannel
        for member in portchannel_members:
            duthost.shell("config portchannel member del %s %s" % (portchannel, member))
        remove_portchannel_members = True

        # Step 2: Remove portchannel ip from portchannel
        duthost.shell("config interface ip remove %s %s/31" % (portchannel, portchannel_ip))
        remove_portchannel_ip = True

        time.sleep(30)
        int_facts = duthost.interface_facts()['ansible_facts']
        pytest_assert(not int_facts['ansible_interface_facts'][portchannel]['link'])
        pytest_assert(wait_until(120, 10, duthost.check_bgp_statistic, 'ipv4_idle', 1))

        # Step 3: Create tmp portchannel
        duthost.shell("config portchannel add %s" % tmp_portchannel)
        create_tmp_portchannel = True

        # Step 4: Add portchannel member to tmp portchannel
        for member in portchannel_members:
            duthost.shell("config portchannel member add %s %s" % (tmp_portchannel, member))
        add_tmp_portchannel_members = True

        # Step 5: Add portchannel ip to tmp portchannel
        duthost.shell("config interface ip add %s %s/31" % (tmp_portchannel, portchannel_ip))
        int_facts = duthost.interface_facts()['ansible_facts']
        pytest_assert(int_facts['ansible_interface_facts'][tmp_portchannel]['ipv4']['address'] == portchannel_ip)
        add_tmp_portchannel_ip = True

        time.sleep(30)
        int_facts = duthost.interface_facts()['ansible_facts']
        pytest_assert(int_facts['ansible_interface_facts'][tmp_portchannel]['link'])
        pytest_assert(wait_until(120, 10, duthost.check_bgp_statistic, 'ipv4_idle', 0))
    finally:
        # Recover all states
        if add_tmp_portchannel_ip:
            duthost.shell("config interface ip remove %s %s/31" % (tmp_portchannel, portchannel_ip))

        time.sleep(5)
        if add_tmp_portchannel_members:
            for member in portchannel_members:
                duthost.shell("config portchannel member del %s %s" % (tmp_portchannel, member))

        time.sleep(5)
        if create_tmp_portchannel:
            duthost.shell("config portchannel del %s" % tmp_portchannel)
        if remove_portchannel_ip:
            duthost.shell("config interface ip add %s %s/31" % (portchannel, portchannel_ip))
        if remove_portchannel_members:
            for member in portchannel_members:
                duthost.shell("config portchannel member add %s %s" % (portchannel, member))
        pytest_assert(wait_until(120, 10, duthost.check_bgp_statistic, 'ipv4_idle', 0))

