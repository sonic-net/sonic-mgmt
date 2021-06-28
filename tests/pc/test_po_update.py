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

def test_po_update(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index, tbinfo):
    """
    test port channel add/deletion as well ip address configuration
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    int_facts = asichost.interface_facts()['ansible_facts']

    portchannel, portchannel_members = asichost.get_portchannel_and_members_in_ns(tbinfo)
    if portchannel is None:
        pytest.skip("Skip test due to there is no portchannel exists in current topology.")

    tmp_portchannel = "PortChannel999"
    # Initialize portchannel_ip and portchannel_members
    portchannel_ip = int_facts['ansible_interface_facts'][portchannel]['ipv4']['address']

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
            asichost.config_portchannel_member(portchannel, member, "del")
        remove_portchannel_members = True

        # Step 2: Remove portchannel ip from portchannel
        asichost.config_ip_intf(portchannel, portchannel_ip+"/31", "remove")
        remove_portchannel_ip = True

        time.sleep(30)
        int_facts = asichost.interface_facts()['ansible_facts']
        pytest_assert(not int_facts['ansible_interface_facts'][portchannel]['link'])
        pytest_assert(wait_until(120, 10, asichost.check_bgp_statistic, 'ipv4_idle', 1))

        # Step 3: Create tmp portchannel
        asichost.config_portchannel(tmp_portchannel, "add")
        create_tmp_portchannel = True

        # Step 4: Add portchannel member to tmp portchannel
        for member in portchannel_members:
            asichost.config_portchannel_member(tmp_portchannel, member, "add")
        add_tmp_portchannel_members = True

        # Step 5: Add portchannel ip to tmp portchannel
        asichost.config_ip_intf(tmp_portchannel, portchannel_ip+"/31", "add")
        int_facts = asichost.interface_facts()['ansible_facts']
        pytest_assert(int_facts['ansible_interface_facts'][tmp_portchannel]['ipv4']['address'] == portchannel_ip)
        add_tmp_portchannel_ip = True

        time.sleep(30)
        int_facts = asichost.interface_facts()['ansible_facts']
        pytest_assert(int_facts['ansible_interface_facts'][tmp_portchannel]['link'])
        pytest_assert(wait_until(120, 10, asichost.check_bgp_statistic, 'ipv4_idle', 0))
    finally:
        # Recover all states
        if add_tmp_portchannel_ip:
            asichost.config_ip_intf(tmp_portchannel, portchannel_ip+"/31", "remove")

        time.sleep(5)
        if add_tmp_portchannel_members:
            for member in portchannel_members:
                asichost.config_portchannel_member(tmp_portchannel, member, "del")

        time.sleep(5)
        if create_tmp_portchannel:
            asichost.config_portchannel(tmp_portchannel, "del")
        if remove_portchannel_ip:
            asichost.config_ip_intf(portchannel, portchannel_ip+"/31", "add")
        if remove_portchannel_members:
            for member in portchannel_members:
                asichost.config_portchannel_member(portchannel, member, "add")
        pytest_assert(wait_until(120, 10, asichost.check_bgp_statistic, 'ipv4_idle', 0))
