'''

The test case will verify that the applied Macsec sessions are secured
even if LACP isn't up.

1: Configure 2 portchannels on DUT with two members each.
2: First ensure portchannels are up and macsec sessions are secured.
3: Mismatch interfaces on both portchannels. LACP should go down while macsec
sessions should stay secured.

'''
import pytest
import logging
import sys
import time

if sys.version_info.major > 2:
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))

from tests.common.helpers.assertions import pytest_assert
from tests.common import config_reload
from tests.common.utilities import wait_until
from .macsec_helper import get_mka_session, get_sci, check_mka_session
from .macsec_platform_helper import get_macsec_ifname

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("any")
]


@pytest.fixture(scope="function")
def reload_testbed_on_failed(request, duthosts, enum_rand_one_per_hwsku_frontend_hostname, loganalyzer):
    """
        Reload dut after test function finished
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    yield None
    if request.node.rep_call.failed:
        # if test case failed, means bgp session down or port channel status not recovered, execute config reload
        logging.info("Reloading config and restarting swss...")
        config_reload(duthost, safe_reload=True)


def _wait_until_pc_members_removed(asichost, pc_names):
    """
    Wait until all port channel members are removed.
    """
    if not wait_until(30, 5, 5, lambda: not asichost.get_portchannel_members(pc_names)):
        # Mark the test case as failed if port channel members are not removed.
        # The fixture reload_testbed_on_failed will do config reload to restore the DUT.
        pytest.fail("Portchannel members are not removed from {}".format(pc_names))


def has_bgp_neighbors(duthost, portchannel):
    return duthost.shell("show ip int | grep {} | awk '{{print $4}}'".format(portchannel))['stdout'] != 'N/A'


def pc_active(asichost, portchannel):
    return asichost.interface_facts()['ansible_facts']['ansible_interface_facts'][portchannel]['active']


def verify_macsec_session(duthost, ctrl_links, policy, cipher_suite, send_sci):
    dut_mka_session = get_mka_session(duthost)
    assert len(dut_mka_session) == len(ctrl_links)
    for port_name, nbr in list(ctrl_links.items()):
        nbr_mka_session = get_mka_session(nbr["host"])
        dut_macsec_port = get_macsec_ifname(duthost, port_name)
        nbr_macsec_port = get_macsec_ifname(
            nbr["host"], nbr["port"])
        dut_macaddress = duthost.get_dut_iface_mac(port_name)
        nbr_macaddress = nbr["host"].get_dut_iface_mac(nbr["port"])
        dut_sci = get_sci(dut_macaddress)
        nbr_sci = get_sci(nbr_macaddress)
        check_mka_session(dut_mka_session[dut_macsec_port], dut_sci,
                          nbr_mka_session[nbr_macsec_port], nbr_sci,
                          policy, cipher_suite, send_sci)


def test_lacp_transparency(duthosts,
                           enum_rand_one_per_hwsku_frontend_hostname,
                           enum_frontend_asic_index, tbinfo,
                           ctrl_links, policy, cipher_suite, send_sci):

    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    int_facts = asichost.interface_facts()['ansible_facts']

    portchannels_info = asichost.get_portchannels_and_members_in_ns(tbinfo)
    if not portchannels_info:
        pytest.skip(
            "Skip test as there are no port channels on asic {} on dut {}".format(enum_frontend_asic_index, duthost))

    pytest_assert(portchannels_info, 'Can not get PortChannel interface for test')
    portchannels_data = {}
    for pc, members in portchannels_info.items():
        ip = int_facts['ansible_interface_facts'][pc]['ipv4']['address']
        portchannels_data[pc] = {
            'members': members,
            'ip': ip
        }

    # Initialize temp_portchannel_ip and tmp_portchannel_members
    tmp_portchannels = ["PortChannel998", "PortChannel999"]
    tmp_portchannels_data = {}
    portchannels = list(portchannels_data.keys())
    for index, tmp_pc in enumerate(tmp_portchannels):
        portchannel = portchannels[index]
        mismatch_portchannel_members = []
        for pc, data in portchannels_data.items():
            mismatch_portchannel_members.append(data['members'][index])

        tmp_portchannels_data[tmp_pc] = {
            'members': portchannels_data[portchannel]['members'],
            'mismatched_members': mismatch_portchannel_members,
            'ip': portchannels_data[portchannel]['ip']
        }

    logging.info("portchannels_data=%s" % portchannels_data)
    logging.info("temporary_portchannels_data=%s" % tmp_portchannels_data)

    try:
        # Step 1: Remove portchannel members and ip from portchannel
        for pc, data in portchannels_data.items():
            for member in data['members']:
                asichost.config_portchannel_member(pc, member, "del")
            asichost.config_ip_intf(pc, data['ip'] + "/31", "remove")

        time.sleep(30)
        int_facts = asichost.interface_facts()['ansible_facts']
        for pc, data in portchannels_data.items():
            pytest_assert(not int_facts['ansible_interface_facts'][pc]['link'])
            pytest_assert(
                has_bgp_neighbors(duthost, pc) and
                wait_until(120, 10, 0, asichost.check_bgp_statistic, 'ipv4_idle', 1)
                or not wait_until(10, 10, 0, pc_active, asichost, pc))

        verify_macsec_session(duthost, ctrl_links, policy, cipher_suite, send_sci)

        # Step 2: Create 2 tmp portchannel, add portchannel members and ip
        for tmp_pc, data in tmp_portchannels_data.items():
            asichost.config_portchannel(tmp_pc, "add")
            for member in data['members']:
                asichost.config_portchannel_member(tmp_pc, member, "add")
            asichost.config_ip_intf(tmp_pc, data['ip'] + "/31", "add")

        int_facts = asichost.interface_facts()['ansible_facts']
        for tmp_pc, data in tmp_portchannels_data.items():
            pytest_assert(int_facts['ansible_interface_facts'][tmp_pc]['ipv4']['address'] == data['ip'])

        time.sleep(30)
        int_facts = asichost.interface_facts()['ansible_facts']
        for tmp_pc, data in tmp_portchannels_data.items():
            pytest_assert(int_facts['ansible_interface_facts'][tmp_pc]['link'])
            pytest_assert(
                has_bgp_neighbors(duthost, tmp_pc) and
                wait_until(120, 10, 0, asichost.check_bgp_statistic, 'ipv4_idle', 0)
                or wait_until(10, 10, 0, pc_active, asichost, tmp_pc))

        verify_macsec_session(duthost, ctrl_links, policy, cipher_suite, send_sci)

        # Step 4: Remove portchannel members and ip from tmp portchannel
        for tmp_pc, data in tmp_portchannels_data.items():
            for member in data['members']:
                asichost.config_portchannel_member(tmp_pc, member, "del")
            asichost.config_ip_intf(tmp_pc, data['ip'] + "/31", "remove")

        time.sleep(30)
        int_facts = asichost.interface_facts()['ansible_facts']
        for tmp_pc, data in tmp_portchannels_data.items():
            pytest_assert(not int_facts['ansible_interface_facts'][tmp_pc]['link'])
            pytest_assert(
                has_bgp_neighbors(duthost, tmp_pc) and
                wait_until(120, 10, 0, asichost.check_bgp_statistic, 'ipv4_idle', 1)
                or not wait_until(10, 10, 0, pc_active, asichost, tmp_pc))

        verify_macsec_session(duthost, ctrl_links, policy, cipher_suite, send_sci)

        # Step 5: Add mismatched portchannel members and ip to tmp portchannel
        for tmp_pc, data in tmp_portchannels_data.items():
            asichost.config_portchannel(tmp_pc, "add")
            for member in data["mismatched_members"]:
                asichost.config_portchannel_member(tmp_pc, member, "add")
            asichost.config_ip_intf(tmp_pc, data['ip'] + "/31", "add")

        int_facts = asichost.interface_facts()['ansible_facts']
        for tmp_pc, data in tmp_portchannels_data.items():
            pytest_assert(int_facts['ansible_interface_facts'][tmp_pc]['ipv4']['address'] == data['ip'])

        time.sleep(30)
        int_facts = asichost.interface_facts()['ansible_facts']
        for tmp_pc, data in tmp_portchannels_data.items():
            pytest_assert(int_facts['ansible_interface_facts'][tmp_pc]['link'])
            pytest_assert(
                has_bgp_neighbors(duthost, tmp_pc) and
                wait_until(120, 10, 0, asichost.check_bgp_statistic, 'ipv4_idle', 1)
                or wait_until(10, 10, 0, pc_active, asichost, tmp_pc))
        logger.info(duthost.shell("show interfaces portchannel")["stdout_lines"])
        verify_macsec_session(duthost, ctrl_links, policy, cipher_suite, send_sci)

    finally:

        config_reload(duthost)

        time.sleep(120)
