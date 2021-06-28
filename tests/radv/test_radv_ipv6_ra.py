import ipaddress
import logging
import time

import pytest

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.helpers.assertions import pytest_assert
from tests.ptf_runner import ptf_runner

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.device_type('vs')
]

RADV_CONF_FILE = '/etc/radvd.conf'
RADV_BACKUP_CONF_FILE = '/tmp/radvd.conf'
RADV_MIN_RA_INTERVAL_SECS = 3
RADV_MAX_RA_INTERVAL_SECS = 4

"""
@summary: This fixture collects the data related to downlink VLAN port(s) and
the connected PTF port(s) required to setup the RADV tests

"""

@pytest.fixture(scope="module")
def radv_test_setup(duthosts, rand_one_dut_hostname, ptfhost, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    # RADVd is configured for each VLAN interface
    vlan_dict = mg_facts['minigraph_vlans']
    vlan_interfaces_list = []
    for vlan_iface_name, vlan_info_dict in vlan_dict.items():
        # Gather information about the downlink VLAN interface this relay agent is listening on
        downlink_vlan_iface = {}
        downlink_vlan_iface['name'] = vlan_iface_name

        # Obtain the link-local IPv6 address of the DUT's downlink VLAN interface
        downlink_vlan_iface['mac'] = duthost.get_dut_iface_mac(vlan_iface_name)
        cmd = "ip -6 -o addr show dev {} scope link | sed -e's/^.*inet6 \([^ ]*\)\/.*$/\\1/;t;d'".format(vlan_iface_name)
        res = duthost.shell(cmd)
        ip6 = ipaddress.IPv6Address(unicode(res['stdout']))
        pytest_assert(ip6.is_link_local,
                "ip6 address:{} of {} is not a link-local address".format(str(ip6), downlink_vlan_iface['name']))
        downlink_vlan_iface['ip6'] = str(ip6)

        # Obtain link-local IPv6 address of the connected PTF port (Eg eth0)
        # This PTF port maps to the first member of the TOR's VLAN
        ptf_port = {}
        ptf_port['port_idx'] = mg_facts['minigraph_ptf_indices'][vlan_info_dict['members'][0]]
        ptf_port['name'] = "eth" + str(ptf_port['port_idx'])
        cmd = "ip -6 -o addr show dev {} scope link | sed -e's/^.*inet6 \([^ ]*\)\/.*$/\\1/;t;d'".format(ptf_port['name'])
        res = ptfhost.shell(cmd)
        ip6 = ipaddress.IPv6Address(unicode(res['stdout']))
        pytest_assert(ip6.is_link_local,
                "ip6 address:{} of {} is not a link-local address".format(str(ip6), ptf_port['name']))
        ptf_port['ip6'] = str(ip6)

        vlan_intf_data = {}
        vlan_intf_data['downlink_vlan_intf'] = downlink_vlan_iface
        vlan_intf_data['ptf_port'] = ptf_port
        vlan_interfaces_list.append(vlan_intf_data)

    return vlan_interfaces_list

"""
@summary: Updates min/max RA interval in RADVd's config file

"""

def dut_update_ra_interval(duthost, ra, interval):
    logging.info("Updating %s to %d in RADVd's config file:%s", ra, int(interval), RADV_CONF_FILE)
    cmd = "sed -ie 's/\(.*\)\({}\) \([[:digit:]]\+\)/\\1\\2 {}/' {}".format(ra, interval, RADV_CONF_FILE)
    duthost.shell("docker exec radv {}".format(cmd))

"""
@summary: A fixture that updates the RADVd's periodic RA update intervals and restores the
intervals to old values after the test

"""
@pytest.fixture
def dut_update_radv_periodic_ra_interval(duthost):
    pytest_assert(duthost.is_service_fully_started('radv'), "radv service not running")

    cmd = 'docker exec radv [ -f {} ] && echo "1" || echo "0"'.format(RADV_CONF_FILE)
    pytest_assert(u'1' == duthost.shell(cmd)["stdout"], "radv conf file {} NOT found".format(RADV_CONF_FILE))

    # Take backup of original radvd.conf before updating
    duthost.shell('docker exec radv cp {} {}'.format(RADV_CONF_FILE, RADV_BACKUP_CONF_FILE))

    dut_update_ra_interval(duthost, "MinRtrAdvInterval", RADV_MIN_RA_INTERVAL_SECS)
    dut_update_ra_interval(duthost, "MaxRtrAdvInterval", RADV_MAX_RA_INTERVAL_SECS)

    # Notify RADVd to read the updated RA intervals
    logging.info("Notifying RADVd to read the updated config file:%s", RADV_CONF_FILE)
    duthost.shell("docker exec radv supervisorctl signal SIGHUP radvd")

    yield
    # Restore the original radvd.conf file
    duthost.shell('docker exec radv cp {} {}'.format(RADV_BACKUP_CONF_FILE, RADV_CONF_FILE))
    duthost.shell('docker exec radv rm -f {}'.format(RADV_BACKUP_CONF_FILE))
    duthost.shell("docker exec radv supervisorctl signal SIGHUP radvd")
    logging.info("Successfully restored RADVd's config back to original")

"""
@summary: Test validates the RADVd's periodic router advertisement sent on each VLAN interface

"""

def test_radv_router_advertisement(dut_update_radv_periodic_ra_interval, duthost, ptfhost, radv_test_setup):
    for vlan_intf in radv_test_setup:
        # Run the RADV test on the PTF host
        logging.info("Verifying RA on VLAN intf:%s with TOR's mapped PTF port:eth%s",
                                                vlan_intf['downlink_vlan_intf']['name'],
                                                vlan_intf['ptf_port']['port_idx'])
        ptf_runner(ptfhost,
                   "ptftests",
                   "radv_ipv6_ra_test.RadvUnSolicitedRATest",
                   platform_dir="ptftests",
                   params={"hostname": duthost.hostname,
                           "downlink_vlan_mac": vlan_intf['downlink_vlan_intf']['mac'],
                           "downlink_vlan_ip6": vlan_intf['downlink_vlan_intf']['ip6'],
                           "ptf_port_index": vlan_intf['ptf_port']['port_idx'],
                           "max_ra_interval": RADV_MAX_RA_INTERVAL_SECS},
                   log_file="/tmp/radv_ipv6_ra_test.RadvUnSolicitedRATest.log")

"""
@summary: Test validates the RADVd's solicited router advertisement sent on each VLAN interface

"""

def test_solicited_router_advertisement(ptfhost, duthost, radv_test_setup):

    for vlan_intf in radv_test_setup:
        # Run the RADV solicited RA test on the PTF host
        logging.info("Verifying solicited RA on VLAN intf:%s with TOR's mapped PTF port:eth%s",
                                                        vlan_intf['downlink_vlan_intf']['name'],
                                                        vlan_intf['ptf_port']['port_idx'])
        ptf_runner(ptfhost,
                   "ptftests",
                   "radv_ipv6_ra_test.RadvSolicitedRATest",
                   platform_dir="ptftests",
                   params={"hostname": duthost.hostname,
                           "downlink_vlan_mac": vlan_intf['downlink_vlan_intf']['mac'],
                           "downlink_vlan_ip6": vlan_intf['downlink_vlan_intf']['ip6'],
                           "ptf_port_index": vlan_intf['ptf_port']['port_idx'],
                           "ptf_port_ip6": vlan_intf['ptf_port']['ip6'],
                           "max_ra_interval": RADV_MAX_RA_INTERVAL_SECS},
                   log_file="/tmp/radv_ipv6_ra_test.RadvSolicitedRATest.log")
