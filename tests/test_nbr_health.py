import json
import pytest
import logging

from common.helpers.assertions import pytest_assert
from common.devices.eos import EosHost
from common.devices.sonic import SonicHost

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('util') #special marker
]

def check_snmp(hostname, mgmt_addr, localhost, community, is_eos):
    logger.info("Check neighbor {}, mgmt ip {} snmp".format(hostname, mgmt_addr))
    res = localhost.snmp_facts(host=mgmt_addr, version='v2c', is_eos=is_eos, community=community)
    try:
        snmp_data = res['ansible_facts']
    except:
        return "neighbor {} has no snmp data".format(hostname)
    logger.info("Neighbor {}, sysdescr {}".format(hostname, snmp_data['ansible_sysdescr']))

def check_eos_facts(hostname, mgmt_addr, host):
    logger.info("Check neighbor {} eos facts".format(hostname))
    res = host.eos_facts()
    logger.info("facts: {}".format(json.dumps(res, indent=4)))
    try:
        eos_facts = res['ansible_facts']
    except:
        return "neighbor {} has no eos_facts".format(hostname)

    mgmt_ifnames = [ x for x in eos_facts['ansible_net_interfaces'] if x.startswith('Management') ]
    if len(mgmt_ifnames) == 0:
        return "there is no management interface in neighbor {}".format(hostname)
    for ifname in mgmt_ifnames:
        try:
            mgmt_ip = eos_facts['ansible_net_interfaces'][ifname]['ipv4']['address']
        except Exception as e:
            logger.info("interface {} has no managment address on neighbor {}".format(ifname, hostname))

        if mgmt_ip == mgmt_addr:
            return

    return "neighbor {} has no management address {}".format(hostname, mgmt_ip)

def check_sonic_facts(hostname, mgmt_addr, host):
    logger.info("Check neighbor {} eos facts".format(hostname))
    res = host.facts
    logger.info("facts: {}".format(json.dumps(res, indent=4)))
    mgmt_addrs = host.facts['mgmt_interface']
    if len(mgmt_addrs) == 0:
        return "there is no management interface in neighbor {}".format(hostname)
    for addr in mgmt_addrs:
        if addr == mgmt_addr:
            return
    return "neighbor {} has no management address {}".format(hostname, mgmt_ip)

def check_eos_bgp_facts(hostname, host):
    logger.info("Check neighbor {} bgp facts".format(hostname))
    res = host.eos_command(commands=['show ip bgp sum'])
    logger.info("bgp: {}".format(res))
    if not res.has_key('stdout_lines') or u'BGP summary' not in res['stdout_lines'][0][0]:
        return "neighbor {} bgp not configured correctly".format(hostname)

def check_sonic_bgp_facts(hostname, host):
    logger.info("Check neighbor {} bgp facts".format(hostname))
    res = host.command('vtysh -c "show ip bgp sum"')
    logger.info("bgp: {}".format(res))
    if not res.has_key('stdout_lines') or u'Unicast Summary' not in "\n".join(res['stdout_lines']):
        return "neighbor {} bgp not configured correctly".format(hostname)

def test_neighbors_health(duthosts, localhost, nbrhosts, eos, sonic, enum_frontend_dut_hostname):
    """Check each neighbor device health"""

    fails = []
    duthost = duthosts[enum_frontend_dut_hostname]

    config_facts  = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    nei_meta = config_facts.get('DEVICE_NEIGHBOR_METADATA', {})

    dut_type = None
    dev_meta = config_facts.get('DEVICE_METADATA', {})
    if "localhost" in dev_meta and "type" in dev_meta["localhost"]:
        dut_type = dev_meta["localhost"]["type"]

    for k, v in nei_meta.items():
        if v['type'] in ['SmartCable', 'Server', 'Asic'] or dut_type == v['type']:
            # Smart cable doesn't respond to snmp, it doesn't have BGP session either.
            # DualToR has the peer ToR listed in device as well. If the device type
            # is the same as testing DUT, then it is the peer.
            # The server neighbors need to be skipped too.
            # Skip if the neigbhor is asic as well.
            continue

        nbrhost = nbrhosts[k]['host']

        if isinstance(nbrhost, EosHost):
            failmsg = check_snmp(k, v['mgmt_addr'], localhost, eos['snmp_rocommunity'], True)
            if failmsg:
                fails.append(failmsg)

            failmsg = check_eos_facts(k, v['mgmt_addr'], nbrhost)
            if failmsg:
                fails.append(failmsg)

            failmsg = check_eos_bgp_facts(k, nbrhost)
            if failmsg:
                fails.append(failmsg)

        elif isinstance(nbrhost, SonicHost):
            failmsg = check_snmp(k, v['mgmt_addr'], localhost, sonic['snmp_rocommunity'], False)
            if failmsg:
                fails.append(failmsg)

            failmsg = check_sonic_facts(k, v['mgmt_addr'], nbrhost)
            if failmsg:
                fails.append(failmsg)

            failmsg = check_sonic_bgp_facts(k, nbrhost)
            if failmsg:
                fails.append(failmsg)

        else:
            failmsg = "neighbor type {} is unknown".format(k)
            fails.append(failmsg)


    # TODO: check link, bgp, etc. on

    pytest_assert(len(fails) == 0, "\n".join(fails))
