import json
import pytest
import logging
logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
]

def check_snmp(hostname, mgmt_addr, localhost, community):
    logger.info("Check neighbor {}, mgmt ip {} snmp".format(hostname, mgmt_addr))
    res = localhost.snmp_facts(host=mgmt_addr, version='v2c', is_eos=True, community=community)
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

    try:
        mgmt_ip = eos_facts['ansible_net_interfaces']['Management0']['ipv4']['address']
    except:
        return "neighbor {} managment address not assigned".format(hostname)

    if mgmt_ip != mgmt_addr:
        return "neighbor {} management address {} not correct".format(hostname, mgmt_ip)

def check_bgp_facts(hostname, host):
    logger.info("Check neighbor {} bgp facts".format(hostname))
    res = host.eos_command(commands=['show ip bgp sum'])
    logger.info("bgp: {}".format(res))
    if not res.has_key('stdout_lines') or u'BGP summary' not in res['stdout_lines'][0][0]:
        return "neighbor {} bgp not configured correctly".format(hostname)

def test_neighbors_health(duthost, testbed_devices, nbrhosts, eos):
    """Check each neighbor device health"""

    fails = []
    localhost = testbed_devices['localhost']
    config_facts  = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    nei_meta = config_facts.get('DEVICE_NEIGHBOR_METADATA', {})
    for k, v in nei_meta.items():
        failmsg = check_snmp(k, v['mgmt_addr'], localhost, eos['snmp_rocommunity'])
        if failmsg:
            fails.append(failmsg)

        eoshost = nbrhosts[k]
        failmsg = check_eos_facts(k, v['mgmt_addr'], eoshost)
        if failmsg:
            fails.append(failmsg)

        failmsg = check_bgp_facts(k, eoshost)
        if failmsg:
            fails.append(failmsg)

    # TODO: check link, bgp, etc. on
    if len(fails) > 0:
        pytest.fail("\n".join(fails))
