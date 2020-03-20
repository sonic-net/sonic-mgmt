import pytest
import logging
logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
]

def test_neighbors_health(duthost, testbed_devices, eos):
    """Check each neighbor device health"""

    fails = []
    localhost = testbed_devices['localhost']
    config_facts  = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    nei_meta = config_facts.get('DEVICE_NEIGHBOR_METADATA', {})
    for k, v in nei_meta.items():
        logger.info("Check neighbor {}, mgmt ip {} snmp".format(k, v['mgmt_addr']))
        res = localhost.snmp_facts(host=v['mgmt_addr'], version='v2c', is_eos=True, community=eos['snmp_rocommunity'])
        try:
            snmp_data = res['ansible_facts']
        except:
            fails.append("neighbor {} has no snmp data".format(k))
            continue
        logger.info("Neighbor {}, sysdescr {}".format(k, snmp_data['ansible_sysdescr']))

    # TODO: check link, bgp, etc. on 

    if len(fails) > 0:
        pytest.fail("\n".join(fails))
