import pytest

PSU_STATUS_OK = 2

pytestmark = [
    pytest.mark.topology('any')
]

@pytest.mark.bsl
def test_snmp_numpsu(duthost, localhost, creds):

    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    snmp_facts = localhost.snmp_facts(host=hostip, version="v2c", community=creds["snmp_rocommunity"])['ansible_facts']
    res = duthost.shell("psuutil numpsus")
    assert int(res[u'rc']) == 0, "Failed to get number of PSUs"

    numpsus = int(res['stdout'])
    assert numpsus == len(snmp_facts['snmp_psu'])


@pytest.mark.bsl
def test_snmp_psu_status(duthost, localhost, creds):

    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    snmp_facts = localhost.snmp_facts(host=hostip, version="v2c", community=creds["snmp_rocommunity"])['ansible_facts']

    for k, v in snmp_facts['snmp_psu'].items():
        if int(v['operstatus']) != PSU_STATUS_OK:
            pytest.fail("PSU {} operstatus is not OK!".format(k))
