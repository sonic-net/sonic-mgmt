import pytest
from tests.common.helpers.assertions import pytest_assert

PSU_STATUS_OK = 2
PSU_STATUS_FUNCTIONING_FAIL = 7
PSU_STATUS_MODULE_MISSING = 8

pytestmark = [
    pytest.mark.topology('any')
]

@pytest.mark.bsl
def test_snmp_numpsu(duthosts, enum_supervisor_dut_hostname, localhost, creds_all_duts):
    duthost = duthosts[enum_supervisor_dut_hostname]

    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    snmp_facts = localhost.snmp_facts(host=hostip, version="v2c", community=creds_all_duts[duthost]["snmp_rocommunity"])['ansible_facts']
    res = duthost.shell("psuutil numpsus")
    assert int(res[u'rc']) == 0, "Failed to get number of PSUs"

    numpsus = int(res['stdout'])
    assert numpsus == len(snmp_facts['snmp_psu'])


@pytest.mark.bsl
def test_snmp_psu_status(duthosts, enum_supervisor_dut_hostname, localhost, creds_all_duts):
    duthost = duthosts[enum_supervisor_dut_hostname]
    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    snmp_facts = localhost.snmp_facts(host=hostip, version="v2c", community=creds_all_duts[duthost]["snmp_rocommunity"])['ansible_facts']

    psus_on = 0
    msg = "Unexpected operstatus results {} != {} for PSU {}"

    for psu_indx, operstatus in snmp_facts['snmp_psu'].items():
        get_presence = duthost.shell("redis-cli -n 6 hget 'PSU_INFO|PSU {}' presence".format(psu_indx))
        get_status = duthost.shell("redis-cli -n 6 hget 'PSU_INFO|PSU {}' status".format(psu_indx))
        status = get_status['stdout'] == 'true'
        presence = get_presence['stdout'] == 'true'

        if presence and status:
            pytest_assert(int(operstatus['operstatus']) == PSU_STATUS_OK,
                          msg.format(operstatus['operstatus'], PSU_STATUS_OK, psu_indx))
            psus_on += 1
        elif presence and not status:
            pytest_assert(int(operstatus['operstatus']) == PSU_STATUS_FUNCTIONING_FAIL,
                          msg.format(operstatus['operstatus'], PSU_STATUS_FUNCTIONING_FAIL, psu_indx))
        elif not presence:
            pytest_assert(int(operstatus['operstatus']) == PSU_STATUS_MODULE_MISSING,
                          msg.format(operstatus['operstatus'], PSU_STATUS_MODULE_MISSING, psu_indx))

    pytest_assert(psus_on >= 1, "At least one PSU should be with operstatus OK")