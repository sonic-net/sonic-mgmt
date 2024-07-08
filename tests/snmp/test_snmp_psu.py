import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.snmp_helpers import get_snmp_facts
from natsort import natsorted
import logging

PSU_STATUS_OK = 2
PSU_STATUS_FUNCTIONING_FAIL = 7
PSU_STATUS_MODULE_MISSING = 8

pytestmark = [
    pytest.mark.topology('any')
]


@pytest.mark.bsl
def test_snmp_numpsu(duthosts, enum_supervisor_dut_hostname, localhost, creds_all_duts):
    duthost = duthosts[enum_supervisor_dut_hostname]

    hostip = duthost.host.options['inventory_manager'].get_host(
        duthost.hostname).vars['ansible_host']

    snmp_facts = get_snmp_facts(
        localhost, host=hostip, version="v2c",
        community=creds_all_duts[duthost.hostname]["snmp_rocommunity"], wait=True)['ansible_facts']
    res = duthost.shell("psuutil numpsus")
    assert int(res['rc']) == 0, "Failed to get number of PSUs"

    numpsus = int(res['stdout'])
    assert numpsus == len(snmp_facts['snmp_psu'])


@pytest.mark.bsl
def test_snmp_psu_status(duthosts, enum_supervisor_dut_hostname, localhost, creds_all_duts):
    duthost = duthosts[enum_supervisor_dut_hostname]
    hostip = duthost.host.options['inventory_manager'].get_host(
        duthost.hostname).vars['ansible_host']
    snmp_facts = get_snmp_facts(
        localhost, host=hostip, version="v2c",
        community=creds_all_duts[duthost.hostname]["snmp_rocommunity"], wait=True)['ansible_facts']

    psu_keys = natsorted(redis_get_keys(duthost, 'STATE_DB', 'PSU_INFO|*'))
    psus_on = 0
    msg = "Unexpected operstatus results {} != {} for PSU {}"

    for psu_indx, operstatus in snmp_facts['snmp_psu'].items():
        get_presence = duthost.shell(
            "redis-cli -n 6 hget '{}' presence".format(psu_keys[int(psu_indx)-1]))
        get_status = duthost.shell(
            "redis-cli -n 6 hget '{}' status".format(psu_keys[int(psu_indx)-1]))
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

    pytest_assert(
        psus_on >= 1, "At least one PSU should be with operstatus OK")


def redis_get_keys(duthost, db_id, pattern):
    """
    Get all keys for a given pattern in given redis database
    :param duthost: DUT host object
    :param db_id: ID of redis database
    :param pattern: Redis key pattern
    :return: A list of key name in string
    """
    cmd = 'sonic-db-cli {} KEYS \"{}\"'.format(db_id, pattern)
    logging.debug('Getting keys from redis by command: {}'.format(cmd))
    output = duthost.shell(cmd)
    content = output['stdout'].strip()
    return content.split('\n') if content else None
