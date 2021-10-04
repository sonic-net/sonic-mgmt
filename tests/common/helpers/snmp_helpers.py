from tests.common.utilities import wait_until
from tests.common.errors import RunAnsibleModuleFail
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

DEF_WAIT_TIMEOUT=300
DEF_CHECK_INTERVAL=10

global_snmp_facts={}

def _get_snmp_facts(localhost, host, version, community, is_dell, module_ignore_errors):
    snmp_facts = localhost.snmp_facts(host=host, version=version, community=community, is_dell=is_dell, module_ignore_errors=module_ignore_errors)
    return snmp_facts


def _update_snmp_facts(localhost, host, version, community, is_dell):
    global global_snmp_facts

    try:
        global_snmp_facts = _get_snmp_facts(localhost, host, version, community, is_dell,
                                            module_ignore_errors=False)
    except RunAnsibleModuleFail as e:
        logger.info("encountered error when getting snmp facts: {}".format(e))
        global_snmp_facts = {}
        return False

    return True


def get_snmp_facts(localhost, host, version, community, is_dell=False, module_ignore_errors=False,
                   wait=False, timeout=DEF_WAIT_TIMEOUT, interval=DEF_CHECK_INTERVAL):
    if not wait:
        return _get_snmp_facts(localhost, host, version, community, is_dell, module_ignore_errors)

    global global_snmp_facts

    pytest_assert(wait_until(timeout, interval, _update_snmp_facts, localhost, host, version,
                             community, is_dell), "Timeout waiting for SNMP facts")
    return global_snmp_facts

