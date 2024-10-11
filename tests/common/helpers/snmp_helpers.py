import logging
import ipaddress

from tests.common.utilities import wait_until
from tests.common.errors import RunAnsibleModuleFail
from tests.common.helpers.assertions import pytest_assert
from tests.common.devices.eos import EosHost

logger = logging.getLogger(__name__)

DEF_WAIT_TIMEOUT = 300
DEF_CHECK_INTERVAL = 10
SNMP_SUBAGENT_WAIT_TIMEOUT = 120
SNMP_SUBAGENT_CHECK_INTERVAL = 5

global_snmp_facts = {}


def is_snmp_subagent_running(duthost):
    cmd = "docker exec snmp supervisorctl status snmp-subagent"
    output = duthost.shell(cmd)
    if "RUNNING" in output["stdout"]:
        return True
    return False


def _get_snmp_facts(localhost, host, version, community, is_dell, include_swap, module_ignore_errors):
    snmp_facts = localhost.snmp_facts(host=host, version=version, community=community, is_dell=is_dell,
                                      module_ignore_errors=module_ignore_errors, include_swap=include_swap)
    return snmp_facts


def _update_snmp_facts(localhost, host, version, community, is_dell, include_swap, duthost):
    global global_snmp_facts

    try:
        pytest_assert(
            wait_until(SNMP_SUBAGENT_WAIT_TIMEOUT, SNMP_SUBAGENT_CHECK_INTERVAL, 0,
                       is_snmp_subagent_running, duthost),
            "SNMP Sub-Agent is not in Running state")
        global_snmp_facts = _get_snmp_facts(localhost, host, version, community, is_dell, include_swap,
                                            module_ignore_errors=False)
    except RunAnsibleModuleFail as e:
        logger.info("encountered error when getting snmp facts: {}".format(e))
        global_snmp_facts = {}
        return False

    return True


def get_snmp_facts(duthost, localhost, host, version, community, is_dell=False, module_ignore_errors=False,
                   wait=False, include_swap=False, timeout=DEF_WAIT_TIMEOUT, interval=DEF_CHECK_INTERVAL):
    if not wait:
        return _get_snmp_facts(localhost, host, version, community, is_dell, include_swap, module_ignore_errors)

    global global_snmp_facts

    pytest_assert(wait_until(timeout, interval, 0, _update_snmp_facts, localhost, host, version,
                             community, is_dell, include_swap, duthost), "Timeout waiting for SNMP facts")
    return global_snmp_facts


def get_snmp_output(ip, duthost, nbr, creds_all_duts, oid='.1.3.6.1.2.1.1.1.0'):
    """
    Get snmp output from duthost using specific ip to query
    snmp query is sent from neighboring ceos/vsonic

     Args:
        ip(str): IP of dut to be used to send SNMP query
        duthost: duthost
        nbr: from where the snmp query should be executed
        creds_all_duts: creds to get snmp_rocommunity of duthost
        oid: to query

    Returns:
        SNMP result
    """
    ipaddr = ipaddress.ip_address(ip)
    iptables_cmd = "iptables"

    if isinstance(ipaddr, ipaddress.IPv6Address):
        iptables_cmd = "ip6tables"

    ip_tbl_rule_add = "sudo {} -I INPUT 1 -p udp --dport 161 -d {} -j ACCEPT".format(
        iptables_cmd, ip)
    duthost.shell(ip_tbl_rule_add)

    if isinstance(nbr["host"], EosHost):
        eos_snmpget = "bash snmpget -v2c -c {} {} {}".format(
            creds_all_duts[duthost.hostname]['snmp_rocommunity'], ip, oid)
        out = nbr['host'].eos_command(commands=[eos_snmpget])
    else:
        command = "docker exec snmp snmpwalk -v 2c -c {} {} {}".format(
                  creds_all_duts[duthost.hostname]['snmp_rocommunity'], ip, oid)
        out = nbr['host'].command(command)

    ip_tbl_rule_del = "sudo {} -D INPUT -p udp --dport 161 -d {} -j ACCEPT".format(
        iptables_cmd, ip)
    duthost.shell(ip_tbl_rule_del)

    return out
