import pytest
import ipaddress
from tests.common.helpers.snmp_helpers import get_snmp_facts
try:  # python3
    from shlex import quote
except ImportError:  # python2
    from pipes import quote

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]


def get_snmp_output(ip, duthost, nbr, creds_all_duts):
    ipaddr = ipaddress.ip_address(ip)
    iptables_cmd = "iptables"

    # TODO : Fix snmp query over loopback v6 and remove this check and add IPv6 ACL table/rule.
    if isinstance(ipaddr, ipaddress.IPv6Address):
        iptables_cmd = "ip6tables"
        return None

    ip_tbl_rule_add = "sudo {} -I INPUT 1 -p udp --dport 161 -d {} -j ACCEPT".format(iptables_cmd, ip)
    duthost.shell(ip_tbl_rule_add)

    eos_snmpget = "bash snmpget -v2c -c {} {} 1.3.6.1.2.1.1.1.0".format(quote(creds_all_duts[duthost]['snmp_rocommunity']), ip)
    out = nbr['host'].eos_command(commands=[eos_snmpget])

    ip_tbl_rule_del = "sudo {} -D INPUT -p udp --dport 161 -d {} -j ACCEPT".format(iptables_cmd, ip)
    duthost.shell(ip_tbl_rule_del)

    return out


@pytest.mark.bsl
def test_snmp_loopback(duthosts, enum_rand_one_per_hwsku_frontend_hostname, nbrhosts, tbinfo, localhost, creds_all_duts):
    """
    Test SNMP query to DUT over loopback IP
      - Send SNMP query over loopback IP from one of the BGP Neighbors
      - Get SysDescr from snmpfacts
      - compare result from snmp query over loopback IP and snmpfacts
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    snmp_facts = get_snmp_facts(localhost, host=hostip, version="v2c", community=creds_all_duts[duthost]["snmp_rocommunity"], wait=True)['ansible_facts']
    config_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
    # Get first neighbor VM information
    nbr = nbrhosts[list(nbrhosts.keys())[0]]

    # TODO: Fix snmp query over Management IPv6 adderess and add SNMP test over management IPv6 address.

    for ip in config_facts[u'LOOPBACK_INTERFACE'][u'Loopback0']:
        loip = ip.split('/')[0]
        loip = ipaddress.ip_address(loip)
        # TODO: Fix SNMP query over IPv6 and remove the below check.
        if not isinstance(loip, ipaddress.IPv4Address):
            continue
        result = get_snmp_output(loip, duthost, nbr, creds_all_duts)
        assert result is not None, 'No result from snmpget'
        assert len(result[u'stdout_lines']) > 0, 'No result from snmpget'
        assert "SONiC Software Version" in result[u'stdout_lines'][0][0], "Sysdescr not found in SNMP result from IP {}".format(ip)
        assert snmp_facts['ansible_sysdescr'] in result[u'stdout_lines'][0][0], "Sysdescr from IP{} not matching with result from Mgmt IPv4.".format(ip)
