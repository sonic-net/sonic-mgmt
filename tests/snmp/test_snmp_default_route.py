import pytest

from tests.common.helpers.assertions import pytest_require
from tests.common.helpers.snmp_helpers import get_snmp_facts

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]


@pytest.mark.bsl
def test_snmp_default_route(duthosts, enum_rand_one_per_hwsku_frontend_hostname, localhost, creds_all_duts, tbinfo):
    """compare the snmp facts between observed states and target state"""

    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    pytest_require('backend' not in tbinfo['topo']['name'], "Skip this testcase since this topology {} has no default routes".format(tbinfo['topo']['name']))

    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    snmp_facts = get_snmp_facts(localhost, host=hostip, version="v2c", community=creds_all_duts[duthost]["snmp_rocommunity"], wait=True)['ansible_facts']
    dut_result = duthost.shell('show ip route 0.0.0.0/0 | grep "\*"')

    dut_result_nexthops = []
    # ipCidrRouteEntry MIB for default route will have entries
    # where next hop are not eth0 interface.
    for line in dut_result['stdout_lines']:
        if 'via' in line:
            ip, interface = line.split('via')
            ip = ip.strip("*, ")
            interface = interface.strip("*, ")
            if interface != "eth0":
                dut_result_nexthops.append(ip)

    # If show ip route 0.0.0.0/0 has route only via eth0,
    # or has no route snmp_facts for ip_cidr_route
    # will be empty.
    if len(dut_result_nexthops) == 0:
        assert 'snmp_cidr_route' not in snmp_facts, 'snmp_cidr_route should not be present in snmp_facts'

    if len(dut_result_nexthops) != 0:
        # Test to ensure show ip route 0.0.0.0/0 result matches with SNMP result
        for ip in dut_result_nexthops:
            assert ip in snmp_facts['snmp_cidr_route'], "{} ip not found in snmp_facts".format(ip)
            assert snmp_facts['snmp_cidr_route'][ip]['route_dest'] == '0.0.0.0', "Incorrect route_dest for {} ip".format(ip)
            assert snmp_facts['snmp_cidr_route'][ip]['status'] == '1', "Incorrect status for {} ip".format(ip)

        # Compare the length of routes in CLI output and SNMP facts
        assert len(snmp_facts['snmp_cidr_route'].keys()) == len(snmp_facts['snmp_cidr_route'].keys()), \
                "Number or route entries in SNMP does not match with cli"
