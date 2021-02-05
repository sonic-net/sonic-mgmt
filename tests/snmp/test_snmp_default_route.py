import pytest
try:  # python3
    from shlex import quote
except ImportError:  # python2
    from pipes import quote

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]


@pytest.mark.bsl
def test_snmp_default_route(duthosts, enum_dut_hostname, localhost, creds):
    """compare the snmp facts between observed states and target state"""

    duthost = duthosts[enum_dut_hostname]
    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    dut_result = duthost.shell('show ip route 0.0.0.0/0 | grep "\*"')
    route_count = 0

    # Test to ensure show ip route 0.0.0.0/0 result matches with SNMP result
    for line in dut_result['stdout_lines']:
        if 'via' in line:
            ip, interface = line.split('via')
            ip = ip.strip("*, ")
            interface = interface.strip("*, ")
            if interface != "eth0":
                route_count = route_count + 1
                snmp_result = localhost.shell(
                        'snmpget -v2c -c {} {} 1.3.6.1.2.1.4.24.4.1.1.0.0.0.0.0.0.0.0.0.{}'
                        .format(quote(creds['snmp_rocommunity']), hostip, ip))
                assert snmp_result is not None, "snmpget failed for default route via {}".format(ip)
                assert(snmp_result['stdout_lines'][0].split('=')[1].strip().lower() == "ipaddress: 0.0.0.0")

                snmp_result = localhost.shell(
                        'snmpget -v2c -c {} {} 1.3.6.1.2.1.4.24.4.1.16.0.0.0.0.0.0.0.0.0.{}'
                        .format(quote(creds['snmp_rocommunity']), hostip, ip))
                assert snmp_result is not None, "snmpget failed for default route via {}".format(ip)
                assert(snmp_result['stdout_lines'][0].split('=')[1].strip().lower() == "integer: 1")

    # Test to ensure the number of lines in SNMP result matches the output from show ip route
    snmp_result = localhost.shell(
            'snmpwalk -v2c -c {} {} 1.3.6.1.2.1.4.24.4.1.1'.format(quote(creds['snmp_rocommunity']), hostip))
    assert snmp_result is not None, "snmpwalk failed for default route via {}".format(ip)
    assert len(snmp_result['stdout_lines']) == route_count

    snmp_result = localhost.shell(
            'snmpwalk -v2c -c {} {} 1.3.6.1.2.1.4.24.4.1.16'.format(quote(creds['snmp_rocommunity']), hostip))
    assert snmp_result is not None, "snmpwalk failed for default route via {}".format(ip)
    assert len(snmp_result['stdout_lines']) == route_count
