import pytest
from tests.common.helpers.snmp_helpers import get_snmp_facts
from tests.common import config_reload

pytestmark = [
    pytest.mark.topology('t0', 't1', 't2', 'm0', 'mx', 't1-multi-asic'),
    pytest.mark.device_type('vs')
]


@pytest.fixture(autouse=True, scope='module')
def config_reload_after_test(duthosts,
                             enum_rand_one_per_hwsku_frontend_hostname):
    yield
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    config_reload(duthost, config_source='config_db', safe_reload=True, check_intf_up_ports=True)


@pytest.mark.bsl
def test_snmp_link_local_ip(duthosts,
                            enum_rand_one_per_hwsku_frontend_hostname,
                            nbrhosts, tbinfo, localhost, creds_all_duts):
    """
    Test SNMP query to DUT over link local IP
      - configure eth0's link local IP as snmpagentaddress
      - Query over linklocal IP from within snmp docker
      - Get SysDescr from snmpfacts
      - compare result from snmp query over link local IP and snmpfacts
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    hostip = duthost.host.options['inventory_manager'].get_host(
        duthost.hostname).vars['ansible_host']
    snmp_facts = get_snmp_facts(
        localhost, host=hostip, version="v2c",
        community=creds_all_duts[duthost.hostname]["snmp_rocommunity"],
        wait=True)['ansible_facts']
    # Get link local IP of mamangement interface
    ip_cmd = 'ip addr show eth0 | grep "inet6" | grep "link"\
              | awk "{print $2}" | cut -d/ -f1'
    link_local_ips = duthost.shell(ip_cmd)['stdout_lines']
    sysdescr_oid = '1.3.6.1.2.1.1.1.0'
    # configure link local IP in config_db
    for ip in link_local_ips:
        if ip.split()[1].lower().startswith('fe80'):
            link_local_ip = ip.split()[1]
            break
    # configure link local IP in config_db
    # Restart snmp service to regenerate snmpd.conf with
    # link local IP configured in MGMT_INTERFACE
    duthost.shell("config snmpagentaddress add {}%eth0".format(link_local_ip))
    stdout_lines = duthost.shell("docker exec snmp snmpget \
                                 -v2c -c {} {}%eth0 {}"
                                 .format(creds_all_duts[duthost.hostname]
                                         ['snmp_rocommunity'],
                                         link_local_ip,
                                         sysdescr_oid))['stdout_lines'][0]
    assert "SONiC Software Version" in stdout_lines,\
        "Sysdescr not found in SNMP result from Link Local IP {}".format(
                link_local_ip)
    assert snmp_facts['ansible_sysdescr'] in stdout_lines,\
        "Sysdescr from IP{} not matching with result from Mgmt IPv4.".format(
                link_local_ip)
