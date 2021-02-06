import pytest
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)

def ssh_remote_run(localhost, remote_ip, username, password, cmd):
    res = localhost.shell("sshpass -p {} ssh "\
                          "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "\
                          "{}@{} {}".format(
            password, username, remote_ip, cmd), module_ignore_errors=True)
    return res

def test_ro_user(localhost, duthosts, rand_one_dut_hostname, creds, test_tacacs):
    duthost = duthosts[rand_one_dut_hostname]
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    res = ssh_remote_run(localhost, dutip, creds['tacacs_ro_user'], creds['tacacs_ro_user_passwd'], 'cat /etc/passwd')

    for l in res['stdout_lines']:
        fds = l.split(':')
        if fds[0] == "test":
            assert fds[4] == "remote_user"

def test_ro_user_ipv6(localhost, duthosts, rand_one_dut_hostname, creds, test_tacacs_v6):
    duthost = duthosts[rand_one_dut_hostname]
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    res = ssh_remote_run(localhost, dutip, creds['tacacs_ro_user'], creds['tacacs_ro_user_passwd'], 'cat /etc/passwd')

    for l in res['stdout_lines']:
        fds = l.split(':')
        if fds[0] == "test":
            assert fds[4] == "remote_user"

def test_ro_user_allowed_command(localhost, duthosts, rand_one_dut_hostname, creds, test_tacacs):
    duthost = duthosts[rand_one_dut_hostname]
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    # Run as readonly use the commands allowed by sudoers file
    # TODO: some commands need further preparation, will enable when runable directly
    # TODO: `tail -F` will not exit, not posssible to test here
    # Note: the quagga command could only run on image with quagga
    commands_direct = [
            'sudo cat /var/log/syslog',
            'sudo cat /var/log/syslog.1',
            'sudo cat /var/log/syslog.2.gz',
            'sudo brctl show',
            'sudo docker exec snmp cat /etc/snmp/snmpd.conf',
            # 'sudo docker exec bgp cat /etc/quagga/bgpd.conf',
            'sudo docker images --format "table {% raw %}{{.Repository}}\\t{{.Tag}}\\t{{.ID}}\\t{{.Size}}{% endraw %}"',
            'sudo docker ps',
            'sudo docker ps -a',
            'sudo lldpctl',
            # 'sudo sensors',
            # 'sudo tail -F /var/log/syslog',
            '"sudo vtysh -c \'show ip bgp su\'"',
            '"sudo vtysh -n 0 -c \'show ip bgp su\'"',
            'sudo decode-syseeprom',
            'sudo generate_dump',
            'sudo lldpshow',
            # 'sudo psuutil *',
            # 'sudo sfputil show *',
            'sudo ip netns identify 1',
    ]
    if "201911" in duthosts[rand_one_dut_hostname].os_version:
        commands_direct.append('sudo sonic_installer list')
    else:
        commands_direct.append('sudo sonic-installer list')

    # Run as readonly use the commands allowed indirectly based on sudoers file
    commands_indirect = [
            'show version',
    ]

    for command in commands_direct + commands_indirect:
        res = ssh_remote_run(localhost, dutip, creds['tacacs_ro_user'], creds['tacacs_ro_user_passwd'], command)
        # Verify that the command is allowed
        logger.info("check command \"{}\" rc={}".format(command, res['rc']))
        pytest_assert(res['rc'] == 0 or (res['rc'] != 0 and "Make sure your account has RW permission to current device" not in res['stderr']),
                "command '{}' not authorized".format(command))

def test_ro_user_banned_command(localhost, duthosts, rand_one_dut_hostname, creds, test_tacacs):
    duthost = duthosts[rand_one_dut_hostname]
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    # Run as readonly use the commands allowed by sudoers file
    commands = [
            'sudo shutdown',
    ]

    for command in commands:
        res = ssh_remote_run(localhost, dutip, creds['tacacs_ro_user'], creds['tacacs_ro_user_passwd'], command)
        # Verify that the command is allowed
        logger.info("check command \"{}\" rc={}".format(command, res['rc']))
        pytest_assert(res['rc'] != 0 and "Make sure your account has RW permission to current device" in res['stderr'],
                "command '{}' authorized".format(command))
