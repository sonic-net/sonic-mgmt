import pytest
import time
from tests.common.helpers.assertions import pytest_assert
from .utils import check_output

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)

SLEEP_TIME      = 10
TIMEOUT_LIMIT   = 120

def ssh_remote_run(localhost, remote_ip, username, password, cmd):
    res = localhost.shell("sshpass -p {} ssh "\
                          "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "\
                          "{}@{} {}".format(
            password, username, remote_ip, cmd), module_ignore_errors=True)
    return res


def does_command_exist(localhost, remote_ip, username, password, command):
    usr_find_cmd = "find /usr -name {}".format(command)
    usr_result = ssh_remote_run(localhost, remote_ip, username, password, usr_find_cmd)

    bin_find_cmd = "find /bin -name {}".format(command)
    bin_result = ssh_remote_run(localhost, remote_ip, username, password, bin_find_cmd)

    if usr_result["rc"] != 0:
        logger.warning('unexpected rc={} from "{}"'.format(usr_result["rc"], usr_find_cmd))

    if bin_result["rc"] != 0:
        logger.warning('unexpected rc={} from "{}"'.format(bin_result["rc"], bin_find_cmd))

    return len(usr_result["stdout_lines"]) > 0 or len(bin_result["stdout_lines"]) > 0

def ssh_remote_allow_run(localhost, remote_ip, username, password, cmd):
    res = ssh_remote_run(localhost, remote_ip, username, password, cmd)
    # Verify that the command is allowed
    logger.info("check command \"{}\" rc={}".format(cmd, res['rc']))
    expected = res['rc'] == 0 or (res['rc'] != 0 and "Make sure your account has RW permission to current device" not in res['stderr'])
    if not expected:
        logger.error("error output=\"{}\"".format(res["stderr"]))
    return expected


def ssh_remote_ban_run(localhost, remote_ip, username, password, cmd):
    res = ssh_remote_run(localhost, remote_ip, username, password, cmd)
    # Verify that the command is allowed
    logger.info("check command \"{}\" rc={}".format(cmd, res['rc']))
    return res['rc'] != 0 and "Make sure your account has RW permission to current device" in res['stderr']

def wait_for_tacacs(localhost, remote_ip, username, password):
    current_attempt = 0
    cmd = 'systemctl status hostcfgd.service'
    while (True):
        # Wait for tacacs to finish configuration from hostcfgd
        logger.info("Check if hostcfgd started and configured tacac attempt = {}".format(current_attempt))
        time.sleep(SLEEP_TIME)
        output = localhost.shell("sshpass -p {} ssh "\
                        "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "\
                        "{}@{} {}".format(
        password, username, remote_ip, cmd), module_ignore_errors=True)['stdout_lines']
        if "active (running)" in str(output):
            return
        else:
            if current_attempt >= TIMEOUT_LIMIT/SLEEP_TIME:
                pytest_assert(False, "hostcfgd did not start after {} seconds".format(TIMEOUT_LIMIT))
            else:
                current_attempt += 1

def test_ro_user(localhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts, test_tacacs):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    res = ssh_remote_run(localhost, dutip, creds_all_duts[duthost]['tacacs_ro_user'],
                         creds_all_duts[duthost]['tacacs_ro_user_passwd'], 'cat /etc/passwd')

    check_output(res, 'test', 'remote_user')

def test_ro_user_ipv6(localhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts, test_tacacs_v6):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    res = ssh_remote_run(localhost, dutip, creds_all_duts[duthost]['tacacs_ro_user'],
                         creds_all_duts[duthost]['tacacs_ro_user_passwd'], 'cat /etc/passwd')

    check_output(res, 'test', 'remote_user')

def test_ro_user_allowed_command(localhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts, test_tacacs):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.host.options["inventory_manager"].get_host(duthost.hostname).vars["ansible_host"]

    # Run as RO and use the commands allowed by the sudoers file
    commands = {
        "cat": ["sudo cat /var/log/syslog", "sudo cat /var/log/syslog.1", "sudo cat /var/log/syslog.2.gz"],
        "brctl": ["sudo brctl show"],
        "docker": [
            "sudo docker exec snmp cat /etc/snmp/snmpd.conf",
            'sudo docker images --format "table {% raw %}{{.Repository}}\\t{{.Tag}}\\t{{.ID}}\\t{{.Size}}{% endraw %}"',
            "sudo docker ps",
            "sudo docker ps -a",
        ],
        "lldpctl": ["sudo lldpctl"],
        "vtysh": ['sudo vtysh -c "show version"', 'sudo vtysh -c "show bgp ipv4 summary json"', 'sudo vtysh -c "show bgp ipv6 summary json"'],
        "rvtysh": ['sudo rvtysh -c "show ip bgp su"', 'sudo rvtysh -n 0 -c "show ip bgp su"'],
        "decode-syseeprom": ["sudo decode-syseeprom"],
        "generate_dump": ['sudo generate_dump -s "5 secs ago"'],
        "lldpshow": ["sudo lldpshow"],
        "pcieutil": ["sudo pcieutil check"],
        "ip": ["sudo ip netns identify 1"],
        "ipintutil": [
            "sudo ipintutil",
            "sudo ipintutil -a ipv6",
            "sudo ipintutil -n asic0 -d all",
            "sudo ipintutil -n asic0 -d all -a ipv6",
        ],
        "show": [
            "show version",
            "show interface status",
            "show interface portchannel",
            "show ip bgp summary",
            "show ip interface",
            "show ipv6 interface",
            "show lldp table",
        ],
    }

    # NOTE: `sudo tail -F /var/log/syslog` will not exit, not posssible to test here
    # NOTE: `sudo docker exec bgp cat /etc/quagga/bgpd.conf` can only run on image with quagga
    # TODO: some commands need further preparation, will enable when runable directly:
    # sudo sensors
    # sudo psuutil *
    # sudo sfputil show

    for command in commands:
        if does_command_exist(localhost, dutip, creds_all_duts[duthost]['tacacs_ro_user'],
                              creds_all_duts[duthost]['tacacs_ro_user_passwd'], command):
            for subcommand in commands[command]:
                allowed = ssh_remote_allow_run(localhost, dutip, creds_all_duts[duthost]['tacacs_ro_user'],
                                               creds_all_duts[duthost]['tacacs_ro_user_passwd'], subcommand)
                pytest_assert(allowed, "command '{}' not authorized".format(subcommand))
        else:
            logger.info('"{}" not found on DUT, skipping...'.format(command))

    dash_allowed = ssh_remote_allow_run(localhost, dutip, creds_all_duts[duthost]['tacacs_ro_user'],
                                        creds_all_duts[duthost]['tacacs_ro_user_passwd'], 'sudo sonic-installer list')
    if not dash_allowed:
        dash_banned = ssh_remote_ban_run(localhost, dutip, creds_all_duts[duthost]['tacacs_ro_user'],
                                         creds_all_duts[duthost]['tacacs_ro_user_passwd'], 'sudo sonic-installer list')
        pytest_assert(dash_banned, "command 'sudo sonic-installer list' should be either allowed or banned")
        underscore_allowed = ssh_remote_allow_run(localhost, dutip, creds_all_duts[duthost]['tacacs_ro_user'],
                                                  creds_all_duts[duthost]['tacacs_ro_user_passwd'],
                                                  'sudo sonic_installer list')
        pytest_assert(underscore_allowed, "command 'sudo sonic_installer list' should be allowed if"
                                          " 'sudo sonic-installer list' is banned")


def test_ro_user_banned_command(localhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts, test_tacacs):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    # Run as readonly use the commands allowed by sudoers file
    commands = [
            'sudo shutdown',
            # all commands under the config tree
            'sudo config'
    ]

    # Wait until hostcfgd started and configured tacas authorization
    wait_for_tacacs(localhost, dutip, creds_all_duts[duthost]['tacacs_ro_user'], creds_all_duts[duthost]['tacacs_ro_user_passwd'])

    for command in commands:
        banned = ssh_remote_ban_run(localhost, dutip, creds_all_duts[duthost]['tacacs_ro_user'],
                                    creds_all_duts[duthost]['tacacs_ro_user_passwd'], command)
        pytest_assert(banned, "command '{}' authorized".format(command))
