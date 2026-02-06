import time
import logging
import pytest
import json
from tests.common.utilities import wait_until
from tests.common.platform.device_utils import get_dpu_ip, get_dpu_port
from tests.common.helpers.gnmi_utils import GNMIEnvironment, add_gnmi_client_common_name, del_gnmi_client_common_name, \
                                            dump_gnmi_log, dump_system_status
from tests.common.helpers.gnmi_utils import gnmi_container   # noqa: F401
from tests.common.helpers.ntp_helper import NtpDaemon, get_ntp_daemon_in_use   # noqa: F401


logger = logging.getLogger(__name__)
GNMI_CONTAINER_NAME = ''
GNMI_PROGRAM_NAME = ''
GNMI_PORT = 0
# Wait 15 seconds after starting GNMI server
GNMI_SERVER_START_WAIT_TIME = 15


def apply_cert_config(duthost):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    # Get subtype
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    metadata = cfg_facts["DEVICE_METADATA"]["localhost"]
    subtype = metadata.get('subtype', None)
    # Stop all running program
    dut_command = "docker exec %s supervisorctl status" % (env.gnmi_container)
    output = duthost.shell(dut_command, module_ignore_errors=True)
    for line in output['stdout_lines']:
        res = line.split()
        if len(res) < 3:
            continue
        program = res[0]
        status = res[1]
        if status == "RUNNING":
            dut_command = "docker exec %s supervisorctl stop %s" % (env.gnmi_container, program)
            duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s pkill %s" % (env.gnmi_container, env.gnmi_process)
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s bash -c " % env.gnmi_container
    dut_command += "\"/usr/bin/nohup /usr/sbin/%s -logtostderr --port %s " % (env.gnmi_process, env.gnmi_port)
    dut_command += "--server_crt /etc/sonic/telemetry/gnmiserver.crt --server_key /etc/sonic/telemetry/gnmiserver.key "
    dut_command += "--config_table_name GNMI_CLIENT_CERT "
    dut_command += "--client_auth cert "
    dut_command += "--enable_crl=true "
    if subtype == 'SmartSwitch':
        dut_command += "--zmq_address=tcp://127.0.0.1:8100 "
    dut_command += "--ca_crt /etc/sonic/telemetry/gnmiCA.pem -gnmi_native_write=true -v=10 >/root/gnmi.log 2>&1 &\""
    duthost.shell(dut_command)

    # Setup gnmi client cert common name
    role = "gnmi_readwrite,gnmi_config_db_readwrite,gnmi_appl_db_readwrite,gnmi_dpu_appl_db_readwrite,gnoi_readwrite"
    add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
    add_gnmi_client_common_name(duthost, "test.client.revoked.gnmi.sonic", role)

    time.sleep(GNMI_SERVER_START_WAIT_TIME)
    dut_command = "sudo netstat -nap | grep %d" % env.gnmi_port
    output = duthost.shell(dut_command, module_ignore_errors=True)
    if duthost.facts['platform'] != 'x86_64-kvm_x86_64-r0':
        is_time_synced = wait_until(60, 3, 0, check_system_time_sync, duthost)
        assert is_time_synced, "Failed to synchronize DUT system time with NTP Server"
    if env.gnmi_process not in output['stdout']:
        # Dump tcp port status and gnmi log
        logger.info("TCP port status: " + output['stdout'])
        dump_gnmi_log(duthost)
        dump_system_status(duthost)
        pytest.fail("Failed to start gnmi server")


def check_gnmi_process(duthost):
    """
    Make sure there's no GNMI process running.
    """
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    dut_command = "docker exec %s pgrep -f %s" % (env.gnmi_container, env.gnmi_process)
    output = duthost.shell(dut_command, module_ignore_errors=True)
    return output['stdout'].strip() == ""


def check_gnmi_status(duthost):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    dut_command = "docker exec %s supervisorctl status %s" % (env.gnmi_container, env.gnmi_program)
    output = duthost.shell(dut_command, module_ignore_errors=True)
    return "RUNNING" in output['stdout']


def recover_cert_config(duthost):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    # Kill the GNMI process
    dut_command = "docker exec %s pkill %s" % (env.gnmi_container, env.gnmi_process)
    duthost.shell(dut_command, module_ignore_errors=True)
    wait_until(60, 1, 0, check_gnmi_process, duthost)
    # Recover all stopped program
    dut_command = "docker exec %s supervisorctl status" % (env.gnmi_container)
    output = duthost.shell(dut_command, module_ignore_errors=True)
    for line in output['stdout_lines']:
        res = line.split()
        if len(res) < 3:
            continue
        program = res[0]
        if program in ["gnmi-native", "telemetry"]:
            dut_command = "docker exec %s supervisorctl start %s" % (env.gnmi_container, program)
            duthost.shell(dut_command, module_ignore_errors=True)

    # Remove gnmi client cert common name
    del_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")
    del_gnmi_client_common_name(duthost, "test.client.revoked.gnmi.sonic")
    ret = wait_until(300, 3, 0, check_gnmi_status, duthost)
    if not ret:
        dut_command = "tail /var/log/gnmi.log"
        output = duthost.shell(dut_command, module_ignore_errors=True)
        logger.error("GNMI service failed to start. GNMI log: {}".format(output['stdout']))
        pytest.fail("Failed to recover GNMI client cert configuration.")


def check_ntp_sync_status(duthost):
    """
    Checks if the DUT's time is synchronized with the NTP server.
    """

    ntp_daemon = get_ntp_daemon_in_use(duthost)

    if ntp_daemon == NtpDaemon.CHRONY:
        ntp_status_cmd = "chronyc -c tracking"
    else:
        ntp_status_cmd = "ntpstat"

    ntp_status = duthost.command(ntp_status_cmd, module_ignore_errors=True)
    if (ntp_daemon == NtpDaemon.CHRONY and "Not synchronised" not in ntp_status["stdout"]) or \
            (ntp_daemon != NtpDaemon.CHRONY and "unsynchronised" not in ntp_status["stdout"]):
        logger.info("DUT %s is synchronized with NTP server.", duthost)
        return True
    else:
        logger.info("DUT %s is NOT synchronized.", duthost)
        return False


def check_system_time_sync(duthost):
    """
    Checks if the DUT's time is synchronized with the NTP server.
    If not synchronized, it attempts to restart the NTP service.
    """

    if check_ntp_sync_status(duthost) is True:
        return True

    ntp_daemon = get_ntp_daemon_in_use(duthost)

    if ntp_daemon == NtpDaemon.CHRONY:
        restart_ntp_cmd = "sudo systemctl restart chrony"
    else:
        restart_ntp_cmd = "sudo systemctl restart ntp"

    logger.info("DUT %s is NOT synchronized. Restarting NTP service...", duthost)
    duthost.command(restart_ntp_cmd)
    time.sleep(5)
    # Rechecking status after restarting NTP
    ntp_status = check_ntp_sync_status(duthost)
    if ntp_status is True:
        logger.info("DUT %s is now synchronized with NTP server.", duthost)
        return True
    else:
        logger.error("DUT %s: NTP synchronization failed. Please check manually.", duthost)
        return False


def gnmi_set(duthost, ptfhost, delete_list, update_list, replace_list, cert=None):
    """
    Send GNMI set request with GNMI client

    Args:
        duthost: fixture for duthost
        ptfhost: fixture for ptfhost
        delete_list: list for delete operations
        update_list: list for update operations
        replace_list: list for replace operations

    Returns:
    """
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    ip = duthost.mgmt_ip
    port = env.gnmi_port
    cmd = '/root/env-python3/bin/python /root/gnxi/gnmi_cli_py/py_gnmicli.py '
    cmd += '--timeout 30 '
    cmd += '-t %s -p %u ' % (ip, port)
    cmd += '-xo sonic-db '
    cmd += '-rcert /root/gnmiCA.pem '
    if cert:
        cmd += '-pkey /root/{}.key '.format(cert)
        cmd += '-cchain /root/{}.crt '.format(cert)
    else:
        cmd += '-pkey /root/gnmiclient.key '
        cmd += '-cchain /root/gnmiclient.crt '
    if len(replace_list) >= 1:
        cmd += '-m set-replace '
    elif len(update_list) >= 1:
        cmd += '-m set-update '
    elif len(delete_list) >= 1:
        cmd += '-m set-delete '
    else:
        raise Exception("SET operation must have at least one entry to modify")
    xpath = ''
    xvalue = ''
    for path in delete_list:
        path = path.replace('sonic-db:', '')
        xpath += ' ' + path
        xvalue += ' ""'
    for update in update_list:
        update = update.replace('sonic-db:', '')
        result = update.rsplit(':', 1)
        xpath += ' ' + result[0]
        xvalue += ' ' + result[1]
    for replace in replace_list:
        replace = replace.replace('sonic-db:', '')
        result = replace.rsplit(':', 1)
        xpath += ' ' + result[0]
        if '#' in result[1]:
            xvalue += ' ""'
        else:
            xvalue += ' ' + result[1]
    cmd += '--xpath ' + xpath
    cmd += ' '
    cmd += '--value ' + xvalue
    # There is a chance that the network connection lost between PTF and switch due to table entry timeout
    # It would lead to execution failure of py_gnmicli.py. The ping action would trigger arp and mac table refresh.
    if ":" in ip:
        ptfhost.shell(f"ping6 {ip} -c 3", module_ignore_errors=True)
    else:
        ptfhost.shell(f"ping {ip} -c 3", module_ignore_errors=True)

    # Health check to make sure the gnmi server is listening on port
    health_check_cmd = f"sudo ss -ltnp | grep {env.gnmi_port} | grep {env.gnmi_process}"

    wait_until(120, 1, 5,
               lambda: len(duthost.shell(health_check_cmd, module_ignore_errors=True)['stdout_lines']) > 0)

    output = ptfhost.shell(cmd, module_ignore_errors=True)
    error = "GRPC error\n"
    if error in output['stdout']:
        dump_gnmi_log(duthost)
        dump_system_status(duthost)
        result = output['stdout'].split(error, 1)
        raise Exception("GRPC error:" + result[1])
    return


def gnmi_get(duthost, ptfhost, path_list):
    """
    Send GNMI get request with GNMI client

    Args:
        duthost: fixture for duthost
        ptfhost: fixture for ptfhost
        path_list: list for get path

    Returns:
        msg_list: list for get result
    """
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    ip = duthost.mgmt_ip
    port = env.gnmi_port
    cmd = '/root/env-python3/bin/python /root/gnxi/gnmi_cli_py/py_gnmicli.py '
    cmd += '--timeout 30 '
    cmd += '-t %s -p %u ' % (ip, port)
    cmd += '-xo sonic-db '
    cmd += '-rcert /root/gnmiCA.pem '
    cmd += '-pkey /root/gnmiclient.key '
    cmd += '-cchain /root/gnmiclient.crt '
    cmd += '--encoding 4 '
    cmd += '-m get '
    cmd += '--xpath '
    for path in path_list:
        path = path.replace('sonic-db:', '')
        cmd += " " + path
    output = ptfhost.shell(cmd, module_ignore_errors=True)
    msg = output['stdout'].replace('\\', '')
    error = "GRPC error\n"
    if error in msg:
        dump_gnmi_log(duthost)
        dump_system_status(duthost)
        result = msg.split(error, 1)
        raise Exception("GRPC error:" + result[1])
    mark = 'The GetResponse is below\n' + '-'*25 + '\n'
    if mark in msg:
        result = msg.split(mark, 1)
        msg_list = result[1].split('-'*25)[0:-1]
        return [msg.strip("\n") for msg in msg_list]
    else:
        dump_gnmi_log(duthost)
        dump_system_status(duthost)
        raise Exception("error:" + msg)


# py_gnmicli does not fully support POLLING mode
# Use gnmi_cli instead
def gnmi_subscribe_polling(duthost, ptfhost, path_list, interval_ms, count):
    """
    Send GNMI subscribe request with GNMI client

    Args:
        duthost: fixture for duthost
        ptfhost: fixture for ptfhost
        path_list: list for get path
        interval_ms: interval, unit is ms
        count: update count

    Returns:
        msg: gnmi client output
    """
    if path_list is None:
        logger.error("path_list is None")
        return "", ""
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    dut_facts = duthost.dut_basic_facts()['ansible_facts']['dut_basic_facts']
    ip = f"[{duthost.mgmt_ip}]" if dut_facts.get('is_mgmt_ipv6_only', False) else duthost.mgmt_ip
    port = env.gnmi_port
    interval = interval_ms / 1000.0
    # Run gnmi_cli in gnmi container as workaround
    cmd = "docker exec %s gnmi_cli -client_types=gnmi -a %s:%s " % (env.gnmi_container, ip, port)
    cmd += "-client_crt /etc/sonic/telemetry/gnmiclient.crt "
    cmd += "-client_key /etc/sonic/telemetry/gnmiclient.key "
    cmd += "-ca_crt /etc/sonic/telemetry/gnmiCA.pem "
    cmd += "-logtostderr "
    # Use sonic-db as default origin
    cmd += '-origin=sonic-db '
    cmd += '-query_type=polling '
    cmd += '-polling_interval %us -count %u ' % (int(interval), count)
    for path in path_list:
        path = path.replace('sonic-db:', '')
        cmd += '-q %s ' % (path)
    output = duthost.shell(cmd, module_ignore_errors=True)
    return output['stdout'], output['stderr']


def gnmi_subscribe_streaming_sample(duthost, ptfhost, path_list, interval_ms, count):
    """
    Send GNMI subscribe request with GNMI client

    Args:
        duthost: fixture for duthost
        ptfhost: fixture for ptfhost
        path_list: list for get path
        interval_ms: interval, unit is ms
        count: update count

    Returns:
        msg: gnmi client output
    """
    if path_list is None:
        logger.error("path_list is None")
        return "", ""
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    ip = duthost.mgmt_ip
    port = env.gnmi_port
    cmd = '/root/env-python3/bin/python /root/gnxi/gnmi_cli_py/py_gnmicli.py '
    cmd += '--timeout 30 '
    cmd += '-t %s -p %u ' % (ip, port)
    cmd += '-xo sonic-db '
    cmd += '-rcert /root/gnmiCA.pem '
    cmd += '-pkey /root/gnmiclient.key '
    cmd += '-cchain /root/gnmiclient.crt '
    cmd += '--encoding 4 '
    cmd += '-m subscribe '
    cmd += '--subscribe_mode 0 --submode 2 --create_connections 1 '
    cmd += '--interval %u --update_count %u ' % (interval_ms, count)
    cmd += '--xpath '
    for path in path_list:
        path = path.replace('sonic-db:', '')
        cmd += " " + path
    output = ptfhost.shell(cmd, module_ignore_errors=True)
    msg = output['stdout'].replace('\\', '')
    return msg, output['stderr']


def gnmi_subscribe_streaming_onchange(duthost, ptfhost, path_list, count):
    """
    Send GNMI subscribe request with GNMI client

    Args:
        duthost: fixture for duthost
        ptfhost: fixture for ptfhost
        path_list: list for get path
        count: update count

    Returns:
        msg: gnmi client output
    """
    if path_list is None:
        logger.error("path_list is None")
        return "", ""
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    ip = duthost.mgmt_ip
    port = env.gnmi_port
    cmd = '/root/env-python3/bin/python /root/gnxi/gnmi_cli_py/py_gnmicli.py '
    cmd += '--timeout 120 '
    cmd += '-t %s -p %u ' % (ip, port)
    cmd += '-xo sonic-db '
    cmd += '-rcert /root/gnmiCA.pem '
    cmd += '-pkey /root/gnmiclient.key '
    cmd += '-cchain /root/gnmiclient.crt '
    cmd += '--encoding 4 '
    cmd += '-m subscribe '
    cmd += '--subscribe_mode 0 --submode 1 --create_connections 1 '
    cmd += '--update_count %u ' % count
    cmd += '--xpath '
    for path in path_list:
        path = path.replace('sonic-db:', '')
        cmd += " " + path
    output = ptfhost.shell(cmd, module_ignore_errors=True)
    msg = output['stdout'].replace('\\', '')
    return msg, output['stderr']


def gnoi_reboot(duthost, method, delay, message):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    dut_facts = duthost.dut_basic_facts()['ansible_facts']['dut_basic_facts']
    ip = f"[{duthost.mgmt_ip}]" if dut_facts.get('is_mgmt_ipv6_only', False) else duthost.mgmt_ip
    port = env.gnmi_port
    # Run gnoi_client in gnmi container as workaround
    cmd = "docker exec %s gnoi_client -target %s:%s " % (env.gnmi_container, ip, port)
    cmd += "-cert /etc/sonic/telemetry/gnmiclient.crt "
    cmd += "-key /etc/sonic/telemetry/gnmiclient.key "
    cmd += "-ca /etc/sonic/telemetry/gnmiCA.pem "
    cmd += "-logtostderr -rpc Reboot "
    cmd += '-jsonin "{\\\"method\\\":%d, \\\"delay\\\":%d, \\\"message\\\":\\\"%s\\\"}"' % (method, delay, message)
    output = duthost.shell(cmd, module_ignore_errors=True)
    if output['stderr']:
        logger.error(output['stderr'])
        return -1, output['stderr']
    else:
        return 0, output['stdout']


def gnoi_request(duthost, localhost, module, rpc, request_json_data):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    dut_facts = duthost.dut_basic_facts()['ansible_facts']['dut_basic_facts']
    ip = f"[{duthost.mgmt_ip}]" if dut_facts.get('is_mgmt_ipv6_only', False) else duthost.mgmt_ip
    port = env.gnmi_port
    cmd = "docker exec %s gnoi_client -target %s:%s " % (env.gnmi_container, ip, port)
    cmd += "-cert /etc/sonic/telemetry/gnmiclient.crt "
    cmd += "-key /etc/sonic/telemetry/gnmiclient.key "
    cmd += "-ca /etc/sonic/telemetry/gnmiCA.pem "
    cmd += "-logtostderr -module {} -rpc {} ".format(module, rpc)
    cmd += f'-jsonin \'{request_json_data}\''
    output = duthost.shell(cmd, module_ignore_errors=True)
    if output['stderr']:
        logger.error(output['stderr'])
        return -1, output['stderr']
    else:
        return 0, output['stdout']


def extract_gnoi_response(output):
    """
    Extract the JSON response from the gNOI client output

    Args:
        output: gNOI client output, the output is in the form of
                "Module RPC: <JSON response>", e.g. "System Time\n {"time":1735921221909617549}"

    Returns:
        json response: JSON response extracted from the output
    """
    try:
        if '\n' not in output:
            logging.error("Invalid output format: {}, expecting 'Module RPC: <JSON response>'.".format(output))
            return None
        response_line = output.split('\n')[1]
        return json.loads(response_line)
    except json.JSONDecodeError:
        logging.error("Failed to parse JSON: {}".format(response_line))
        return None


def is_reboot_inactive(duthost, localhost):
    ret, msg = gnoi_request(duthost, localhost, "System", "RebootStatus", "")
    if ret != 0:
        return False
    status = extract_gnoi_response(msg)
    return status and not status.get("active", True)


def gnoi_request_dpu(duthost, localhost, dpu_index, module, rpc, request_json_data):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)

    ip = get_dpu_ip(duthost, dpu_index)
    if ip is None:
        return -1, "Failed to get DPU IP address"

    port = get_dpu_port(duthost, dpu_index)
    if port is None:
        return -1, "Failed to get DPU gNMI port"

    cmd = "docker exec %s gnoi_client -target %s:%s " % (env.gnmi_container, ip, port)
    cmd += "-cert /etc/sonic/telemetry/gnmiclient.crt "
    cmd += "-key /etc/sonic/telemetry/gnmiclient.key "
    cmd += "-ca /etc/sonic/telemetry/gnmiCA.pem "
    cmd += "-notls "
    cmd += "-logtostderr -module {} -rpc {} ".format(module, rpc)
    cmd += f'-jsonin \'{request_json_data}\''
    output = duthost.shell(cmd, module_ignore_errors=True)
    if output['stderr']:
        logging.error(output['stderr'])
        return -1, output['stderr']
    else:
        return 0, output['stdout']
