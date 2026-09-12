import logging
import json
import ipaddress
from tests.common.utilities import wait_until
from tests.common.platform.device_utils import get_dpu_ip, get_dpu_port
from tests.common.helpers.gnmi_utils import GNMIEnvironment, dump_gnmi_log, dump_system_status
from tests.common.helpers.gnmi_utils import (   # noqa: F401
    apply_cert_config,
    recover_cert_config,
    check_gnmi_process,
    check_gnmi_status,
    check_ntp_sync_status,
    check_system_time_sync,
    GNMI_SERVER_START_WAIT_TIME,
)
from tests.common.helpers.ntp_helper import NtpDaemon, get_ntp_daemon_in_use   # noqa: F401


logger = logging.getLogger(__name__)
GNMI_CONTAINER_NAME = ''
GNMI_PROGRAM_NAME = ''
GNMI_PORT = 0


def is_mgmt_vrf_enabled(duthost):
    res = duthost.shell('sudo sonic-db-cli CONFIG_DB HGET "MGMT_VRF_CONFIG|vrf_global" "mgmtVrfEnabled"')["stdout"]
    return res == "true"


def gnmi_set(duthost, ptfhost, delete_list, update_list, replace_list, cert=None, ip=None):
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
    ip = ip or duthost.mgmt_ip
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

    stdout = output.get("stdout") or ""
    stderr = output.get("stderr") or ""
    rc = output.get("rc", 1)
    combined = f"{stdout}\n{stderr}"

    if rc != 0 or "GRPC error" in combined or "rpc error" in combined:
        dump_gnmi_log(duthost)
        dump_system_status(duthost)
        raise Exception(f"py_gnmicli failed rc={rc}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}")  # noqa: E231


def gnmi_get(duthost, ptfhost, path_list, ip=None, target=None, origin="sonic-db", raw=False):
    """
    Send GNMI get request with GNMI client

    Args:
        duthost: fixture for duthost
        ptfhost: fixture for ptfhost
        path_list: list for get path
        target: gNMI target (-xt), e.g. "OTHERS" for non-DB paths; omitted when None
        origin: gNMI origin (-xo); defaults to "sonic-db", pass None to omit
        raw: when True, return the raw client stdout instead of the parsed result
            list (used by callers that parse the GetResponse themselves)

    Returns:
        msg_list: list for get result (or the raw stdout string when raw=True)
    """
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    ip = ip or duthost.mgmt_ip
    port = env.gnmi_port
    cmd = '/root/env-python3/bin/python /root/gnxi/gnmi_cli_py/py_gnmicli.py '
    cmd += '--timeout 30 '
    cmd += '-t %s -p %u ' % (ip, port)
    if origin:
        cmd += '-xo %s ' % origin
    if target:
        cmd += '-xt %s ' % target
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
    if raw:
        return msg
    mark = 'The GetResponse is below\n' + '-'*25 + '\n'
    if mark in msg:
        result = msg.split(mark, 1)
        msg_list = result[1].split('-'*25)[0:-1]
        return [msg.strip("\n") for msg in msg_list]
    else:
        dump_gnmi_log(duthost)
        dump_system_status(duthost)
        raise Exception("error:" + msg)


def _bracket_ipv6(ip):
    """Wrap an IPv6 literal in brackets for use in a host:port target.

    gnmi_cli/gnoi_client take the server address as ``-a <host>:<port>``.
    A bare IPv6 address contains colons that collide with the ``:<port>``
    separator, so IPv6 literals must be written as ``[<ipv6>]:<port>``.
    IPv4 addresses, hostnames and already-bracketed IPv6 values are returned
    unchanged.

    Args:
        ip: server address (IPv4/IPv6 literal, hostname, or ``[ipv6]``).

    Returns:
        The address with IPv6 literals wrapped in brackets.
    """
    if not ip or ip.startswith('['):
        return ip
    try:
        if ipaddress.ip_address(ip).version == 6:
            return f"[{ip}]"
    except ValueError:
        # Not an IP literal (e.g. a hostname); leave it untouched.
        pass
    return ip


# py_gnmicli does not fully support POLLING mode
# Use gnmi_cli instead
def gnmi_subscribe_polling(duthost, ptfhost, path_list, interval_ms, count, ip=None, vrf_name=None):
    """
    Send GNMI subscribe request with GNMI client

    Args:
        duthost: fixture for duthost
        ptfhost: fixture for ptfhost
        path_list: list for get path
        interval_ms: interval, unit is ms
        count: update count
        ip: server IP to connect to (defaults to duthost.mgmt_ip)
        vrf_name: when set, run gnmi_cli on the DUT inside the given VRF
            (using `ip vrf exec`) instead of inside the gnmi container.

    Returns:
        msg: gnmi client output
    """
    if path_list is None:
        logger.error("path_list is None")
        return "", ""
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    if ip is None:
        ip = duthost.mgmt_ip
    # gnmi_cli expects the target as -a <host>:<port>. IPv6 literals must be
    # wrapped in brackets ([<ipv6>]:<port>) so the address colons are not
    # confused with the host:port separator. Normalize here so bracketing is
    # applied whether `ip` was defaulted from duthost.mgmt_ip or passed in
    # explicitly (e.g. a bare IPv6 dut_ip from a VRF config).
    ip = _bracket_ipv6(ip)
    port = env.gnmi_port
    interval = interval_ms / 1000.0
    # For a non-default VRF the gnmi container does not have `ip vrf exec`
    # privileges, so run gnmi_cli on the DUT host in the target VRF instead.
    if vrf_name and vrf_name != "default":
        cmd = "sudo ip vrf exec %s /tmp/gnmi_cli -client_types=gnmi -a %s:%s " % (vrf_name, ip, port)
    else:
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


def gnmi_subscribe_polling_py(duthost, ptfhost, path_list, target, polling_interval, update_count,
                              max_sync_count, timeout, namespace=None, ip=None):
    """
    Send a POLL-mode GNMI subscribe request via py_gnmicli.

    Unlike gnmi_subscribe_polling (gnmi_cli), this uses py_gnmicli so callers can
    bound the run with max_sync_count / timeout and inspect the raw response
    stream (sync_response, json_ietf_val, delete markers).

    The DB is given via the target (-xt <target>[/<namespace>]) with table-relative
    xpaths, not via a sonic-db origin with the DB in the path.

    Returns the ptfhost.shell result dict (rc / stdout / stderr).
    """
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    ip = ip or duthost.mgmt_ip
    port = env.gnmi_port
    ns = "/{}".format(namespace) if namespace else ""
    cmd = '/root/env-python3/bin/python /root/gnxi/gnmi_cli_py/py_gnmicli.py '
    cmd += '-t %s -p %u ' % (ip, port)
    cmd += '-rcert /root/gnmiCA.pem '
    cmd += '-pkey /root/gnmiclient.key '
    cmd += '-cchain /root/gnmiclient.crt '
    cmd += '-m subscribe '
    # Quote each xpath so an escaped slash in a route prefix (e.g. 0.0.0.0\/0)
    # survives the shell and reaches py_gnmicli as a single path element.
    cmd += '-x %s ' % " ".join('"{}"'.format(p) for p in path_list)
    cmd += '-xt %s%s ' % (target, ns)
    cmd += '--subscribe_mode 2 '  # POLL
    cmd += '--polling_interval %u ' % polling_interval
    cmd += '--update_count %d ' % update_count
    cmd += '--max_sync_count %d ' % max_sync_count
    cmd += '--timeout %u' % timeout
    return ptfhost.shell(cmd, module_ignore_errors=True)


def gnmi_subscribe_streaming_sample(duthost, ptfhost, path_list, interval_ms, count, origin=None, target=None,
                                    ip=None):
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
    ip = ip or duthost.mgmt_ip
    port = env.gnmi_port
    cmd = '/root/env-python3/bin/python /root/gnxi/gnmi_cli_py/py_gnmicli.py '
    cmd += '--timeout 30 '
    cmd += '-t %s -p %u ' % (ip, port)
    if origin:
        cmd += f'-xo {origin} '
    if target:
        cmd += f'-xt {target} '
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


def gnmi_subscribe_streaming_onchange(duthost, ptfhost, path_list, count, ip=None):
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
    ip = ip or duthost.mgmt_ip
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


def gnmi_subscribe_stream_connections(duthost, ptfhost, path_list, target, create_connections,
                                      update_count, namespace=None, ip=None):
    """
    STREAM subscribe via py_gnmicli opening create_connections channels, used to
    exercise the gnmi server's channel handling.

    Returns the ptfhost.shell result dict (rc / stdout / stderr).
    """
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    ip = ip or duthost.mgmt_ip
    port = env.gnmi_port
    ns = "/{}".format(namespace) if namespace else ""
    cmd = '/root/env-python3/bin/python /root/gnxi/gnmi_cli_py/py_gnmicli.py '
    cmd += '-t %s -p %u ' % (ip, port)
    cmd += '-rcert /root/gnmiCA.pem '
    cmd += '-pkey /root/gnmiclient.key '
    cmd += '-cchain /root/gnmiclient.crt '
    cmd += '-m subscribe '
    cmd += '-x %s ' % " ".join('"{}"'.format(p) for p in path_list)
    cmd += '-xt %s%s ' % (target, ns)
    cmd += '--timeout 30 '
    cmd += '--encoding 4 '
    cmd += '--subscribe_mode 0 --submode 2 '  # STREAM / SAMPLE
    cmd += '--create_connections %d --update_count %d' % (create_connections, update_count)
    return ptfhost.shell(cmd, module_ignore_errors=True)


def archive_gnmi_certs(duthost):
    """Move the gnmi server/CA certs aside so the server has no certs."""
    path = "/etc/sonic/telemetry/"
    archive_dir = path + "old_certs"
    duthost.shell("mkdir -p {}".format(archive_dir))
    for filename in duthost.shell("ls {}".format(path))['stdout_lines']:
        if filename.startswith("gnmi") and filename.endswith((".crt", ".key", ".pem")):
            duthost.shell("mv {} {}".format(path + filename, archive_dir))


def unarchive_gnmi_certs(duthost):
    """Restore the gnmi certs previously moved aside by archive_gnmi_certs."""
    path = "/etc/sonic/telemetry/"
    archive_dir = path + "old_certs"
    for filename in duthost.shell("ls {}".format(archive_dir))['stdout_lines']:
        duthost.shell("mv {}/{} {}".format(archive_dir, filename, path))
    duthost.shell("rm -rf {}".format(archive_dir))


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
    cmd += "-insecure "
    cmd += "-logtostderr -module {} -rpc {} ".format(module, rpc)
    cmd += f'-jsonin \'{request_json_data}\''
    output = duthost.shell(cmd, module_ignore_errors=True)
    if output['stderr']:
        logging.error(output['stderr'])
        return -1, output['stderr']
    else:
        return 0, output['stdout']


def get_namespace(duthost, iface="Ethernet0"):
    """
    Return per-ASIC namespace name if multi asic and localhost otherwise
    """
    if duthost.is_multi_asic:
        return duthost.get_port_asic_instance(iface).namespace
    return "localhost"
