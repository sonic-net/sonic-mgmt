import logging
import time
import proto_utils

from tests.common.helpers.gnmi_utils import GNMIEnvironment

logger = logging.getLogger(__name__)


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
    cmd += '-m set-update '
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
    output = ptfhost.shell(cmd, module_ignore_errors=True)
    error = "GRPC error\n"
    if error in output['stdout']:
        result = output['stdout'].split(error, 1)
        raise Exception("GRPC error:" + result[1])
    return


def apply_messages(
    localhost,
    duthost,
    ptfhost,
    messages,
    dpu_index,
    setup_ha_config,
    gnmi_key,
    filename,
    set_db=True,
    wait_after_apply=5,
    max_updates_in_single_cmd=1024,
):
    env = GNMIEnvironment(duthost)
    update_list = []
    delete_list = []
    ptfhost.copy(src=filename, dest='/root')

    if set_db:
        if proto_utils.ENABLE_PROTO:
            path = f"/APPL_DB/dpu{dpu_index}/{gnmi_key}:/root/{filename}"
        else:
            path = f"/APPL_DB/dpu{dpu_index}/{gnmi_key}:/root/{filename}"
        update_list.append(path)
    else:
        path = f"/APPL_DB/dpu{dpu_index}/{gnmi_key}"
        delete_list.append(path)

    write_gnmi_files(localhost, duthost, ptfhost, env, delete_list, update_list, max_updates_in_single_cmd)
    time.sleep(wait_after_apply)


def write_gnmi_files(localhost, duthost, ptfhost, env, delete_list, update_list, max_updates_in_single_cmd):

    if delete_list:
        gnmi_set(duthost, ptfhost, delete_list, [], [])
    if update_list:
        gnmi_set(duthost, ptfhost, [], update_list, [])
