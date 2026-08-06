""" This module provides interface to interact with the BMC of the DUT via platform API remotely """
import ast
import json
import logging

logger = logging.getLogger(__name__)


def bmc_pmon_api(conn, name, args=None):
    if args is None:
        args = []
    conn.request('POST', '/platform/chassis/bmc/{}'.format(name), json.dumps({'args': args}))
    resp = conn.getresponse()
    res = json.loads(resp.read())['res']
    logger.info('Executing chassis API: "{}", arguments: "{}", result: "{}"'.format(name, args, res))
    return res


def bmc_host_api(duthost, api_name, *args):
    bmc_instance = 'sudo python -c "import sonic_platform; \
                                    bmc = sonic_platform.platform.Platform().get_chassis().get_bmc(); \
                                    print(bmc.{})"'
    res = duthost.shell(bmc_instance.format(api_name + str(args)))['stdout']
    try:
        return ast.literal_eval(res)
    except (ValueError, SyntaxError):
        return res.strip()


def is_bmc_exists(duthost):
    all_components = "sudo python -c 'import sonic_platform; \
                                      com = sonic_platform.platform.Platform().get_chassis().get_all_components(); \
                                      print(com)'"
    components = duthost.shell(all_components)['stdout']
    if 'BMC' in components:
        return True
    else:
        return False


def get_name(conn):
    return bmc_pmon_api(conn, 'get_name')


def get_presence(conn):
    return bmc_pmon_api(conn, 'get_presence')


def get_model(duthost):
    return bmc_host_api(duthost, 'get_model')


def get_serial(duthost):
    return bmc_host_api(duthost, 'get_serial')


def get_revision(conn):
    return bmc_pmon_api(conn, 'get_revision')


def get_status(conn):
    return bmc_pmon_api(conn, 'get_status')


def is_replaceable(conn):
    return bmc_pmon_api(conn, 'is_replaceable')


def get_eeprom(duthost):
    return bmc_host_api(duthost, 'get_eeprom')


def get_version(duthost):
    return bmc_host_api(duthost, 'get_version')


def reset_root_password(duthost):
    return bmc_host_api(duthost, 'reset_root_password')


def trigger_bmc_debug_log_dump(duthost):
    return bmc_host_api(duthost, 'trigger_bmc_debug_log_dump')


def get_bmc_debug_log_dump(duthost, task_id, filename, path):
    return bmc_host_api(duthost, 'get_bmc_debug_log_dump', task_id, filename, path)


def update_firmware(duthost, fw_image):
    return bmc_host_api(duthost, 'update_firmware', fw_image)


def request_bmc_reset(duthost):
    return bmc_host_api(duthost, 'request_bmc_reset')
