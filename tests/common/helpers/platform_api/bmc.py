""" This module provides interface to interact with the BMC of the DUT via platform API remotely """
import ast
import json
import logging

logger = logging.getLogger(__name__)

# Values of the 'os' field of bmc_os.json in the HwSKU directory. They select the
# protocol the switch host uses to reach the BMC: Redfish for OpenBMC, Redis for SONiC BMC.
BMC_OS_SONIC = 'sonic'
BMC_OS_OPENBMC = 'openbmc'


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


def get_bmc_os(duthost):
    """Return the BMC OS the switch host is configured to talk to.

    Reads the 'show platform bmc os' CLI, which reports the 'os' field of
    bmc_os.json in the HwSKU directory, defaulting to 'sonic' when the file is
    missing or invalid. Images that predate this feature have no such command;
    there Redfish was the only supported path, so 'openbmc' is reported instead.

    Note that is_bmc_exists() cannot be used to tell the two apart: the switch
    host exposes a BMC component in both cases.
    """
    res = duthost.shell('show platform bmc os', module_ignore_errors=True)
    if res['rc'] != 0:
        logger.info(f'"show platform bmc os" is not available on {duthost.hostname}, assuming {BMC_OS_OPENBMC}')
        return BMC_OS_OPENBMC
    return res['stdout'].strip().lower()


def is_sonic_bmc_os(duthost):
    """Return True when the switch host reaches the BMC over Redis instead of Redfish."""
    return get_bmc_os(duthost) == BMC_OS_SONIC


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
