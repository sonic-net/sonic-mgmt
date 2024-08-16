import pytest
import re
import logging
from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.utilities import get_host_visible_vars
from tests.common.reboot import reboot, REBOOT_TYPE_COLD, REBOOT_TYPE_WARM
from tests.common.utilities import wait_until


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.asic('broadcom'),
    pytest.mark.topology('t0', 't1'),
    pytest.mark.disable_loganalyzer
]

seed_cmd = [
    'bcmcmd "getreg RTAG7_HASH_SEED_A"',
    'bcmcmd "getreg RTAG7_HASH_SEED_A_PIPE0"',
    'bcmcmd "getreg RTAG7_HASH_SEED_A_PIPE1"',
    'bcmcmd "getreg RTAG7_HASH_SEED_A_PIPE2"',
    'bcmcmd "getreg RTAG7_HASH_SEED_A_PIPE3"',
    'bcmcmd "getreg RTAG7_HASH_SEED_B"',
    'bcmcmd "getreg RTAG7_HASH_SEED_B_PIPE0"',
    'bcmcmd "getreg RTAG7_HASH_SEED_B_PIPE1"',
    'bcmcmd "getreg RTAG7_HASH_SEED_B_PIPE2"',
    'bcmcmd "getreg RTAG7_HASH_SEED_B_PIPE3"'
]

seed_cmd_td2 = [
    'bcmcmd "getreg RTAG7_HASH_SEED_A"',
    'bcmcmd "getreg RTAG7_HASH_SEED_B"'
]

seed_cmd_td3 = [
    'bcmcmd "getreg RTAG7_HASH_SEED_A"',
    'bcmcmd "getreg RTAG7_HASH_SEED_A_PIPE0"',
    'bcmcmd "getreg RTAG7_HASH_SEED_B"',
    'bcmcmd "getreg RTAG7_HASH_SEED_B_PIPE0"',
]

offset_cmd = 'bcmcmd  "dump RTAG7_PORT_BASED_HASH 0 392 OFFSET_ECMP"'


@pytest.fixture
def enable_container_autorestart(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    # Enable autorestart for all features
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    feature_list, _ = duthost.get_feature_status()
    container_autorestart_states = duthost.get_container_autorestart_states()
    for feature, status in list(feature_list.items()):
        # Enable container autorestart only if the feature is enabled and container autorestart is disabled.
        if status == 'enabled' and container_autorestart_states[feature] == 'disabled':
            duthost.shell("sudo config feature autorestart {} enabled".format(feature))

    yield
    for feature, status in list(feature_list.items()):
        # Disable container autorestart back if it was initially disabled.
        if status == 'enabled' and container_autorestart_states[feature] == 'disabled':
            duthost.shell("sudo config feature autorestart {} disabled".format(feature))


def parse_hash_seed(output, asic_name):
    logger.info("Checking seed config: {}".format(output))
    # RTAG7_HASH_SEED_A.ipipe0[1][0x16001500]=0: <HASH_SEED_A=0>
    # Regular expression pattern to find both HASH_SEED_A and HASH_SEED_B
    pattern = r'HASH_SEED_[A|B]=(0x?[0-9a-fA-F]?)'

    matches = re.findall(pattern, output)
    if len(matches) == 1:
        logger.info("HASH_SEED value: {}".format(matches[0]))
        numeric_value = matches[0]
    else:
        pytest.fail("Matched number of HASH_SEED is not correct.")
    return numeric_value


def parse_ecmp_offset(outputs):
    # Regular expression pattern to extract OFFSET_ECMP values (hexadecimal)
    pattern = r'OFFSET_ECMP=(0x?[0-9a-fA-F]?)'

    # Extracted values
    extracted_values = []

    for line in outputs.splitlines():
        line = line.strip()
        matches = re.findall(pattern, line)
        if len(matches) == 1:
            value = matches[0]
            extracted_values.append(value)
        elif len(matches) == 0:
            continue
        else:
            pytest.fail("Matched number of OFFSET_ECMP is not correct.")
    return extracted_values


def check_syncd_is_running(duthost):
    """
    Check if syncd container is running
    """
    output = duthost.shell("docker ps | grep syncd")["stdout"]
    if "syncd" in output:
        return True
    else:
        return False


def check_config_bcm_file(duthost, topo_type):
    """
    Read the config bcm file and check if sai_hash_seed_config_hash_offset_enable is set
    """
    ls_command = "docker exec syncd cat /etc/sai.d/sai.profile | grep SAI_INIT_CONFIG_FILE"
    ls_output = duthost.shell(ls_command, module_ignore_errors=True)['stdout']
    # Check if the file exists
    if ls_output:
        file_name = ls_output.split("=")[-1]
        logging.info("Config bcm file found:{}".format(file_name))
        cat_command = "docker exec syncd cat {} | grep sai_hash_seed_config_hash_offset_enable".format(file_name)
        cat_output = duthost.shell(cat_command, module_ignore_errors=True)['stdout']
        if cat_output:
            value = cat_output.split("=")[-1]
            logging.info("sai_hash_seed_config_hash_offset_enable={}".format(value))
        else:
            logging.info("sai_hash_seed_config_hash_offset_enable not found in the file.")
        # with code change https://github.com/sonic-net/sonic-buildimage/pull/18912,
        # the sai_hash_seed_config_hash_offset_enable is not set in config.bcm,
        # it's set by swss config on 202311 and later image
        if "20230531" in duthost.os_version:
            if topo_type == "t0":
                pytest_assert(not cat_output, "sai_hash_seed_config_hash_offset_enable should not set for T0")
            if topo_type == "t1":
                pytest_assert(cat_output and value == "1", "sai_hash_seed_config_hash_offset_enable is not set to 1")
    else:
        pytest.fail("Config bcm file not found.")


def check_hash_seed_value(duthost, asic_name, topo_type):
    """
    Check the value of HASH_SEED
    t0: HASH_SEED is set to 0
    t1: HASH_SEED is set to 0xa
    """
    pytest_assert(wait_until(300, 20, 0, check_syncd_is_running, duthost), "syncd is not running!")
    check_config_bcm_file(duthost, topo_type)
    if asic_name == "td2":
        seed_cmd_input = seed_cmd_td2
    elif asic_name == "td3":
        seed_cmd_input = seed_cmd_td3
    else:
        seed_cmd_input = seed_cmd
    for cmd in seed_cmd_input:
        output = duthost.command(cmd, module_ignore_errors=True)["stdout_lines"][2].strip()
        hash_seed = parse_hash_seed(output, asic_name)
        if topo_type == "t1":
            pytest_assert(hash_seed == '0xa', "HASH_SEED is not set to 0xa")
        elif topo_type == "t0":
            pytest_assert(hash_seed == '0', "HASH_SEED is not set to 0")


def check_ecmp_offset_value(duthost, asic_name, topo_type, hwsku):
    """
    Check the value of OFFSET_ECMP
    TH/TH2: the count of 0xa is 67
    TD2: the count of 0xa is 33
    """
    pytest_assert(wait_until(300, 20, 0, check_syncd_is_running, duthost), "syncd is not running!")
    output = duthost.shell(offset_cmd, module_ignore_errors=True)['stdout']
    offset_list = parse_ecmp_offset(output)
    if topo_type == "t0":
        offset_count = offset_list.count('0')
        if asic_name == "td3":
            # For TD3, RTAG7_PORT_BASED_HASH.ipipe0[1]: <OFFSET_ECMP=2,>
            pytest_assert(offset_count == 391, "the count of 0 OFFSET_ECMP is not correct. \
                          Expected {}, but got {}.".format(391, offset_count))
        elif asic_name == "td2":
            # For TD2, 7050qx, the total number of ports are 362
            pytest_assert(offset_count == 362, "the count of 0 OFFSET_ECMP is not correct. \
                          Expected {}, but got {}.".format(362, offset_count))
        else:
            pytest_assert(offset_count == 392, "the count of 0 OFFSET_ECMP is not correct. \
                          Expected {}, but got {}.".format(392, offset_count))
    elif topo_type == "t1":
        offset_count = offset_list.count('0xa')
        if hwsku in ["Arista-7060CX-32S-C32", "Arista-7050QX32S-Q32", "Arista-7050-QX-32S"]:
            pytest_assert(offset_count >= 33, "the count of 0xa OFFSET_ECMP is not correct. \
                          Expected >= 33, but got {}.".format(offset_count))
        else:
            pytest_assert(offset_count >= 67, "the count of 0xa OFFSET_ECMP is not correct. \
                          Expected >= 67, but got {}.".format(offset_count))
    else:
        pytest.fail("Unsupported topology type: {}".format(topo_type))


@pytest.mark.parametrize("parameter", ["common", "restart_syncd", "reload", "reboot", "warm-reboot"])
def test_ecmp_hash_seed_value(localhost, duthosts, tbinfo, enum_rand_one_per_hwsku_frontend_hostname, parameter,
                              enable_container_autorestart):
    """
    Check ecmp HASH_SEED
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic = duthost.facts["asic_type"]
    topo_type = tbinfo['topo']['type']
    hostvars = get_host_visible_vars(duthost.host.options['inventory'], duthost.hostname)
    hwsku = duthost.facts['hwsku']
    supported_platforms = ['broadcom_td2_hwskus', 'broadcom_td3_hwskus', 'broadcom_th_hwskus',
                           'broadcom_th2_hwskus', 'broadcom_th3_hwskus']
    asic_name = None
    for platform in supported_platforms:
        supported_skus = hostvars.get(platform, [])
        if hwsku in supported_skus:
            asic_name = platform.split('_')[1]
        else:
            continue
    if asic_name is None:
        pytest.skip("Unsupported platform: {}".format(hwsku))

    if asic != "broadcom":
        pytest.skip("Unsupported asic type: {}".format(asic))

    if parameter == "common":
        check_hash_seed_value(duthost, asic_name, topo_type)
    elif parameter == "restart_syncd":
        duthost.command("sudo systemctl restart syncd", module_ignore_errors=True)
        logging.info("Wait until all critical services are fully started")
        wait_critical_processes(duthost)
        check_hash_seed_value(duthost, asic_name, topo_type)
    elif parameter == "reload":
        logging.info("Run config reload on DUT")
        config_reload(duthost, safe_reload=True, check_intf_up_ports=True)
        check_hash_seed_value(duthost, asic_name, topo_type)
    elif parameter == "reboot":
        logging.info("Run cold reboot on DUT")
        reboot(duthost, localhost, reboot_type=REBOOT_TYPE_COLD, reboot_helper=None,
               reboot_kwargs=None, safe_reboot=True)
        check_hash_seed_value(duthost, asic_name, topo_type)
    elif parameter == "warm-reboot" and topo_type == "t0":
        logging.info("Run warm reboot on DUT")
        reboot(duthost, localhost, reboot_type=REBOOT_TYPE_WARM, reboot_helper=None,
               reboot_kwargs=None, safe_reboot=True)
        check_hash_seed_value(duthost, asic_name, topo_type)


@pytest.mark.parametrize("parameter", ["common", "restart_syncd", "reload", "reboot", "warm-reboot"])
def test_ecmp_offset_value(localhost, duthosts, tbinfo, enum_rand_one_per_hwsku_frontend_hostname, parameter,
                           enable_container_autorestart):
    """
    Check ecmp HASH_OFFSET
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic = duthost.facts["asic_type"]
    topo_type = tbinfo['topo']['type']
    hostvars = get_host_visible_vars(duthost.host.options['inventory'], duthost.hostname)
    hwsku = duthost.facts['hwsku']
    supported_platforms = ['broadcom_td2_hwskus', 'broadcom_td3_hwskus', 'broadcom_th_hwskus',
                           'broadcom_th2_hwskus', 'broadcom_th3_hwskus']
    asic_name = None
    for platform in supported_platforms:
        supported_skus = hostvars.get(platform, [])
        if hwsku in supported_skus:
            asic_name = platform.split('_')[1]
        else:
            continue
    if asic_name is None:
        pytest.skip("Unsupported platform: {}".format(hwsku))

    if (asic != "broadcom"):
        pytest.skip("Unsupported asic type: {}".format(asic))

    if parameter == "common":
        check_ecmp_offset_value(duthost, asic_name, topo_type, hwsku)
    elif parameter == "restart_syncd":
        duthost.command("sudo systemctl restart syncd", module_ignore_errors=True)
        logging.info("Wait until all critical services are fully started")
        wait_critical_processes(duthost)
        check_ecmp_offset_value(duthost, asic_name, topo_type, hwsku)
    elif parameter == "reload":
        logging.info("Run config reload on DUT")
        config_reload(duthost, safe_reload=True, check_intf_up_ports=True)
        check_ecmp_offset_value(duthost, asic_name, topo_type, hwsku)
    elif parameter == "reboot":
        logging.info("Run cold reboot on DUT")
        reboot(duthost, localhost, reboot_type=REBOOT_TYPE_COLD, reboot_helper=None,
               reboot_kwargs=None, safe_reboot=True)
        check_ecmp_offset_value(duthost, asic_name, topo_type, hwsku)
    elif parameter == "warm-reboot" and topo_type == "t0":
        logging.info("Run warm reboot on DUT")
        reboot(duthost, localhost, reboot_type=REBOOT_TYPE_WARM, reboot_helper=None,
               reboot_kwargs=None, safe_reboot=True)
        check_ecmp_offset_value(duthost, asic_name, topo_type, hwsku)
