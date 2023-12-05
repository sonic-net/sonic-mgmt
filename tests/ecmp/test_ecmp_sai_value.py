import pytest
import re
import logging
from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.processes_utils import wait_critical_processes


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.asic('broadcom'),
    pytest.mark.topology('t1'),
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

offset_cmd = 'bcmcmd  "dump RTAG7_PORT_BASED_HASH 0 392 OFFSET_ECMP"'
# offset_0xa_cmd = 'bcmcmd  "dump RTAG7_PORT_BASED_HASH 0 392 OFFSET_ECMP" | grep OFFSET_ECMP=0xa | wc -l'


def parse_hash_seed(output):
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


@pytest.mark.parametrize("parameter", ["", "restart_syncd", "reload"])
def test_ecmp_hash_seed_value(duthosts, enum_rand_one_per_hwsku_frontend_hostname, parameter):
    """
    Check ecmp HASH_SEED
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic = duthost.facts["asic_type"]

    if (asic != "broadcom"):
        pytest.skip("Unsupported asic type: {}".format(asic))
        return
    if parameter == "":
        for cmd in seed_cmd:
            output = duthost.command(cmd, module_ignore_errors=True)["stdout_lines"][2].strip()
            hash_seed = parse_hash_seed(output)
            pytest_assert(hash_seed == '0xa', "HASH_SEED is not set to 0xa")
    elif parameter == "restart_syncd":
        duthost.command("docker restart syncd", module_ignore_errors=True)
        logging.info("Wait until all critical services are fully started")
        wait_critical_processes(duthost)
        for cmd in seed_cmd:
            output = duthost.command(cmd, module_ignore_errors=True)["stdout_lines"][2].strip()
            hash_seed = parse_hash_seed(output)
            pytest_assert(hash_seed == '0xa', "HASH_SEED is not set to 0xa")
    elif parameter == "reload":
        config_reload(duthost, safe_reload=True, check_intf_up_ports=True)
        for cmd in seed_cmd:
            output = duthost.command(cmd, module_ignore_errors=True)["stdout_lines"][2].strip()
            hash_seed = parse_hash_seed(output)
            pytest_assert(hash_seed == '0xa', "HASH_SEED is not set to 0xa")


@pytest.mark.parametrize("parameter", ["", "restart_syncd", "reload"])
def test_ecmp_offset_value(duthosts, enum_rand_one_per_hwsku_frontend_hostname, parameter):
    """
    Check ecmp HASH_OFFSET
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic = duthost.facts["asic_type"]

    if (asic != "broadcom"):
        pytest.skip("Unsupported asic type: {}".format(asic))
        return
    if parameter == "":
        output = duthost.shell(offset_cmd, module_ignore_errors=True)['stdout']
        offset_list = parse_ecmp_offset(output)
        count_0xa = offset_list.count('0xa')
        pytest_assert(count_0xa >= 67, "the count of 0xa OFFSET_ECMP is not correct.")
    elif parameter == "restart_syncd":
        duthost.command("docker restart syncd", module_ignore_errors=True)
        logging.info("Wait until all critical services are fully started")
        wait_critical_processes(duthost)
        output = duthost.shell(offset_cmd, module_ignore_errors=True)['stdout']
        offset_list = parse_ecmp_offset(output)
        count_0xa = offset_list.count('0xa')
        pytest_assert(count_0xa >= 67, "the count of 0xa OFFSET_ECMP is not correct.")
    elif parameter == "reload":
        output = duthost.shell(offset_cmd, module_ignore_errors=True)['stdout']
        offset_list = parse_ecmp_offset(output)
        count_0xa = offset_list.count('0xa')
        pytest_assert(count_0xa >= 67, "the count of 0xa OFFSET_ECMP is not correct.")
