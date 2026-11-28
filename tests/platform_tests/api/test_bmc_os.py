"""Test cases for selecting the communication protocol between the switch host and the BMC.

The switch host reaches the BMC over Redfish when the BMC runs OpenBMC, and over Redis
when it runs SONiC BMC. The BMC OS is defined per HwSKU by the 'os' field of bmc_os.json
in the HwSKU directory: device_info.get_bmc_os() reads it, and 'show platform bmc os'
displays it. A missing file or an invalid value falls back to 'sonic'.
"""
import json
import logging
import shlex

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.platform_api import bmc
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('any')
]

SHOW_BMC_OS_CMD = 'show platform bmc os'
GET_BMC_OS_CMD = 'sudo python3 -c "from sonic_py_common import device_info; print(device_info.get_bmc_os())"'
BMC_OS_FILE_BACKUP = '/tmp/bmc_os.json.backup'
DEFAULT_BMC_OS = bmc.BMC_OS_SONIC

# Content written to bmc_os.json (None removes the file) and the BMC OS expected from it.
BMC_OS_FILE_CASES = [
    pytest.param('{"os": "sonic"}', bmc.BMC_OS_SONIC, id='valid_sonic'),
    pytest.param('{"os": "openbmc"}', bmc.BMC_OS_OPENBMC, id='valid_openbmc'),
    pytest.param(None, DEFAULT_BMC_OS, id='missing'),
    pytest.param('', DEFAULT_BMC_OS, id='malformed_empty'),
    pytest.param('{"os": "openbmc"', DEFAULT_BMC_OS, id='malformed_truncated'),
    pytest.param('["openbmc"]', DEFAULT_BMC_OS, id='malformed_not_object'),
    pytest.param('{"os": "foo"}', DEFAULT_BMC_OS, id='invalid_unknown'),
    pytest.param('{"os": "OpenBMC"}', DEFAULT_BMC_OS, id='invalid_case'),
    pytest.param('{"os": ""}', DEFAULT_BMC_OS, id='invalid_empty'),
    pytest.param('{}', DEFAULT_BMC_OS, id='invalid_no_os'),
]

STATE_DB_ID = 6
EEPROM_INFO_TABLE = 'EEPROM_INFO'
# TLV code that backs each field the switch host reports for the BMC EEPROM. This mirrors
# the mapping the host applies when it reads the BMC EEPROM over Redis; 'PowerState' is
# deliberately absent because it is derived from the BMC reachability, not from the EEPROM.
BMC_EEPROM_TLV_MAP = {
    'Model': '0x21',
    'PartNumber': '0x22',
    'SerialNumber': '0x23',
    'Revision': '0x27',
    'Manufacturer': '0x2b',
}
# EEPROM fields that 'show platform bmc eeprom' displays, as 'N/A' when get_eeprom() lacks them.
CLI_EEPROM_FIELDS = ('Manufacturer', 'Model', 'PartNumber', 'SerialNumber')


@pytest.fixture(scope="module")
def switch_host(duthosts, enum_rand_one_per_hwsku_hostname):
    """Return the switch host under test, skipping where the BMC OS feature does not apply.

    What these cases need is a DUT that is not itself a BMC but has one attached, which is
    the pair of checks below: is_bmc() reads the device's router_type, while is_bmc_exists()
    asks whether that device exposes a BMC component.
    """
    dut = duthosts[enum_rand_one_per_hwsku_hostname]

    if dut.is_bmc():
        pytest.skip("These cases drive the switch host side of the link, not the BMC itself")

    if not bmc.is_bmc_exists(dut):
        pytest.skip(f"BMC is not present on {dut.hostname}")

    res = dut.shell(SHOW_BMC_OS_CMD, module_ignore_errors=True)
    if res['rc'] != 0:
        pytest.skip(f"'{SHOW_BMC_OS_CMD}' is not supported by the image running on {dut.hostname}")

    return dut


@pytest.fixture(scope="module")
def bmc_addr(switch_host):
    """Return the BMC address the switch host uses on the internal host-to-BMC link."""
    platform = switch_host.facts['platform']
    bmc_config = switch_host.shell(f'cat /usr/share/sonic/device/{platform}/bmc.json')['stdout']
    return json.loads(bmc_config)['bmc_addr']


@pytest.fixture(scope="class")
def bmc_os_file(switch_host):
    """Return the path of bmc_os.json, and put the file back the way it was found afterwards.

    The original file is copied aside with its owner and mode before any case touches it.
    When the HwSKU has no bmc_os.json, the file is removed again instead.

    The scope is the class of the cases that rewrite the file, not the module: the file is
    restored as soon as the last of them ends, so the cases after that class run with the
    BMC OS the setup is configured with.
    """
    platform = switch_host.facts['platform']
    hwsku = switch_host.facts['hwsku']
    path = f'/usr/share/sonic/device/{platform}/{hwsku}/bmc_os.json'
    original_bmc_os = _show_bmc_os(switch_host)
    existed = switch_host.stat(path=path)['stat']['exists']
    logger.info(f'{path} {"exists" if existed else "does not exist"}, BMC OS is {original_bmc_os}')
    if existed:
        switch_host.shell(f'sudo cp -p {path} {BMC_OS_FILE_BACKUP}')

    yield path

    if existed:
        switch_host.shell(f'sudo mv {BMC_OS_FILE_BACKUP} {path}')
    else:
        switch_host.shell(f'sudo rm -f {path}')
    restored_bmc_os = _show_bmc_os(switch_host)
    pytest_assert(restored_bmc_os == original_bmc_os,
                  f"BMC OS is '{restored_bmc_os}' after restoring {path}, expected '{original_bmc_os}'")


def _show_bmc_os(duthost):
    """Return the BMC OS reported by the CLI."""
    return duthost.shell(SHOW_BMC_OS_CMD)['stdout'].strip()


def _write_bmc_os_file(duthost, path, content):
    """Write content to bmc_os.json, or remove the file when content is None."""
    if content is None:
        duthost.shell(f'sudo rm -f {path}')
    else:
        duthost.shell(f"printf '%s' {shlex.quote(content)} | sudo tee {path} > /dev/null")


def _check_bmc_os(duthost, expected_bmc_os):
    """Check that device_info.get_bmc_os() and the CLI both report the expected BMC OS."""
    api_bmc_os = duthost.shell(GET_BMC_OS_CMD)['stdout'].strip()
    pytest_assert(api_bmc_os == expected_bmc_os,
                  f"device_info.get_bmc_os() returned '{api_bmc_os}', expected '{expected_bmc_os}'")
    cli_bmc_os = _show_bmc_os(duthost)
    pytest_assert(cli_bmc_os == expected_bmc_os,
                  f"'{SHOW_BMC_OS_CMD}' reported '{cli_bmc_os}', expected '{expected_bmc_os}'")


class TestBmcOsFile:
    """Cases that rewrite bmc_os.json, grouped so that bmc_os_file restores it right after them."""

    @pytest.mark.parametrize('content, expected_bmc_os', BMC_OS_FILE_CASES)
    def test_bmc_os_file(self, switch_host, bmc_os_file, content, expected_bmc_os):
        """Verify the BMC OS follows bmc_os.json in the HwSKU directory.

        The file is first set to the other BMC OS, so the expected value can only come from the
        content under test. Nothing is restarted between writing the file and reading it back.
        """
        other_bmc_os = bmc.BMC_OS_OPENBMC if expected_bmc_os == bmc.BMC_OS_SONIC else bmc.BMC_OS_SONIC
        with allure.step(f"Set bmc_os.json to '{other_bmc_os}' first"):
            _write_bmc_os_file(switch_host, bmc_os_file, json.dumps({'os': other_bmc_os}))
            _check_bmc_os(switch_host, other_bmc_os)

        with allure.step(f"Write {content!r} to bmc_os.json and expect '{expected_bmc_os}'"):
            _write_bmc_os_file(switch_host, bmc_os_file, content)
            _check_bmc_os(switch_host, expected_bmc_os)


def test_bmc_eeprom_matches_bmc_redis(switch_host, bmc_addr):
    """Verify the BMC EEPROM the switch host reports is the one held on the BMC.

    The existing test_get_eeprom only proves the host returns a well-formed dictionary that
    agrees with its own CLI; it cannot tell whether those values came from the BMC at all,
    nor whether each TLV was mapped to the right field name. This case reads the source
    EEPROM_INFO table on the BMC over Redis and compares it field by field.
    """
    if not bmc.is_sonic_bmc_os(switch_host):
        pytest.skip(f"The switch host reads the BMC EEPROM over Redis only when the BMC OS is '{bmc.BMC_OS_SONIC}'")

    def _redis_hget(key, field):
        cmd = f'redis-cli -h {bmc_addr} -n {STATE_DB_ID} HGET "{EEPROM_INFO_TABLE}|{key}" {field}'
        return switch_host.shell(cmd)['stdout'].strip()

    with allure.step("Step 1: The BMC STATE_DB is reachable and its EEPROM table is initialized"):
        res = switch_host.shell(f'redis-cli -h {bmc_addr} -n {STATE_DB_ID} PING', module_ignore_errors=True)
        pytest_assert(res['stdout'].strip() == 'PONG',
                      f"The BMC STATE_DB at {bmc_addr} did not answer PING: {res['stdout'] + res['stderr']}")
        pytest_assert(_redis_hget('State', 'Initialized') == '1',
                      f"{EEPROM_INFO_TABLE}|State reports the BMC EEPROM is not initialized yet")

    with allure.step("Step 2: Read the EEPROM_INFO table on the BMC"):
        bmc_eeprom = {}
        for field, tlv_code in BMC_EEPROM_TLV_MAP.items():
            value = _redis_hget(tlv_code, 'Value')
            if value:
                bmc_eeprom[field] = value
        logger.info(f'BMC EEPROM read over Redis from {bmc_addr}: {bmc_eeprom}')
        pytest_assert(bmc_eeprom, f"No EEPROM TLV of {list(BMC_EEPROM_TLV_MAP)} was found on the BMC")

    with allure.step("Step 3: Read the BMC EEPROM through the platform API and the CLI"):
        host_eeprom = bmc.get_eeprom(switch_host)
        pytest_assert(isinstance(host_eeprom, dict) and host_eeprom,
                      f"The switch host reported no BMC EEPROM: {host_eeprom}")
        cli_output = switch_host.command('sudo show platform bmc eeprom')['stdout']

    with allure.step("Step 4: get_eeprom() matches the BMC for every EEPROM field"):
        # A field whose TLV is absent on the BMC must be absent from get_eeprom() as well.
        for field in BMC_EEPROM_TLV_MAP:
            pytest_assert(host_eeprom.get(field) == bmc_eeprom.get(field),
                          f"BMC EEPROM field '{field}' is {host_eeprom.get(field)!r} on the switch host "
                          f"but {bmc_eeprom.get(field)!r} on the BMC")

    with allure.step("Step 5: 'show platform bmc eeprom' matches get_eeprom() for the fields it displays"):
        for field in CLI_EEPROM_FIELDS:
            expected_line = f"{field}: {host_eeprom.get(field, 'N/A')}"
            pytest_assert(expected_line in cli_output,
                          f"'show platform bmc eeprom' does not show '{expected_line}': {cli_output}")
