import re
import logging
from tests.common.platform.interface_utils import get_port_map

DICT_WRITABLE_BYTE_FOR_PAGE_0 = {
    "cmis":  33,
    "sff8472": 110,
    "sff8636": 86}


def parse_output(output_lines):
    """
    @summary: For parsing command output. The output lines should have format 'key value'.
    @param output_lines: Command output lines
    @return: Returns result in a dictionary
    """
    res = {}
    for line in output_lines:
        fields = line.split()
        if len(fields) < 2:
            continue
        res[fields[0]] = line.replace(fields[0], '').strip()
    return res


def parse_eeprom(output_lines):
    """
    @summary: Parse the SFP eeprom information from command output
    @param output_lines: Command output lines
    @return: Returns result in a dictionary
    """
    res = {}
    for line in output_lines:
        if re.match(r"^Ethernet\d+: .*", line):
            fields = line.split(":")
            res[fields[0]] = fields[1].strip()
    return res


def get_dev_conn(duthost, conn_graph_facts, asic_index):
    dev_conn = conn_graph_facts.get("device_conn", {}).get(duthost.hostname, {})

    # Get the interface pertaining to that asic
    portmap = get_port_map(duthost, asic_index)
    logging.info("Got portmap {}".format(portmap))

    if asic_index is not None:
        # Check if the interfaces of this AISC is present in conn_graph_facts
        dev_conn = {k: v for k, v in list(portmap.items()) if k in conn_graph_facts["device_conn"][duthost.hostname]}
        logging.info("ASIC {} interface_list {}".format(asic_index, dev_conn))

    return portmap, dev_conn


def validate_transceiver_lpmode(sfp_lpmode, port):
    lpmode = sfp_lpmode.get(port)
    if lpmode is None:
        logging.error(f"Interface {port} does not present in the show command")  # noqa E713
        return False

    if lpmode not in ["Off", "On"]:
        logging.error("Invalid low-power mode {} for port {}".format(lpmode, port))
        return False

    return True


def get_sfp_type(duthost, port):
    """
    Get sfp type by reading the first byte of o page in eeprom.
    """

    sfp_type = None
    try:
        first_byte_in_cable_eeprom = read_eeprom_by_page_and_byte(duthost, port, "cmis", offset=0, page=0)
    except Exception as err:
        logging.info(f"get sfp type error: {err}")
        first_byte_in_cable_eeprom = read_eeprom_by_page_and_byte(duthost, port, "sff8472", offset=0, page=0)
    finally:
        first_byte_in_cable_eeprom = f"0x{first_byte_in_cable_eeprom}"
    logging.info(f"first_byte_in_cable_eeprom is {first_byte_in_cable_eeprom}")

    cmis_ids = ["0x18", "0x19", "0x1e"]
    sff8636_ids = ["0x11", "0x0D"]
    sff8472_ids = ["0x03"]
    if first_byte_in_cable_eeprom in cmis_ids:
        sfp_type = "cmis"
    elif first_byte_in_cable_eeprom in sff8636_ids:
        sfp_type = "sff8636"
    elif first_byte_in_cable_eeprom in sff8472_ids:
        sfp_type = "sff8472"
    logging.info(f"sfp_type is {sfp_type}")
    return sfp_type


def read_eeprom_by_page_and_byte(duthost, port, sfp_type, page, offset, size=1, no_format=True):
    cmd_get_sfp_eeprom = f"sudo sfputil read-eeprom -p {port} -n {page} -o {offset} -s {size}"

    if sfp_type == "sff8472":
        cmd_get_sfp_eeprom = f"{cmd_get_sfp_eeprom} --wire-addr a0h"
    if no_format:
        cmd_get_sfp_eeprom = f"{cmd_get_sfp_eeprom} --no-format "

    return duthost.shell(cmd_get_sfp_eeprom)['stdout']


def write_eeprom_by_page_and_byte(
        duthost, port, sfp_type, data, page, offset, is_verify=False, module_ignore_errors=False):
    cmd_write_sfp_eeprom = f"sfputil write-eeprom -p {port} -n {page} -o {offset} -d {data}"

    if sfp_type == "sff8472":
        cmd_write_sfp_eeprom = f"{cmd_write_sfp_eeprom} --wire-addr a0h"

    if is_verify:
        cmd_write_sfp_eeprom = f"{cmd_write_sfp_eeprom} --verify"

    return duthost.shell(cmd_write_sfp_eeprom, module_ignore_errors=module_ignore_errors)['stdout']
