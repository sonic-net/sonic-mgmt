import os
import re
import logging
import functools
from tests.platform_tests.mellanox.interface_utils import get_module_to_interfaces_map, get_interfaces_physical_path
from tests.platform_tests.mellanox import software_control_constants as sc_const


logger = logging.getLogger()

CMD_SFPUTIL_SHOW_PRESENCE = "sudo sfputil show presence"


def get_platform_sfputil_ports(duthost):
    """
    @summary: Ports reported Present by ``sfputil show presence``.
    """
    return [
        entry["port"]
        for entry in duthost.show_and_parse(CMD_SFPUTIL_SHOW_PRESENCE)
    ]


def check_sc_sai_attribute_value(duthost):
    """
    @summary: This method is for checking if Software Control SAI attribute set to 1 in sai.profile
    @param: duthosts: duthosts fixture
    """
    dut_hwsku = duthost.facts['hwsku']
    dut_platfrom = duthost.facts['platform']
    sai_profile_path = os.path.join(
        sc_const.PLATFORM_FOLDER_PATH, dut_platfrom, dut_hwsku, sc_const.SAI_PROFILE_FILE_NAME)
    cmd = duthost.shell('cat {}'.format(sai_profile_path))
    if sc_const.SC_SAI_ATTRIBUTE_NAME in cmd['stdout']:
        sc_enabled_in_sai = re.search(f"{sc_const.SC_SAI_ATTRIBUTE_NAME}=(\\d?)", cmd['stdout']).group(1)
        if sc_enabled_in_sai == '1':
            return True
    return False


def parse_output_to_dict(output, keys_list):
    """
    @summary: Parse the output based at keys list provided
    @param output: command output
    @param keys_list: list of keys to be parsed
    @return: returns result in a dictionary
    """
    result_dict = {}
    for key in keys_list:
        match = re.search(f"{key}(\\s+)?:\\n? (.*)", output)  # noqa: E231
        if match:
            result_dict.update({key.replace('\\', ''): match.group(2).strip()})
        else:
            result_dict.update({key.replace('\\', ''): None})
    return result_dict


def parse_sc_eeprom(output_lines):
    """
    @summary: Parse the SFP eeprom information from command output
    @param output_lines: command output lines
    @return: returns result in a dictionary
    """
    return parse_output_to_dict(output_lines, sc_const.EEPROM_CLI_KEYS)


def parse_all_interfaces_eeprom_output_to_dict(output):
    """
    @summary: Parse the SFP eeprom information from command output
    @param output: command output
    @return: returns result in a dictionary
    """
    port_info = {}
    pattern = r'(Ethernet\d+):(.*?)(?=Ethernet\d+:|$)'
    matches = re.finditer(pattern, output, re.DOTALL)
    for match in matches:
        port_name = match.group(1)
        port_data = match.group(2).strip()
        port_info[port_name] = port_data
    return port_info


def parse_transceivers_info_from_redis(transceiver_query_output, cmd_type):
    result = {}
    sections = transceiver_query_output.split(f'=== {cmd_type}|')
    for section in sections:
        if not section.strip():
            continue
        split_section = section.strip().split('===')
        intf = split_section[0].strip()
        data = split_section[1].splitlines()
        result[intf] = data[1:]
    return result


@functools.lru_cache(maxsize=2)
def get_all_transceivers_info_from_redis(duthost, asichost, cmd_type):
    """
    @summary: Get all interfaces transceiver info from redis database
    @param duthost: duthost fixture
    @param asichost: asichost fixture
    @return: Returns result in a dictionary
    """
    redis_keys_cmd = sc_const.CMD_REDIS_TRANSCEIVERS[cmd_type]
    cmd = (
        'for port in $({}); do echo "=== $port ==="; redis-cli -n 6 hgetall "$port"; done'.format(redis_keys_cmd)
    )
    docker_cmd = asichost.get_docker_cmd(cmd, "database")
    all_interfaces_xcvr_info = parse_transceivers_info_from_redis(duthost.shell(docker_cmd)["stdout"], cmd_type)
    return all_interfaces_xcvr_info


def transform_redis_transceiver_data(duthost, cmd_type, asic_index, interfaces):
    """
    @summary: Parse the SFP eeprom information from redis database
    @param duthost: duthost fixture
    @param cmd_type: command type to be executed
    @param asic_index: asic index
    @param interfaces: interfaces list
    @return: Returns result in a dictionary
    """
    result_dict = {}
    asichost = duthost.asic_instance(asic_index)
    logging.info("Check detailed transceiver information of each connected port")
    all_interfaces_xcvr_info = get_all_transceivers_info_from_redis(duthost, asichost, cmd_type)
    for intf in interfaces:
        redis_all_data_dict = {}
        intf_xcvr_info = all_interfaces_xcvr_info[intf]
        split_by_2 = [intf_xcvr_info[i * 2:(i + 1) * 2] for i in range((len(intf_xcvr_info) + 2 - 1) // 2)]
        for item in split_by_2:
            redis_all_data_dict.update({item[0]: item[1].rstrip()})
        # Clean up the placeholder (\x00 or \u0000) in vendor_date field
        cleanup_placeholder(redis_all_data_dict, "vendor_date")
        cleanup_placeholder(redis_all_data_dict, "vendor_rev")
        result_dict.update({intf: redis_all_data_dict})
    return result_dict


def compare_data_from_cli_and_redis(cli_data, redis_data, port, key_mapping):
    for cli_eeprom_key, redis_key in key_mapping.items():
        # For SFF cables some fields having multi line output, taking first and check if present in redis db output
        cli_value = cli_data[cli_eeprom_key.replace("\\", "")]
        cli_value = cli_value.rstrip('\x00')
        redis_value = redis_data[port][redis_key].strip()
        assert cli_value == redis_value if ":" not in cli_value else cli_value.split(":")[-1].strip() in redis_value, \
            f"Data from cli param {cli_eeprom_key} does not match data from redis"


def get_sff_cables(duthost, cmd_type, asic_index, port_list):
    sff_ports = []
    for port in port_list:
        redis_output = transform_redis_transceiver_data(duthost, cmd_type, asic_index, [port])
        if 'QSFP28' in redis_output[port][sc_const.SC_REDIS_SFP_IDENTIFIER_KEY]:
            sff_ports.append(port)
    return sff_ports


def parse_sc_transceiver_status(output_lines):
    """
    @summary: Parse the  output
    @param output_lines: Command output lines
    @return: Returns result in a dictionary
    """
    return parse_output_to_dict(output_lines, sc_const.TRANCEIVER_CLI_KEYS)


@functools.lru_cache(maxsize=1)
def get_mst_path(duthost):
    return duthost.shell(sc_const.ASIC_DETECT_GET_DEVICE_PATH_CMD)['stdout'].strip()


def _mlxlink_plain(text):
    """
    @summary: Remove mlxlink color codes so field values can be compared
    @param text: mlxlink stdout
    @return: stdout without color codes
    """
    return sc_const._MLXLINK_ANSI_RE.sub('', text or '')


def get_mlxlink_tool_errors(output):
    """
    @summary: Return the mlxlink Errors-section body, or an empty string
    @param output: mlxlink stdout
    @return: Errors-section text, or an empty string when that section is missing
    """
    match = sc_const.MLXLINK_TOOL_ERRORS_RE.search(_mlxlink_plain(output))
    return match.group(1).strip() if match else ''


def assert_mlxlink_no_tool_errors(output, port, cmd):
    """
    @summary: Assert that mlxlink stdout has an empty Errors section
    @param output: mlxlink stdout
    @param port: DUT interface name
    @param cmd: mlxlink command label used in the assertion message
    """
    tool_errors = get_mlxlink_tool_errors(output)
    assert not tool_errors, f"mlxlink {cmd} reported errors for port {port}: {tool_errors}"


def is_mlxlink_sc_cable_dump_no_cable(output):
    """
    @summary: True when the Errors section says no cable is plugged
    @param output: mlxlink --cable --dump stdout
    @return: True when 'No plugged cable detected' is in the Errors section
    """
    errors = get_mlxlink_tool_errors(output)
    return sc_const.MLXLINK_SC_CABLE_DUMP_NO_CABLE in errors


def is_mlxlink_sc_cable_dump_expected_fail(output, module_present=False):
    """
    @summary: True when SC blocked mlxlink --cable --dump
    @param output: mlxlink --cable --dump stdout
    @param module_present: When True, 'No plugged cable detected' also counts as the expected failure
    @return: True for a PDDR, register-not-supported, or EEPROM-dump error
    """
    errors = get_mlxlink_tool_errors(output)
    if any(pattern in errors for pattern in sc_const.MLXLINK_SC_CABLE_DUMP_ACCESS_BLOCK_ERRORS):
        return True
    return bool(module_present) and sc_const.MLXLINK_SC_CABLE_DUMP_NO_CABLE in errors


def is_mlxlink_sc_module_state_expected_fail(output):
    """
    @summary: True when mlxlink --module_state failed as the SC coverage table requires
    @param output: mlxlink --module_state stdout
    @return: True for a PMAOS or register-not-supported error
    """
    errors = get_mlxlink_tool_errors(output)
    return any(pattern in errors for pattern in sc_const.MLXLINK_SC_MODULE_STATE_EXPECTED_ERRORS)


def get_mlxlink_operational_fec(output):
    """
    @summary: Return the Operational Info FEC value from mlxlink stdout
    @param output: mlxlink stdout
    @return: FEC value, or an empty string when it is missing
    """
    match = sc_const.MLXLINK_OPERATIONAL_FEC_RE.search(_mlxlink_plain(output))
    return match.group(1).strip() if match else ''


def is_mlxlink_fec_histogram_unsupported(output):
    """
    @summary: True when the active FEC cannot provide an RX FEC histogram, for example No FEC
    @param output: mlxlink --rx_fec_histogram stdout
    @return: True for No FEC. RS-FEC and FC-FEC still return False when the histogram error appears
    """
    fec = get_mlxlink_operational_fec(output).lower()
    if fec == sc_const.MLXLINK_FEC_NO_FEC:
        return True
    errors = get_mlxlink_tool_errors(output)
    if sc_const.MLXLINK_NO_HISTOGRAM_FOR_FEC not in errors:
        return False
    # Fallback when FEC is No FEC (or unparsed) but mlxlink already said no histogram.
    # RS-FEC / FC-FEC must still fail on this Errors section.
    return sc_const.MLXLINK_FEC_RS_FEC not in fec and sc_const.MLXLINK_FEC_FC_FEC not in fec


def parse_mlxlink_rx_fec_histogram(output):
    """
    @summary: Parse the Histogram of FEC Errors section from mlxlink stdout
    @param output: mlxlink --rx_fec_histogram stdout
    @return: Dictionary of bins, or None when the section, header, or bin rows are missing
    """
    if not output or sc_const.MLXLINK_RX_FEC_HISTOGRAM_SECTION not in output:
        return None
    if not sc_const.MLXLINK_RX_FEC_HISTOGRAM_HEADER_RE.search(output):
        return None
    bins = {}
    for bin_match in sc_const.MLXLINK_RX_FEC_HISTOGRAM_BIN_RE.finditer(output):
        bin_id = int(bin_match.group(1))
        bins[bin_id] = {
            "range": bin_match.group(2),
            "occurrences": int(bin_match.group(3)),
        }
    if not bins:
        return None
    return {"bins": bins}


def parse_mlxlink_serdes_tx(output):
    """
    @summary: Parse mlxlink --show_serdes_tx stdout. Parameter names are read from the output
    @param output: mlxlink --show_serdes_tx stdout
    @return: Dictionary of parameter names and lanes, or None when the section is missing
    """
    if not output or sc_const.MLXLINK_SERDES_TX_SECTION not in output:
        return None
    param_match = sc_const.MLXLINK_SERDES_TX_PARAMETERS_RE.search(output)
    if not param_match:
        return None
    parameters = [name.strip() for name in param_match.group(1).split(',') if name.strip()]
    lanes = {}
    for lane_match in sc_const.MLXLINK_SERDES_TX_LANE_RE.finditer(output):
        lane_id = int(lane_match.group(1))
        values = [value.strip() for value in lane_match.group(2).split(',') if value.strip()]
        lanes[lane_id] = values
    return {"parameters": parameters, "lanes": lanes}


def parse_mlxlink_interfaces_output(output, interfaces_physical_paths):
    '''
    @summary: Parse the mlxlink output from run_mlxlink_all_interfaces into a dictionary.
    @param output: mlxlink output per interface
    @param interfaces_physical_paths: dictionary of interfaces and their physical paths
    @return: Returns result in a dictionary
    '''
    reverse_interfaces_physical_paths = {v: k for k, v in interfaces_physical_paths.items()}
    result = {}
    for interface_output in output:
        interface_output_splitted = interface_output.split("===")
        interface_path = interface_output_splitted[0].strip()
        interface_name = reverse_interfaces_physical_paths[interface_path]
        result[interface_name] = _mlxlink_plain(interface_output_splitted[1])
    return result


def run_mlxlink_all_interfaces(duthost, interfaces, mlxlink_flags, ignore_errors=False):
    """
    @summary: Run mlxlink for all interfaces with the given flags and return the output
    @param duthost: duthost fixture
    @param interfaces: List of DUT interfaces
    @param mlxlink_flags: mlxlink command flags (e.g., '--show_serdes_tx', '-c')
    @param ignore_errors: If True, do not raise when mlxlink returns rc!=0 (caller inspects stdout).
                          Used by --rx_fec_histogram, --cable --dump, and --module_state.
    @return: Dictionary with mlxlink output per interface
    """
    interfaces_physical_paths = get_interfaces_physical_path(duthost, interfaces)
    mst_path = get_mst_path(duthost)
    interfaces_physical_paths_as_str = ' '.join(interfaces_physical_paths.values())
    cmd = (
        'for iface in {}; do echo "=== Interface: $iface ==="; mlxlink -d {} -p "$iface" {}; done'.format(
            interfaces_physical_paths_as_str, mst_path, mlxlink_flags)
    )
    result = duthost.shell(cmd, module_ignore_errors=ignore_errors)
    if ignore_errors and result.get('rc'):
        logger.warning(
            "mlxlink '%s' exited with code %s. The test continues and checks the command output.",
            mlxlink_flags, result['rc'])
    output = result['stdout']
    output_per_interface = output.split("=== Interface: ")
    output_per_interface = output_per_interface[1:]
    return parse_mlxlink_interfaces_output(output_per_interface, interfaces_physical_paths)


def get_mlxlink_ber_output_all_interfaces(duthost, interfaces):
    """
    @summary: Get raw mlxlink -c output for all interfaces
    @param duthost: duthost fixture
    @param interfaces: List of DUT interfaces
    @return: Dictionary with mlxlink output per interface
    """
    return run_mlxlink_all_interfaces(duthost, interfaces, '-c')


def get_mlxlink_ber_all_interfaces(duthost, interfaces):
    """
    @summary: Parse the BER output from mlxlink -c. The Errors section must be empty
    @param duthost: duthost fixture
    @param interfaces: List of DUT interfaces
    @return: BER values dictionary
    """
    mlxlink_output_all_interfaces = get_mlxlink_ber_output_all_interfaces(duthost, interfaces)
    result = {}
    for interface, output in mlxlink_output_all_interfaces.items():
        assert_mlxlink_no_tool_errors(output, interface, "-c")
        result[interface] = parse_output_to_dict(output, sc_const.BER_KEY_MAP)
    return result


def get_mlxlink_serdes_tx_all_interfaces(duthost, interfaces):
    """
    @summary: Get mlxlink SERDES TX parameters for all interfaces
    @param duthost: duthost fixture
    @param interfaces: List of DUT interfaces
    @return: Dictionary with mlxlink output per interface
    """
    return run_mlxlink_all_interfaces(duthost, interfaces, '--show_serdes_tx')


def get_mlxlink_rx_fec_histogram_all_interfaces(duthost, interfaces):
    """
    @summary: Get mlxlink RX FEC histogram for all interfaces. A non-zero rc is ignored
    @param duthost: duthost fixture
    @param interfaces: List of DUT interfaces
    @return: Dictionary with mlxlink output per interface
    """
    return run_mlxlink_all_interfaces(
        duthost, interfaces, '--rx_fec_histogram --show_histogram', ignore_errors=True)


def get_mlxlink_cable_dump_all_interfaces(duthost, interfaces):
    """
    @summary: Get mlxlink cable EEPROM dump for all interfaces. A non-zero rc is ignored
    @param duthost: duthost fixture
    @param interfaces: List of DUT interfaces
    @return: Dictionary with mlxlink output per interface
    """
    return run_mlxlink_all_interfaces(
        duthost, interfaces, '--cable --dump', ignore_errors=True)


def get_mlxlink_counters_all_interfaces(duthost, interfaces):
    """
    @summary: Get mlxlink port counters for all interfaces
    @param duthost: duthost fixture
    @param interfaces: List of DUT interfaces
    @return: Dictionary with mlxlink output per interface
    """
    return run_mlxlink_all_interfaces(duthost, interfaces, '--show_counters')


def set_mlxlink_module_state_all_interfaces(duthost, interfaces, module_state):
    """
    @summary: Set mlxlink module state for all interfaces. A non-zero rc is ignored
    @param duthost: duthost fixture
    @param interfaces: List of DUT interfaces
    @param module_state: DN (plug out) or UP (plug in)
    @return: Dictionary with command output per interface
    """
    return run_mlxlink_all_interfaces(
        duthost, interfaces, f'--module_state {module_state}', ignore_errors=True)


def is_cpo_switch(duthost):
    """
    @summary: True when the platform ships cpo.json
    @param duthost: duthost fixture
    @return: True if cpo.json exists under the platform directory
    """
    cpo_json_path = os.path.join(sc_const.PLATFORM_FOLDER_PATH, duthost.facts["platform"], "cpo.json")
    return duthost.stat(path=cpo_json_path)["stat"]["exists"]


def get_ports_supporting_sc(duthost, only_ports_index_up=False):
    """
    @summary: This method is for get DUT ports supporting Software Control
    @param: duthost: duthost fixture
    @param: enum_frontend_asic_index: enum_frontend_asic_index fixture
    @return: list of Software Control ports supported
    """
    module_to_interfaces_map = get_module_to_interfaces_map(duthost, only_ports_index_up=only_ports_index_up)
    cmd = 'for i in /sys/module/sx_core/asic0/module*/control; do echo -n "$(basename $(dirname $i)): "; cat $i; done'
    res = duthost.shell(cmd)['stdout'].splitlines()
    ports_with_sc_support = []
    for module_sc_status in res:
        module_number, sc_status = re.findall(r'module(\d+): (\d+)', module_sc_status)[0]
        if int(sc_status) == sc_const.SC_ENABLED:
            ports_with_sc_support.extend(module_to_interfaces_map.get(int(module_number), []))
    return ports_with_sc_support


def is_spc1(duthost):
    """
    @summary: This method checking if platform is SPC1
    @param: duthost: duthost fixture
    @return: True if platform is SPC1 else false
    """
    return True if "sn2" in duthost.facts["platform"] else False


def is_spc2(duthost):
    """
    @summary: This method checking if platform is SPC2
    @param: duthost: duthost fixture
    @return: True if platform is SPC2 else false
    """
    return True if "sn3" in duthost.facts["platform"] else False


def sc_supported(duthost):
    """
    @summary: This method checking if platform supports Software Control feature
    @param: duthost: duthost fixture
    @return: True if platform supports Software Control feature else false
    """
    return True if not is_spc1(duthost) and not is_spc2(duthost) else False


def sc_ms_sku(duthost):
    """
    @summary: This method checking if HWSKU is Microsoft
    @param: duthost: duthost fixture
    @return: True if HWSKU is in platform generation supporting Software Control feature
    """
    return any(item in duthost.facts['hwsku'] for item in sc_const.PLATFORM_GENERATION)


def cleanup_placeholder(parsed_eeprom: dict, key: str):
    """
    Clean up the placeholder (\x00 or \u0000) in Vendor Date and Vendor Rev Code field

    Args:
        parsed_eeprom: dict, Dictionary containing parsed EEPROM data
        key: str, Key name for vendor date or vendor rev in the EEPROM dictionary
    """
    if key in parsed_eeprom:
        logger.info(f"The current vendor date is [{parsed_eeprom[key]}]")
        parsed_eeprom[key] = parsed_eeprom[key].split()[0].rstrip('\x00').rstrip('\u0000')
        logger.info(f"The vendor date after update is [{parsed_eeprom[key]}]")
