"""
Helper script for checking status of transceivers

This script contains re-usable functions for checking status of transceivers.
"""
import logging
import re


def parse_transceiver_info(output_lines):
    """
    @summary: Parse the list of transceiver from DB table TRANSCEIVER_INFO content
    @param output_lines: DB table TRANSCEIVER_INFO content output by 'redis' command
    @return: Return parsed transceivers in a list
    """
    result = []
    p = re.compile(r"TRANSCEIVER_INFO\|(Ethernet\d+)")
    for line in output_lines:
        m = p.match(line)
        assert m, "Unexpected line %s" % line
        result.append(m.group(1))
    return result


def parse_transceiver_dom_sensor(output_lines):
    """
    @summary: Parse the list of transceiver from DB table TRANSCEIVER_DOM_SENSOR content
    @param output_lines: DB table TRANSCEIVER_DOM_SENSOR content output by 'redis' command
    @return: Return parsed transceivers in a list
    """
    result = []
    p = re.compile(r"TRANSCEIVER_DOM_SENSOR\|(Ethernet\d+)")
    for line in output_lines:
        m = p.match(line)
        assert m, "Unexpected line %s" % line
        result.append(m.group(1))
    return result


def all_transceivers_detected(dut, asic_index, interfaces, xcvr_skip_list):
    """
    Check if transceiver information of all the specified interfaces have been detected.
    """
    cmd = r"redis-cli --raw -n 6 keys TRANSCEIVER_INFO\*"
    asichost = dut.asic_instance(asic_index)
    docker_cmd = asichost.get_docker_cmd(cmd, "database")
    db_output = dut.command(docker_cmd)["stdout_lines"]
    not_detected_interfaces = [intf for intf in interfaces if (intf not in xcvr_skip_list[dut.hostname] and
                               "TRANSCEIVER_INFO|{}".format(intf) not in db_output)]
    if len(not_detected_interfaces) > 0:
        logging.info("Interfaces not detected: %s" % str(not_detected_interfaces))
        return False
    return True


def check_transceiver_basic(dut, asic_index, interfaces, xcvr_skip_list):
    """
    @summary: Check whether all the specified interface are in TRANSCEIVER_INFO redis DB.
    @param dut: The AnsibleHost object of DUT. For interacting with DUT.
    @param interfaces: List of interfaces that need to be checked.
    """
    logging.info("Check whether transceiver information of all ports are in redis")
    cmd = "redis-cli -n 6 keys TRANSCEIVER_INFO*"
    asichost = dut.asic_instance(asic_index)
    docker_cmd = asichost.get_docker_cmd(cmd, "database")
    xcvr_info = dut.command(docker_cmd)
    parsed_xcvr_info = parse_transceiver_info(xcvr_info["stdout_lines"])
    for intf in interfaces:
        if intf not in xcvr_skip_list[dut.hostname]:
            assert intf in parsed_xcvr_info, "TRANSCEIVER INFO of %s is not found in DB" % intf


def check_transceiver_details(dut, asic_index, interfaces, xcvr_skip_list):
    """
    @summary: Check the detailed TRANSCEIVER_INFO content of all the specified interfaces.
    @param dut: The AnsibleHost object of DUT. For interacting with DUT.
    @param interfaces: List of interfaces that need to be checked.
    """
    asichost = dut.asic_instance(asic_index)
    logging.info("Check detailed transceiver information of each connected port")
    # NOTE: No more releases to be added here. Platform should use SFP-refactor.
    # 'hardware_rev' is ONLY applicable to QSFP-DD/OSFP modules
    if dut.sonic_release in ["201811", "201911", "202012", "202106", "202111"]:
        expected_fields = ["type", "hardware_rev", "serial", "manufacturer", "model"]
    else:
        expected_fields = ["type", "vendor_rev", "serial", "manufacturer", "model"]

    for intf in interfaces:
        if intf not in xcvr_skip_list[dut.hostname]:
            cmd = 'redis-cli -n 6 hgetall "TRANSCEIVER_INFO|%s"' % intf
            docker_cmd = asichost.get_docker_cmd(cmd, "database")
            port_xcvr_info = dut.command(docker_cmd)
            for field in expected_fields:
                assert port_xcvr_info["stdout"].find(field) >= 0, \
                    "Expected field %s is not found in %s while checking %s" % (field, port_xcvr_info["stdout"], intf)


def check_transceiver_dom_sensor_basic(dut, asic_index, interfaces, xcvr_skip_list, port_list_with_flat_memory):
    """
    @summary: Check whether all the specified interface are in TRANSCEIVER_DOM_SENSOR redis DB.
    @param dut: The AnsibleHost object of DUT. For interacting with DUT.
    @param interfaces: List of interfaces that need to be checked.
    """
    logging.info("Check whether TRANSCEIVER_DOM_SENSOR of all ports in redis")
    cmd = "redis-cli -n 6 keys TRANSCEIVER_DOM_SENSOR*"
    asichost = dut.asic_instance(asic_index)
    docker_cmd = asichost.get_docker_cmd(cmd, "database")
    xcvr_dom_sensor = dut.command(docker_cmd)
    parsed_xcvr_dom_sensor = parse_transceiver_dom_sensor(xcvr_dom_sensor["stdout_lines"])
    for intf in interfaces:
        if intf not in xcvr_skip_list[dut.hostname] + port_list_with_flat_memory[dut.hostname]:
            assert intf in parsed_xcvr_dom_sensor, "TRANSCEIVER_DOM_SENSOR of %s is not found in DB" % intf


def check_transceiver_dom_sensor_details(dut, asic_index, interfaces, xcvr_skip_list, port_list_with_flat_memory):
    """
    @summary: Check the detailed TRANSCEIVER_DOM_SENSOR content of all the specified interfaces.
    @param dut: The AnsibleHost object of DUT. For interacting with DUT.
    @param interfaces: List of interfaces that need to be checked.
    """
    logging.info("Check detailed TRANSCEIVER_DOM_SENSOR information of each connected ports")
    asichost = dut.asic_instance(asic_index)
    expected_fields = ["temperature", "voltage", "rx1power", "rx2power", "rx3power", "rx4power", "tx1bias",
                       "tx2bias", "tx3bias", "tx4bias", "tx1power", "tx2power", "tx3power", "tx4power"]
    for intf in interfaces:
        if intf not in xcvr_skip_list[dut.hostname] + port_list_with_flat_memory[dut.hostname]:
            cmd = 'redis-cli -n 6 hgetall "TRANSCEIVER_DOM_SENSOR|%s"' % intf
            docker_cmd = asichost.get_docker_cmd(cmd, "database")
            port_xcvr_dom_sensor = dut.command(docker_cmd)
            for field in expected_fields:
                assert port_xcvr_dom_sensor["stdout"].find(field) >= 0, \
                    "Expected field %s is not found in %s while checking %s" % (
                    field, port_xcvr_dom_sensor["stdout"], intf)


def check_transceiver_status(dut, asic_index, interfaces, xcvr_skip_list, port_list_with_flat_memory):
    """
    @summary: Check transceiver information of all the specified interfaces in redis DB.
    @param dut: The AnsibleHost object of DUT. For interacting with DUT.
    @param interfaces: List of interfaces that need to be checked.
    """
    check_transceiver_basic(dut, asic_index, interfaces, xcvr_skip_list)
    check_transceiver_details(dut, asic_index, interfaces, xcvr_skip_list)
    check_transceiver_dom_sensor_basic(dut, asic_index, interfaces, xcvr_skip_list, port_list_with_flat_memory)
    check_transceiver_dom_sensor_details(dut, asic_index, interfaces, xcvr_skip_list, port_list_with_flat_memory)


def get_map_port_to_start_and_end_line_number_for_sfp_eeporm(eeprom_infos):
    sfp_eeprom_list = eeprom_infos.split("\n")
    regex_port_name = r"^(?P<key>Ethernet\d+):(?P<value>.*)"
    line_start_num_list_per_port = []
    for index, line in enumerate(sfp_eeprom_list):
        res_port_name = re.search(regex_port_name, line)
        if res_port_name:
            port_name = res_port_name.groupdict()["key"].strip()
            line_start_num_list_per_port.append([port_name, index])
    logging.info(f"line_start_num_list_per_port :{line_start_num_list_per_port}")

    map_port_to_start_and_end_line_number = {}
    for index in range(len(line_start_num_list_per_port)):
        if index == len(line_start_num_list_per_port) - 1:
            line_start_num_for_current_port = line_start_num_list_per_port[index][1]
            line_end_num_for_current_port = len(sfp_eeprom_list) - 1
        else:
            line_start_num_for_current_port = line_start_num_list_per_port[index][1]
            line_end_num_for_current_port = line_start_num_list_per_port[index + 1][1] - 1
        map_port_to_start_and_end_line_number.update(
            {line_start_num_list_per_port[index][0]: [line_start_num_for_current_port, line_end_num_for_current_port]})
    logging.info(f"line_start_num and line_end_number per port :{map_port_to_start_and_end_line_number}")

    return map_port_to_start_and_end_line_number, sfp_eeprom_list


def get_ports_with_flat_memory(dut):
    ports_with_flat_memory = []
    cmd_show_eeprom = "sudo sfputil show eeprom -d"
    eeprom_infos = dut.command(cmd_show_eeprom, module_ignore_errors=True)['stdout']
    map_port_to_start_and_end_line_number, sfp_eeprom_list = get_map_port_to_start_and_end_line_number_for_sfp_eeporm(
        eeprom_infos)
    for port_name, line_number_section in map_port_to_start_and_end_line_number.items():
        if "DOM values not supported for flat memory module" in " ".join(
                sfp_eeprom_list[line_number_section[0]: line_number_section[1]+1]):
            ports_with_flat_memory.append(port_name)
    logging.info(f"Ports with flat memory: {ports_with_flat_memory}")
    return ports_with_flat_memory


def parse_one_sfp_eeprom_info(sfp_eeprom_info, start, end):
    """
    Parse the one sfp eeprom info, return top_key, sfp_eeprom_info_dict
    e.g
    sfp_info:
    Ethernet0: SFP EEPROM detected
        Application Advertisement: N/A
        Connector: No separable connector
        Encoding: 64B/66B
        Extended Identifier: Power Class 3 Module (2.5W max.),
                             No CLEI code present in Page 02h, CDR present in TX, CDR present in RX
        Extended RateSelect Compliance: Unknown
        Identifier: QSFP28 or later
        Length Cable Assembly(m): 3.0
        Nominal Bit Rate(100Mbs): 255
        Specification compliance:
                10/40G Ethernet Compliance Code: Extended
                Extended Specification Compliance: 100G AOC (Active Optical Cable) or 25GAUI C2M AOC
                Fibre Channel Link Length: Unknown
                Fibre Channel Speed: Unknown
                Fibre Channel Transmission Media: Unknown
                Fibre Channel Transmitter Technology: Unknown
                Gigabit Ethernet Compliant Codes: Unknown
                SAS/SATA Compliance Codes: Unknown
                SONET Compliance Codes: Unknown
        Vendor Date Code(YYYY-MM-DD Lot): 2019-01-17
        Vendor Name: Mellanox
        Vendor OUI: 00-02-c9
        Vendor PN: MFA1A00-C003
        Vendor Rev: B2
        Vendor SN: MT1903FT05965
        ChannelMonitorValues:
                RX1Power: 0.927dBm
                RX2Power: 0.938dBm
                RX3Power: 0.912dBm
                RX4Power: 0.95dBm
                TX1Bias: 6.75mA
                TX1Power: 1.071dBm
                TX2Bias: 6.75mA
                TX2Power: 1.04dBm
                TX3Bias: 6.75mA
                TX3Power: 1.039dBm
                TX4Bias: 6.75mA
                TX4Power: 1.031dBm
        ChannelThresholdValues:
                RxPowerHighAlarm  : 5.4dBm
                RxPowerHighWarning: 2.4dBm
                RxPowerLowAlarm   : -13.307dBm
                RxPowerLowWarning : -10.301dBm
                TxBiasHighAlarm   : 8.5mA
                TxBiasHighWarning : 8.0mA
                TxBiasLowAlarm    : 5.492mA
                TxBiasLowWarning  : 6.0mA
        ModuleMonitorValues:
                Temperature: 43.105C
                Vcc: 3.235Volts
        ModuleThresholdValues:
                TempHighAlarm  : 80.0C
                TempHighWarning: 70.0C
                TempLowAlarm   : -10.0C
                TempLowWarning : 0.0C
                VccHighAlarm   : 3.5Volts
                VccHighWarning : 3.465Volts
                VccLowAlarm    : 3.1Volts
                VccLowWarning  : 3.135Volts
    top_key, sfp_eeprom_info_dict:
    Ethernet0,
    {
        'Ethernet0': 'SFP EEPROM detected',
        'Application Advertisement': 'N/A',
        'Connector': 'No separable connector',
        'Encoding': '64B/66B',
        'Extended Identifier': 'Power Class 3 Module (2.5W max.),
                               No CLEI code present in Page 02h, CDR present in TX, CDR present in RX',
        'Extended RateSelect Compliance': 'Unknown',
        'Identifier': 'QSFP28 or later',
        'Length Cable Assembly(m)': '3.0',
        'Nominal Bit Rate(100Mbs)': '255',
        'Specification compliance': {
            '10/40G Ethernet Compliance Code': 'Extended',
            'Extended Specification Compliance': '100G AOC (Active Optical Cable) or 25GAUI C2M AOC',
            'Fibre Channel Link Length': 'Unknown',
            'Fibre Channel Speed': 'Unknown',
            'Fibre Channel Transmission Media': 'Unknown',
            'Fibre Channel Transmitter Technology': 'Unknown',
            'Gigabit Ethernet Compliant Codes': 'Unknown',
            'SAS/SATA Compliance Codes': 'Unknown',
            'SONET Compliance Codes': 'Unknown'
        },
        'Vendor Date Code(YYYY-MM-DD Lot)': '2019-01-17',
        'Vendor Name': 'Mellanox',
        'Vendor OUI': '00-02-c9',
        'Vendor PN': 'MFA1A00-C003',
        'Vendor Rev': 'B2',
        'Vendor SN': 'MT1903FT05965',
        'ChannelMonitorValues': {
            'RX1Power': '0.927dBm',
            'RX2Power': '0.938dBm',
            'RX3Power': '0.912dBm',
            'RX4Power': '0.95dBm',
            'TX1Bias': '6.75mA',
            'TX1Power': '1.071dBm',
            'TX2Bias': '6.75mA',
            'TX2Power': '1.04dBm',
            'TX3Bias': '6.75mA',
            'TX3Power': '1.039dBm',
            'TX4Bias': '6.75mA',
            'TX4Power': '1.031dBm'
        },
        'ChannelThresholdValues': {
            'RxPowerHighAlarm': '5.4dBm',
            'RxPowerHighWarning': '2.4dBm',
            'RxPowerLowAlarm': '-13.307dBm',
            'RxPowerLowWarning': '-10.301dBm',
            'TxBiasHighAlarm': '8.5mA',
            'TxBiasHighWarning': '8.0mA',
            'TxBiasLowAlarm': '5.492mA',
            'TxBiasLowWarning': '6.0mA'
        },
        'ModuleMonitorValues': {
            'Temperature': '43.105C',
            'Vcc': '3.235Volts'
        },
        'ModuleThresholdValues': {
            'TempHighAlarm': '80.0C',
            'TempHighWarning': '70.0C',
            'TempLowAlarm': '-10.0C',
            'TempLowWarning': '0.0C',
            'VccHighAlarm': '3.5Volts',
            'VccHighWarning': '3.465Volts',
            'VccLowAlarm': '3.1Volts',
            'VccLowWarning': '3.135Volts'
        }
    }
    """
    pattern_top_layer_key_value = r"^(?P<key>Ethernet\d+):(?P<value>.*)"
    pattern_second_layer_key_value = r"(^\s{8}|\t{1})(?P<key>[a-zA-Z0-9][a-zA-Z0-9\s\/\(\)-]+):(?P<value>.*)"
    pattern_third_layer_key_value = r"(^\s{16}|\t{2})(?P<key>[a-zA-Z0-9][a-zA-Z0-9\s\/]+):(?P<value>.*)"

    one_sfp_eeprom_info_dict = {}
    second_layer_dict = {}
    previous_key = ""
    top_key = ""
    for line in sfp_eeprom_info[start:end+1]:
        res1 = re.match(pattern_top_layer_key_value, line)
        if res1:
            top_key = res1.groupdict()["key"].strip()
            one_sfp_eeprom_info_dict[top_key] = res1.groupdict()[
                "value"].strip()
            continue
        res2 = re.match(pattern_second_layer_key_value, line)
        if res2:
            if second_layer_dict and previous_key:
                one_sfp_eeprom_info_dict[previous_key] = second_layer_dict
                second_layer_dict = {}
            one_sfp_eeprom_info_dict[res2.groupdict()["key"].strip()] = res2.groupdict()[
                "value"].strip()
            previous_key = res2.groupdict()["key"].strip()
        else:
            res3 = re.match(pattern_third_layer_key_value, line)
            if res3:
                second_layer_dict[res3.groupdict()["key"].strip()] = res3.groupdict()[
                    "value"].strip()
    if second_layer_dict and previous_key:
        one_sfp_eeprom_info_dict[previous_key] = second_layer_dict

    return top_key, one_sfp_eeprom_info_dict


def parse_sfp_eeprom_infos(eeprom_infos):
    """
    This method is to pares sfp eeprom infos, and return sfp_eeprom_info_dict
    """
    map_port_to_start_and_end_line_nubmer, sfp_eeprom_list = get_map_port_to_start_and_end_line_number_for_sfp_eeporm(
        eeprom_infos)
    sfp_eeprom_info_dict = {}
    for port_name, line_number_section in map_port_to_start_and_end_line_nubmer.items():
        _, eeprom_info = parse_one_sfp_eeprom_info(sfp_eeprom_list, line_number_section[0], line_number_section[1])
        sfp_eeprom_info_dict[port_name] = eeprom_info
    return sfp_eeprom_info_dict


def is_passive_cable(sfp_eeprom_info):
    # The implementation of the function refers to the function of is_xcvr_optical
    if "Specification compliance" in sfp_eeprom_info:
        spec_compliance = sfp_eeprom_info["Specification compliance"]

        if "passive" in spec_compliance or "Passive" in spec_compliance:
            # for QSFP-DD  OSFP-8X, and QSFP+C, it has the key "Specification compliance"
            return True
        elif isinstance(spec_compliance, dict):
            if "SFP+CableTechnology" in spec_compliance and "Passive" in spec_compliance.get("SFP+CableTechnology", ""):
                # For SFP/SFP+/SFP28, it has the key  "SFP+CableTechnolog"
                return True
            else:
                if "10/40G Ethernet Compliance Code" in spec_compliance and\
                        "CR" in spec_compliance.get("10/40G Ethernet Compliance Code", " "):
                    return True
                if "Extended Specification Compliance" in spec_compliance and\
                        "CR" in spec_compliance.get("Extended Specification Compliance", " "):
                    return True
    return False


def get_passive_cable_port_list(dut):
    passive_cable_port_list = []
    cmd_show_eeprom = "sudo sfputil show eeprom -d"
    eeprom_infos = dut.command(cmd_show_eeprom)['stdout']
    eeprom_infos = parse_sfp_eeprom_infos(eeprom_infos)
    for port_name, eeprom_info in eeprom_infos.items():
        if is_passive_cable(eeprom_info):
            logging.info(f"{port_name} is passive cable")
            passive_cable_port_list.append(port_name)
    logging.info(f"Ports with passive cable are: {passive_cable_port_list}")
    return passive_cable_port_list
