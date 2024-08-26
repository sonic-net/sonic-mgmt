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
