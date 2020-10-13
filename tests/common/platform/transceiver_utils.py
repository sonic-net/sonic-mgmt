"""
Helper script for checking status of transceivers

This script contains re-usable functions for checking status of transceivers.
"""
import logging
import re
import json


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


def all_transceivers_detected(dut, interfaces):
    """
    Check if transceiver information of all the specified interfaces have been detected.
    """
    db_output = dut.command("redis-cli --raw -n 6 keys TRANSCEIVER_INFO\*")["stdout_lines"]
    not_detected_interfaces = [intf for intf in interfaces if "TRANSCEIVER_INFO|%s" % intf not in db_output]
    if len(not_detected_interfaces) > 0:
        logging.info("Interfaces not detected: %s" % str(not_detected_interfaces))
        return False
    return True


def check_transceiver_basic(dut, interfaces):
    """
    @summary: Check whether all the specified interface are in TRANSCEIVER_INFO redis DB.
    @param dut: The AnsibleHost object of DUT. For interacting with DUT.
    @param interfaces: List of interfaces that need to be checked.
    """
    logging.info("Check whether transceiver information of all ports are in redis")
    xcvr_info = dut.command("redis-cli -n 6 keys TRANSCEIVER_INFO*")
    parsed_xcvr_info = parse_transceiver_info(xcvr_info["stdout_lines"])
    for intf in interfaces:
        assert intf in parsed_xcvr_info, "TRANSCEIVER INFO of %s is not found in DB" % intf


def check_transceiver_details(dut, interfaces):
    """
    @summary: Check the detailed TRANSCEIVER_INFO content of all the specified interfaces.
    @param dut: The AnsibleHost object of DUT. For interacting with DUT.
    @param interfaces: List of interfaces that need to be checked.
    """
    logging.info("Check detailed transceiver information of each connected port")
    expected_fields = ["type", "hardware_rev", "serial", "manufacturer", "model"]
    for intf in interfaces:
        port_xcvr_info = dut.command('redis-cli -n 6 hgetall "TRANSCEIVER_INFO|%s"' % intf)
        for field in expected_fields:
            assert port_xcvr_info["stdout"].find(field) >= 0, \
                "Expected field %s is not found in %s while checking %s" % (field, port_xcvr_info["stdout"], intf)


def check_transceiver_dom_sensor_basic(dut, interfaces):
    """
    @summary: Check whether all the specified interface are in TRANSCEIVER_DOM_SENSOR redis DB.
    @param dut: The AnsibleHost object of DUT. For interacting with DUT.
    @param interfaces: List of interfaces that need to be checked.
    """
    logging.info("Check whether TRANSCEIVER_DOM_SENSOR of all ports in redis")
    xcvr_dom_sensor = dut.command("redis-cli -n 6 keys TRANSCEIVER_DOM_SENSOR*")
    parsed_xcvr_dom_sensor = parse_transceiver_dom_sensor(xcvr_dom_sensor["stdout_lines"])
    for intf in interfaces:
        assert intf in parsed_xcvr_dom_sensor, "TRANSCEIVER_DOM_SENSOR of %s is not found in DB" % intf


def check_transceiver_dom_sensor_details(dut, interfaces):
    """
    @summary: Check the detailed TRANSCEIVER_DOM_SENSOR content of all the specified interfaces.
    @param dut: The AnsibleHost object of DUT. For interacting with DUT.
    @param interfaces: List of interfaces that need to be checked.
    """
    logging.info("Check detailed TRANSCEIVER_DOM_SENSOR information of each connected ports")
    expected_fields = ["temperature", "voltage", "rx1power", "rx2power", "rx3power", "rx4power", "tx1bias",
                       "tx2bias", "tx3bias", "tx4bias", "tx1power", "tx2power", "tx3power", "tx4power"]
    for intf in interfaces:
        port_xcvr_dom_sensor = dut.command('redis-cli -n 6 hgetall "TRANSCEIVER_DOM_SENSOR|%s"' % intf)
        for field in expected_fields:
            assert port_xcvr_dom_sensor["stdout"].find(field) >= 0, \
                "Expected field %s is not found in %s while checking %s" % (field, port_xcvr_dom_sensor["stdout"], intf)


def check_transceiver_status(dut, interfaces):
    """
    @summary: Check transceiver information of all the specified interfaces in redis DB.
    @param dut: The AnsibleHost object of DUT. For interacting with DUT.
    @param interfaces: List of interfaces that need to be checked.
    """
    check_transceiver_basic(dut, interfaces)
    check_transceiver_details(dut, interfaces)
    check_transceiver_dom_sensor_basic(dut, interfaces)
    check_transceiver_dom_sensor_details(dut, interfaces)
