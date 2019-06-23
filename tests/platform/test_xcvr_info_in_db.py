"""
Check xcvrd information in DB

This script is to cover the test case 'Check xcvrd information in DB' in the SONiC platform test plan:
https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""
import logging
import re
import os

from ansible_host import ansible_host


def parse_transceiver_info(output_lines):
    """
    @summary: Parse the list of transceiver from DB table TRANSCEIVER_INFO content
    @param output_lines: DB table TRANSCEIVER_INFO content output by 'redis' command
    @return: Return parsed transceivers in a list
    """
    res = []
    p = re.compile(r"TRANSCEIVER_INFO\|(Ethernet\d+)")
    for line in output_lines:
        m = p.match(line)
        assert m, "Unexpected line %s" % line
        res.append(m.group(1))
    return res


def parse_transceiver_dom_sensor(output_lines):
    """
    @summary: Parse the list of transceiver from DB table TRANSCEIVER_DOM_SENSOR content
    @param output_lines: DB table TRANSCEIVER_DOM_SENSOR content output by 'redis' command
    @return: Return parsed transceivers in a list
    """
    res = []
    p = re.compile(r"TRANSCEIVER_DOM_SENSOR\|(Ethernet\d+)")
    for line in output_lines:
        m = p.match(line)
        assert m, "Unexpected line %s" % line
        res.append(m.group(1))
    return res


def test_xcvr_info_in_db(localhost, ansible_adhoc, testbed):
    """
    @summary: This test case is to verify that xcvrd works as expected by checking transceiver information in DB
    """
    hostname = testbed['dut']
    ans_host = ansible_host(ansible_adhoc, hostname)
    localhost.command("who")
    lab_conn_graph_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), \
        "../../ansible/files/lab_connection_graph.xml")
    conn_graph_facts = localhost.conn_graph_facts(host=hostname, filename=lab_conn_graph_file).\
        contacted['localhost']['ansible_facts']

    logging.info("Check whether transceiver information of all ports are in redis")
    xcvr_info = ans_host.command("redis-cli -n 6 keys TRANSCEIVER_INFO*")
    parsed_xcvr_info = parse_transceiver_info(xcvr_info["stdout_lines"])
    for intf in conn_graph_facts["device_conn"]:
        assert intf in parsed_xcvr_info, "TRANSCEIVER INFO of %s is not found in DB" % intf

    logging.info("Check detailed transceiver information of each connected port")
    expected_fields = ["type", "hardwarerev", "serialnum", "manufacturename", "modelname"]
    for intf in conn_graph_facts["device_conn"]:
        port_xcvr_info = ans_host.command('redis-cli -n 6 hgetall "TRANSCEIVER_INFO|%s"' % intf)
        for field in expected_fields:
            assert port_xcvr_info["stdout"].find(field) >= 0, \
                "Expected field %s is not found in %s while checking %s" % (field, port_xcvr_info["stdout"], intf)

    logging.info("Check whether TRANSCEIVER_DOM_SENSOR of all ports in redis")
    xcvr_dom_senspor = ans_host.command("redis-cli -n 6 keys TRANSCEIVER_DOM_SENSOR*")
    parsed_xcvr_dom_senspor = parse_transceiver_dom_sensor(xcvr_dom_senspor["stdout_lines"])
    for intf in conn_graph_facts["device_conn"]:
        assert intf in parsed_xcvr_dom_senspor, "TRANSCEIVER_DOM_SENSOR of %s is not found in DB" % intf

    logging.info("Check detailed TRANSCEIVER_DOM_SENSOR information of each connected ports")
    expected_fields = ["temperature", "voltage", "rx1power", "rx2power", "rx3power", "rx4power", "tx1bias",
                       "tx2bias", "tx3bias", "tx4bias", "tx1power", "tx2power", "tx3power", "tx4power"]
    for intf in conn_graph_facts["device_conn"]:
        port_xcvr_dom_sensor = ans_host.command('redis-cli -n 6 hgetall "TRANSCEIVER_DOM_SENSOR|%s"' % intf)
        for field in expected_fields:
            assert port_xcvr_dom_sensor["stdout"].find(field) >= 0, \
                "Expected field %s is not found in %s while checking %s" % (field, port_xcvr_dom_sensor["stdout"], intf)
