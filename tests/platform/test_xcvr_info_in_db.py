"""
Check xcvrd information in DB

This script is to cover the test case 'Check xcvrd information in DB' in the SONiC platform test plan:
https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""
import logging
import re
import os

from ansible_host import ansible_host
from check_transceiver_status import check_transceiver_status


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
    interfaces = conn_graph_facts["device_conn"]

    logging.info("Check transceiver status")
    check_transceiver_status(ans_host, interfaces)
