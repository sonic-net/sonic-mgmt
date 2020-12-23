import logging
import json
import os
import pytest

from collections import defaultdict
from jinja2 import Template
from tests.common.fixtures.conn_graph_facts import conn_graph_facts


TESTBED_TEMPLATE = "templates/spytest_testbed.yaml.j2"
PTF_INTERFACE_TEMPLATE = "1/%d"

pytestmark = [
    pytest.mark.topology("util"),
    pytest.mark.sanity_check(skip_sanity=True)
]


@pytest.fixture(scope="function")
def hostvars(duthosts):
    """Return host variables dicts for DUTs defined in testbed."""
    if not duthosts:
        return {}
    var_manager = duthosts[-1].host.options["variable_manager"]
    hostvars_all = var_manager.get_vars()["hostvars"]
    return {duthost.hostname: hostvars_all[duthost.hostname]
            for duthost in duthosts}


def test_gen_spy_testbed(conn_graph_facts, hostvars, tbinfo,
                         pytestconfig):
    """Generate spytest testbed file."""

    def _interface_key(interface):
        """Get interface key to sort."""
        return list(map(int, interface.lstrip("Ethernet").split("/")))

    hostnames = tbinfo["duts"]
    connections = conn_graph_facts["device_conn"]

    # devices section
    devices = []
    for hostname in hostnames:
        hostvar = hostvars[hostname]
        login_info = {}
        login_info["login_access"] = \
            json.dumps(hostvar["login_access"]).replace('"', '')
        login_info["login_credentials"] = \
            json.dumps(hostvar["login_credentials"]).replace('"', '')
        devices.append((hostname, login_info))

    # topology section
    ptf_connections = []
    intf = 1
    for hostname in hostnames:
        end_device = hostname
        conns = connections[hostname]
        end_ports = sorted(
            (_ for _ in conns if conns[_]['peerdevice'] not in connections),
            key=_interface_key)
        for end_port in end_ports:
            ptf_conn = {
                "start_port": PTF_INTERFACE_TEMPLATE % intf,
                "end_device": hostname,
                "end_port": end_port
            }
            ptf_connections.append(ptf_conn)
            conns.pop(end_port)
            intf += 1

    dev_connections = defaultdict(list)
    for hostname in hostnames:
        conns = connections[hostname]
        for start_port in sorted(conns.keys(), key=_interface_key):
            end_device = conns[start_port]["peerdevice"]
            end_port = conns[start_port]["peerport"]
            dev_connections[hostname].append(
                {
                    "start_port": start_port,
                    "end_device": end_device,
                    "end_port": end_port
                }
            )
            connections[end_device].pop(end_port)

    # write to testbed dest file
    with open(TESTBED_TEMPLATE) as tmpl_fd:
        testbed_tmpl = Template(
            tmpl_fd.read(), trim_blocks=True, lstrip_blocks=True)
    testbed_file = os.path.join(str(pytestconfig.rootdir),
                                "../spytest/testbeds/spytest_testbed.yaml")
    testbed_file = os.path.normpath(testbed_file)
    logging.info("testbed save path: %s", testbed_file)
    if os.path.exists(testbed_file):
        logging.warn("testbed file(%s) exists, overwrite!", testbed_file)
    testbed_stream = testbed_tmpl.stream(
        devices=devices,
        tbinfo=tbinfo,
        ptf_connections=ptf_connections,
        dev_connections=dev_connections
    )
    testbed_stream.dump(testbed_file)
