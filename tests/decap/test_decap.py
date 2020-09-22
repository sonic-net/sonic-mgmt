import json
import logging
from datetime import datetime

import pytest
from jinja2 import Template
from netaddr import IPNetwork
from ansible.plugins.filter.core import to_bool

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses       # lgtm[py/unused-import]
from tests.ptf_runner import ptf_runner
from tests.common.plugins.fib import generate_routes

logger = logging.getLogger(__name__)

PTFRUNNER_QLEN = 1000
FIB_INFO_DEST = "/root/fib_info.txt"

pytestmark = [
    pytest.mark.topology('any')
]

def get_uplink_ports(topology, topo_type):

    uplink_ports = []
    if topo_type == "t0":
        for k, v in topology["VMs"].items():
            if "T1" in k:
                uplink_ports.append("[{}]".format(" ".join([str(vlan) for vlan in v["vlans"]])))
    elif topo_type == "t1":
        for k, v in topology["VMs"].items():
            if "T2" in k:
                uplink_ports.append("[{}]".format(" ".join([str(vlan) for vlan in v["vlans"]])))
    return uplink_ports


def get_downlink_ports(topology, topo_type):
    downlink_ports = []
    if topo_type == "t0":
        if "host_interfaces" in topology:
            for intf in topology["host_interfaces"]:
                downlink_ports.append("[{}]".format(intf))
        if "disabled_host_interfaces" in topology:
            for intf in topology["disabled_host_interfaces"]:
                downlink_ports.remove("[{}]".format(intf))
    elif topo_type == "t1":
        for k, v in topology["VMs"].items():
            if "T0" in k:
                downlink_ports.append("[{}]".format(" ".join([str(vlan) for vlan in v["vlans"]])))
    return downlink_ports


def gen_fib_info(ptfhost, tbinfo, cfg_facts):

    topo_type = tbinfo["topo"]["type"]
    topology = tbinfo["topo"]["properties"]["topology"]

    # uplink ports
    uplink_ports_str = " ".join(get_uplink_ports(topology, topo_type))

    # downlink ports
    downlink_ports_str = " ".join(get_downlink_ports(topology, topo_type))

    fibs = []

    podset_number = 5  # Limit the number of podsets to limit test execution time
    tor_number = 16
    tor_subnet_number = 2

    # routes to uplink
    routes_uplink_v4 = []
    routes_uplink_v6 = []
    if topo_type == "t0":
        routes_uplink_v4 = generate_routes("v4", podset_number, tor_number, tor_subnet_number,
                                            0, 0, 0,
                                            "", "")
        routes_uplink_v6 = generate_routes("v6", podset_number, tor_number, tor_subnet_number,
                                            0, 0, 0,
                                            "", "")
    elif topo_type == "t1":
        routes_uplink_v4 = generate_routes("v4", podset_number, tor_number, tor_subnet_number,
                                            0, 0, 0,
                                            "", "", router_type="spine")
        routes_uplink_v6 = generate_routes("v6", podset_number, tor_number, tor_subnet_number,
                                            0, 0, 0,
                                            "", "", router_type="spine")

    for prefix, _, _ in routes_uplink_v4:
        fibs.append("{} {}".format(prefix, uplink_ports_str))
    for prefix, _, _ in routes_uplink_v6:
        fibs.append("{} {}".format(prefix, uplink_ports_str))

    routes_downlink_v4 = []
    routes_downlink_v6 = []
    if topo_type == "t1":
        routes_downlink_v4 = generate_routes("v4", podset_number, tor_number, tor_subnet_number,
                                            0, 0, 0,
                                            "", "", router_type="tor")
        routes_downlink_v6 = generate_routes("v6", podset_number, tor_number, tor_subnet_number,
                                            0, 0, 0,
                                            "", "", router_type="tor")

    for prefix, _, _ in routes_downlink_v4:
        fibs.append("{} {}".format(prefix, downlink_ports_str))
    for prefix, _, _ in routes_downlink_v6:
        fibs.append("{} {}".format(prefix, downlink_ports_str))

    ptfhost.copy(content="\n".join(fibs), dest="/root/fib_info.txt")


def prepare_ptf(ptfhost, tbinfo, cfg_facts):

    gen_fib_info(ptfhost, tbinfo, cfg_facts)


@pytest.fixture(scope="module")
def setup_teardown(request, tbinfo, duthost, ptfhost):

    # Initialize parameters
    dscp_mode = "pipe"
    ecn_mode = "copy_from_outer"
    ttl_mode = "pipe"

    # The hostvars dict has definitions defined in ansible/group_vars/sonic/variables
    hostvars = duthost.host.options["variable_manager"]._hostvars[duthost.hostname]
    sonic_hwsku = duthost.facts["hwsku"]
    mellanox_hwskus = hostvars["mellanox_hwskus"]

    if sonic_hwsku in mellanox_hwskus:
        dscp_mode = "uniform"
        ecn_mode = "standard"

    # Gather some facts
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="persistent")["ansible_facts"]

    lo_ip = None
    lo_ipv6 = None
    for addr in cfg_facts["LOOPBACK_INTERFACE"]["Loopback0"]:
        ip = IPNetwork(addr).ip
        if ip.version == 4 and not lo_ip:
            lo_ip = ip
        elif ip.version == 6 and not lo_ipv6:
            lo_ipv6 = ip
    logger.info("lo_ip={}, lo_ipv6={}".format(str(lo_ip), str(lo_ipv6)))

    vlan_ip = None
    vlan_ipv6 = None
    if "VLAN_INTERFACE" in cfg_facts:
        for addr in cfg_facts["VLAN_INTERFACE"]["Vlan1000"]:
            ip = IPNetwork(addr).ip
            if ip.version == 4 and not vlan_ip:
                vlan_ip = ip
            elif ip.version == 6 and not vlan_ipv6:
                vlan_ipv6 = ip
    logger.info("vlan_ip={}, vlan_ipv6={}".format(str(vlan_ip), str(vlan_ipv6)))

    # config decap
    decap_conf_template = Template(open("../ansible/roles/test/templates/decap_conf.j2").read())

    src_ports = set()
    topology = tbinfo["topo"]["properties"]["topology"]
    if "host_interfaces" in topology:
        src_ports.update(topology["host_interfaces"])
    if "disabled_host_interfaces" in topology:
        for intf in topology["disabled_host_interfaces"]:
            src_ports.discard(intf)
    if "VMs" in topology:
        for k, v in topology["VMs"].items():
            src_ports.update(v["vlans"])

    decap_conf_vars = {
        "outer_ipv4": to_bool(request.config.getoption("outer_ipv4")),
        "outer_ipv6": to_bool(request.config.getoption("outer_ipv6")),
        "inner_ipv4": to_bool(request.config.getoption("inner_ipv4")),
        "inner_ipv6": to_bool(request.config.getoption("inner_ipv6")),
        "lo_ip": str(lo_ip),
        "lo_ipv6": str(lo_ipv6),
        "op": "SET",
        "dscp_mode": dscp_mode,
        "ecn_mode": ecn_mode,
        "ttl_mode": ttl_mode,
    }

    duthost.copy(content=decap_conf_template.render(**decap_conf_vars), dest="/tmp/decap_conf.json")
    duthost.shell("docker cp /tmp/decap_conf.json swss:/decap_conf.json")
    duthost.shell('docker exec swss sh -c "swssconfig /decap_conf.json"')

    # Prepare PTFf docker
    prepare_ptf(ptfhost, tbinfo, cfg_facts)

    setup_info = {
        "src_ports": ",".join([str(port) for port in src_ports]),
        "router_mac": cfg_facts["DEVICE_METADATA"]["localhost"]["mac"],
        "vlan_ip": str(vlan_ip) if vlan_ip else "",
        "vlan_ipv6": str(vlan_ipv6) if vlan_ipv6 else "",
    }
    setup_info.update(decap_conf_vars)
    logger.info(json.dumps(setup_info, indent=2))

    yield setup_info

    # Remove decap configuration
    decap_conf_vars["op"] = "DEL"
    duthost.copy(content=decap_conf_template.render(**decap_conf_vars), dest="/tmp/decap_conf.json")
    duthost.shell("docker cp /tmp/decap_conf.json swss:/decap_conf.json")
    duthost.shell('docker exec swss sh -c "swssconfig /decap_conf.json"')


def test_decap(setup_teardown, tbinfo, ptfhost):

    setup_info = setup_teardown

    log_file = "/tmp/decap.{}.log".format(datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))
    ptf_runner(ptfhost,
               "ptftests",
               "IP_decap_test.DecapPacketTest",
                platform_dir="ptftests",
                params={"testbed_type": tbinfo['topo']['type'],
                        "outer_ipv4": setup_info["outer_ipv4"],
                        "outer_ipv6": setup_info["outer_ipv6"],
                        "inner_ipv4": setup_info["inner_ipv4"],
                        "inner_ipv6": setup_info["inner_ipv6"],
                        "lo_ip": setup_info["lo_ip"],
                        "lo_ipv6": setup_info["lo_ipv6"],
                        "vlan_ip": setup_info["vlan_ip"],
                        "vlan_ipv6": setup_info["vlan_ipv6"],
                        "dscp_mode": setup_info["dscp_mode"],
                        "ttl_mode": setup_info["ttl_mode"],
                        "src_ports": setup_info["src_ports"],
                        "router_mac": setup_info["router_mac"],
                        "fib_info": FIB_INFO_DEST,
                        },
                qlen=PTFRUNNER_QLEN,
                log_file=log_file)
