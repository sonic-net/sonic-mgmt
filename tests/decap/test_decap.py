import json
import logging
import tempfile
from datetime import datetime

import pytest
from jinja2 import Template
from netaddr import IPNetwork
from ansible.plugins.filter.core import to_bool

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses       # lgtm[py/unused-import]
from tests.ptf_runner import ptf_runner

logger = logging.getLogger(__name__)

PTFRUNNER_QLEN = 1000
FIB_INFO_DEST = "/root/fib_info.txt"

pytestmark = [
    pytest.mark.topology('any')
]


def get_fib_info(duthost, cfg_facts, mg_facts):
    """Get parsed FIB information from redis DB.

    Args:
        duthost (SonicHost): Object for interacting with DUT.
        cfg_facts (dict): Configuration facts.
        mg_facts (dict): Minigraph facts.

    Returns:
        dict: Map of prefix to PTF ports that are connected to DUT output ports.
            {
                '192.168.0.0/21': [],
                '192.168.8.0/25': [[58 59] [62 63] [66 67] [70 71]],
                '192.168.16.0/25': [[58 59] [62 63] [66 67] [70 71]],
                ...
                '20c0:c2e8:0:80::/64': [[58 59] [62 63] [66 67] [70 71]],
                '20c1:998::/64': [[58 59] [62 63] [66 67] [70 71]],
                ...
            }
    """
    timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
    duthost.shell("redis-dump -d 0 -k 'ROUTE*' -y > /tmp/fib.{}.txt".format(timestamp))
    duthost.fetch(src="/tmp/fib.{}.txt".format(timestamp), dest="/tmp/fib")

    po = cfg_facts.get('PORTCHANNEL', {})
    ports = cfg_facts.get('PORT', {})

    fib_info = {}
    with open("/tmp/fib/{}/tmp/fib.{}.txt".format(duthost.hostname, timestamp)) as fp:
        fib = json.load(fp)
        for k, v in fib.items():
            skip = False

            prefix = k.split(':', 1)[1]
            ifnames = v['value']['ifname'].split(',')
            nh = v['value']['nexthop']

            oports = []
            for ifname in ifnames:
                if po.has_key(ifname):
                    oports.append([str(mg_facts['minigraph_ptf_indices'][x]) for x in po[ifname]['members']])
                else:
                    if ports.has_key(ifname):
                        oports.append([str(mg_facts['minigraph_ptf_indices'][ifname])])
                    else:
                        logger.info("Route point to non front panel port {}:{}".format(k, v))
                        skip = True

            # skip direct attached subnet
            if nh == '0.0.0.0' or nh == '::' or nh == "":
                skip = True

            if not skip:
                fib_info[prefix] = oports
            else:
                fib_info[prefix] = []
    return fib_info


def gen_fib_info_file(ptfhost, fib_info, filename):
    tmp_fib_info = tempfile.NamedTemporaryFile()
    for prefix, oports in fib_info.items():
        tmp_fib_info.write(prefix)
        if oports:
            for op in oports:
                tmp_fib_info.write(' [{}]'.format(' '.join(op)))
        else:
            tmp_fib_info.write(' []')
        tmp_fib_info.write('\n')
    tmp_fib_info.flush()
    ptfhost.copy(src=tmp_fib_info.name, dest=filename)


def prepare_ptf(duthost, ptfhost, cfg_facts, mg_facts):
    fib_info = get_fib_info(duthost, cfg_facts, mg_facts)
    gen_fib_info_file(ptfhost, fib_info, FIB_INFO_DEST)


@pytest.fixture(scope="module")
def setup_teardown(request, tbinfo, duthosts, rand_one_dut_hostname, ptfhost):
    duthost = duthosts[rand_one_dut_hostname]

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
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

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
    prepare_ptf(duthost, ptfhost, cfg_facts, mg_facts)

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
