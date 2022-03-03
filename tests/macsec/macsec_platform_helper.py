import ast
import collections
import re
from multiprocessing.pool import ThreadPool

import pytest


def global_cmd(duthost, nbrhosts, cmd):
    pool = ThreadPool(1 + len(nbrhosts))
    pool.apply_async(duthost.command, args=(cmd,))
    for nbr in nbrhosts.values():
        pool.apply_async(nbr["host"].command, args=(cmd, ))
    pool.close()
    pool.join()


def find_links(duthost, tbinfo, filter):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    for interface, neighbor in mg_facts["minigraph_neighbors"].items():
        filter(interface, neighbor, mg_facts, tbinfo)


def find_links_from_nbr(duthost, tbinfo, nbrhosts):
    links = collections.defaultdict(dict)

    def filter(interface, neighbor, mg_facts, tbinfo):
        if neighbor["name"] not in nbrhosts.keys():
            return
        port = mg_facts["minigraph_neighbors"][interface]["port"]
        links[interface] = {
            "name": neighbor["name"],
            "host": nbrhosts[neighbor["name"]]["host"],
            "port": port
        }
    find_links(duthost, tbinfo, filter)
    return links


def sonic_db_cli(host, cmd):
    return ast.literal_eval(host.shell(cmd)["stdout_lines"][0])


def get_all_ifnames(host):
    cmd = "ls /sys/class/net/"
    output = host.command(cmd)["stdout_lines"]
    ports = {
        "Ethernet": [],
        "eth": [],
        "macsec": [],
    }
    for type in ports.keys():
        ports[type] = [port.decode("utf-8")
                       for port in output if port.startswith(type)]
        ports[type].sort(key=lambda no: int(re.search(r'\d+', no).group(0)))
    # Remove the eth0
    ports["eth"].pop(0)
    return ports


def get_eth_ifname(host, port_name):
    if u"x86_64-kvm_x86_64" not in get_platform(host):
        logging.info("Can only get the eth ifname on the virtual SONiC switch")
        return None
    ports = get_all_ifnames(host)
    assert port_name in ports["Ethernet"]
    return ports["eth"][ports["Ethernet"].index(port_name)]


def get_macsec_ifname(host, port_name):
    if u"x86_64-kvm_x86_64" not in get_platform(host):
        logging.info(
            "Can only get the macsec ifname on the virtual SONiC switch")
        return None
    ports = get_all_ifnames(host)
    assert port_name in ports["Ethernet"]
    eth_port = ports["eth"][ports["Ethernet"].index(port_name)]
    macsec_infname = "macsec_"+eth_port
    assert macsec_infname in ports["macsec"]
    return macsec_infname


def get_platform(host):
    for line in host.command("show platform summary")["stdout_lines"]:
        if "Platform" == line.split(":")[0]:
            return line.split(":")[1].strip()
    pytest.fail("No platform was found.")


def get_portchannel(host):
    '''
        Here is an output example of `show interfaces portchannel`
        admin@sonic:~$ show interfaces portchannel
        Flags: A - active, I - inactive, Up - up, Dw - Down, N/A - not available,
            S - selected, D - deselected, * - not synced
        No.  Team Dev         Protocol     Ports
        -----  ---------------  -----------  ---------------------------
        0001  PortChannel0001  LACP(A)(Up)  Ethernet112(S) Ethernet108(D)
        0002  PortChannel0002  LACP(A)(Up)  Ethernet116(S)
        0003  PortChannel0003  LACP(A)(Up)  Ethernet120(S)
        0004  PortChannel0004  LACP(A)(Up)  N/A
    '''
    lines = host.command("show interfaces portchannel")["stdout_lines"]
    lines = lines[4:]  # Remove the output header
    portchannel_list = {}
    for line in lines:
        items = line.split()
        portchannel = items[1]
        portchannel_list[portchannel] = {"status": None, "members": []}
        if items[-1] == "N/A":
            continue
        portchannel_list[portchannel]["status"] = re.search(
            r"\((Up|Dw)\)", items[2]).group(1)
        for item in items[3:]:
            port = re.search(r"(Ethernet.*)\(", item).group(1)
            portchannel_list[portchannel]["members"].append(port)
    return portchannel_list


def find_portchannel_from_member(port_name, portchannel_list):
    for k, v in portchannel_list.items():
        if port_name in v["members"]:
            return v
    return None
