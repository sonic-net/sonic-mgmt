import ast
import re
from multiprocessing.pool import ThreadPool

import pytest

from tests.common.devices.eos import EosHost


__all__ = [
    'find_portchannel_from_member',
    'get_eth_ifname',
    'get_macsec_ifname',
    'get_portchannel',
    'get_lldp_list',
    'get_platform',
    'global_cmd',
    'sonic_db_cli'
]


def global_cmd(duthost, nbrhosts, cmd):
    pool = ThreadPool(1 + len(nbrhosts))
    pool.apply_async(duthost.command, args=(cmd,))
    for nbr in nbrhosts.values():
        if isinstance(nbr["host"], EosHost):
            continue
        pool.apply_async(nbr["host"].command, args=(cmd, ))
    pool.close()
    pool.join()


def sonic_db_cli(host, cmd):
    return ast.literal_eval(host.shell(cmd)["stdout_lines"][0])


def get_all_ifnames(host, asic = None):
    cmd_prefix = " "
    if host.is_multi_asic and asic is not None:
        ns = host.get_namespace_from_asic_id(asic.asic_index)
        cmd_prefix = "sudo ip netns exec {} ".format(ns)

    cmd = "{} ls /sys/class/net/".format(cmd_prefix)
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
    asic = None
    if u"x86_64-kvm_x86_64" in get_platform(host):
        logging.info("Get the eth ifname on the virtual SONiC switch")
        if host.is_multi_asic:
            asic = host.get_port_asic_instance(port_name)
        ports = get_all_ifnames(host, asic)
        assert port_name in ports["Ethernet"]
        return ports["eth"][ports["Ethernet"].index(port_name)]
    # Same as port_name
    return port_name


def get_macsec_ifname(host, port_name):
    asic = None
    if u"x86_64-kvm_x86_64" not in get_platform(host):
        logging.info(
            "Can only get the macsec ifname on the virtual SONiC switch")
        return None
    if host.is_multi_asic:
        asic = host.get_port_asic_instance(port_name)
    ports = get_all_ifnames(host, asic)
    assert port_name in ports["Ethernet"]
    eth_port = ports["eth"][ports["Ethernet"].index(port_name)]
    macsec_infname = "macsec_"+eth_port
    assert macsec_infname in ports["macsec"]
    return macsec_infname


def get_platform(host):
    if isinstance(host, EosHost):
        return "Arista"
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
        portchannel_list[portchannel] = {
            "name": portchannel, "status": None, "members": []}
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


def get_lldp_list(host):
    '''
        Here is an output example of `show lldp table`
            Capability codes: (R) Router, (B) Bridge, (O) Other
            LocalPort    RemoteDevice    RemotePortID    Capability    RemotePortDescr
            -----------  --------------  --------------  ------------  -----------------
            Ethernet112  ARISTA01T1      Ethernet1       BR
            Ethernet116  ARISTA02T1      Ethernet1       BR
            Ethernet120  ARISTA03T1      Ethernet1       BR
            Ethernet124  ARISTA04T1      Ethernet1       BR
            --------------------------------------------------
            Total entries displayed:  4
    '''
    lines = host.command("show lldp table")["stdout_lines"]
    lines = lines[3:-2]  # Remove the output header
    lldp_list = {}
    for line in lines:
        items = line.split()
        lldp = items[1]
        lldp_list[lldp] = {"name": lldp, "localport": items[0], "remoteport": items[2]}
    return lldp_list
