from spytest import st
from multihome import const


def get_cli_out():
    """
    Get CLI output for debugging
    :return: None
    """
    cmds = [
        "show vxlan interface",
        "show mac",
        "show arp",
        "show interface counters",
        "show vxlan counters",
        "show evpn es",
        "ip nexthop",
    ]
    for dut in st.get_dut_names():
        if "leaf" in dut:
            for item in cmds:
                output = st.show(dut, item, skip_tmpl=True)
                st.log(output)


def show_cmd(
    node,
    cmd,
    skip_tmpl=False,
    skip_error_check=True,
):
    """
    Show command
    :param node: Node to show command
    :param cmd: Command to show
    :param skip_tmpl: Skip template check
    :return: Parsed output
    """
    output = st.show(node, cmd, skip_tmpl=skip_tmpl)
    parsed = st.parse_show(node, cmd, output)
    return parsed


def configure_cmd(node, cmd):
    """
    Configure command on the node
    :param node: Node to configure command
    :param cmd: Command to configure
    :return: None
    """
    st.config(node, cmd)
    st.wait(10)


def is_mac_exists(nodes, dut_name, mac, interface=None):
    """
    Check if MAC exists in the source VTEP
    :param nodes: List of nodes
    :param dut_name: dut
    :param mac: MAC address to check
    :param interface: Interface to check
    :return: True if MAC exists, False otherwise
    """
    output = st.show(
        nodes[dut_name],
        "show mac -a {}".format(mac),
        skip_tmpl=True,
        skip_error_check=True,
    )
    parsed = st.parse_show(nodes[dut_name], "show mac", output, "show_mac.tmpl")
    st.log(parsed)
    if (
        len(parsed) == 1
    ):  # parsed would contain minimum of 1 entry because of total entries field in show mac o/p
        return False
    if interface and parsed[0]["port"] != interface:
        return False
    return True


def is_mac_exists_local(nodes, dut_name, mac):
    """
    Check if MAC exists in the source VTEP
    :param nodes: List of nodes
    :param dut_name: dut
    :param mac: MAC address to check
    :return: True if MAC exists, False otherwise
    """
    output = st.show(
        nodes[dut_name],
        "show mac -l -a {}".format(mac),
        skip_tmpl=True,
        skip_error_check=True,
    )
    parsed = st.parse_show(nodes[dut_name], "show mac -l", output, "show_mac.tmpl")
    st.log(parsed)
    if (
        len(parsed) == 1
    ):  # parsed would contain minimum of 1 entry because of total entries field in show mac o/p
        return False
    return True


def verify_port_channel(nodes, dut_name):
    """
    verify_port_channel
    Args:
        nodes (WA)      : WorkArea objects (DUTs)
        dut_name (str)  : dut of interest
    Returns:
        True on Success
    """
    output = st.show(
        nodes["leaf0"],
        "show interface portchannel",
        skip_tmpl=True,
        skip_error_check=True,
    )
    parsed = st.parse_show(
        nodes["leaf0"],
        "show interface portchannel",
        output,
        "show_intf_portchannel.tmpl",
    )

    if len(parsed) != 0:
        return False
    return True


def verify_arp(nodes, host_ip, dut_name):
    """
    verify_arp
    Args:
        nodes (WA)      : WorkArea objects (DUTs)
        host_ip (str)   : Host IP address
        dut_name (str)  : Source VTEP dut_name
    Returns:
        True on Success
    """
    output = st.show(nodes[dut_name], "show arp", skip_tmpl=True, skip_error_check=True)
    parsed = st.parse_show(nodes[dut_name], "show arp", output, "show_arp.tmpl")
    st.log(parsed)
    if len(parsed) == 0:
        st.log("empty arp output")
        return False

    for path in parsed:
        if path["address"] == host_ip:
            st.log("host entry present on {}".format(dut_name))
            return True
    return False


def verify_ip_route_multihomed_host(nodes, prefix_ip, dut_name, vrf):
    """
    verify_ip_route_multihomed_host
    Args:
        nodes (WA)      : WorkArea objects (DUTs)
        prefix_ip (str) : Prefix IP address
        dut_name (str)  : Source VTEP dut
        vrf (str)      : VRF name
    Returns:
        True on Success"""
    output = st.show(
        nodes[dut_name],
        "show ip route vrf {}".format(vrf),
        type="vtysh",
        skip_tmpl=True,
        skip_error_check=True,
    )

    parsed = st.parse_show(
        nodes[dut_name],
        "show ip route vrf {}".format(vrf),
        output,
        "show_ip_route_mh.tmpl",
    )

    if len(parsed) == 0:
        st.report_fail(nodes[dut_name], msg="Found no routes in vrf {}".format(vrf))
    for path in parsed:
        if path["type"] == "B" and path["ip_address"] == "10.212.10.2/32":
            st.log(path["nexthop"])
            if path["nexthop"] == ["fd27::233:d0c6:fefb", "fd27::2dc:c1c9:e17c"]:
                return True
    st.log("{} not installed as ecmp in frr on {}".format(prefix_ip, dut_name))
    return False


def verify_vrf_route_l3vni(nodes, prefix_ip, vtep_host, vrf):
    """
    verify_vrf_route_l3vni
    Args:
        nodes (WA)      : WorkArea objects (DUTs)
        prefix_ip (str) : Prefix IP address
        vtep_host (str)  : vtep_host
        vrf (str)      : VRF name
    Returns:
        True on Success"""
    output = st.show(
        nodes[vtep_host],
        "show ip route vrf {}".format(vrf),
        type="vtysh",
        skip_tmpl=True,
        skip_error_check=True,
    )

    parsed = st.parse_show(
        nodes[vtep_host],
        "show ip route vrf {}".format(vrf),
        output,
        "show_ip_route_mh.tmpl",
    )

    if len(parsed) == 0:
        st.report_fail(nodes[vtep_host], msg="Found no routes in vrf {}".format(vrf))
    for path in parsed:
        if (
            path["type"] == "B"
            and path["ip_address"] == "10.212.20.0/24"
            and const.LEAF2_VXLAN_IP in path["nexthop"]
        ):
            return True
    return False
