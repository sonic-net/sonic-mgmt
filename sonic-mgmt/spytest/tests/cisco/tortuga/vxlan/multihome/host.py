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


def is_mac_exists(nodes, dut_name, mac, interface=None, is_dynamic=False):
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
    if is_dynamic and parsed[0]["type"] != "Dynamic":
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


def verify_ndp(nodes, host_ip, dut_name):
    """
    Verify NDP entry exists on the specified DUT.
    Uses show_ndp.tmpl for structured parsing (avoids substring false-matches
    against shorter v6 prefixes that share the same hextet prefix).

    Args:
        nodes (WA)      : WorkArea objects (DUTs)
        host_ip (str)   : IPv6 host address
        dut_name (str)  : DUT name
    Returns:
        True if NDP entry for host_ip is found on dut_name
    """
    output = st.show(nodes[dut_name], "show ndp", skip_tmpl=True, skip_error_check=True)
    parsed = st.parse_show(nodes[dut_name], "show ndp", output, "show_ndp.tmpl")
    st.log(parsed)
    for entry in parsed:
        if entry.get("address") == host_ip:
            st.log("NDP entry for {} present on {}".format(host_ip, dut_name))
            return True
    st.log("NDP entry for {} NOT found on {}".format(host_ip, dut_name))
    return False


def _parse_ipv6_route(node, vrf):
    """Run `show ipv6 route vrf <vrf>` and return parsed rows.

    show_ip_route_mh.tmpl is auto-selected via the template index mapping.
    """

    cmd = "show ipv6 route vrf {}".format(vrf)
    return st.show(node, cmd, type="vtysh", skip_error_check=True)

def verify_vrf_route_l3vni_v6(nodes, prefix_ip, vtep_host, vrf):
    """
    Verify IPv6 Type-5 VRF route on the specified VTEP via L3VNI/VXLAN tunnel.
    Walks the parsed `show ipv6 route vrf` output and asserts a BGP route for
    the requested prefix has LEAF2_VXLAN_IP in its nexthop list.

    Args:
        nodes (WA)      : WorkArea objects (DUTs)
        prefix_ip (str) : IPv6 prefix (e.g. "2001:db8:20::" or "2001:db8:20::/64")
        vtep_host (str) : VTEP host name to query
        vrf (str)       : VRF name
    Returns:
        True if a BGP route with prefix_ip and LEAF2 nexthop exists
    """
    parsed = _parse_ipv6_route(nodes[vtep_host], vrf)
    if not parsed:
        st.log("Empty `show ipv6 route vrf {}` on {}".format(vrf, vtep_host))
        return False
    for path in parsed:
        if path.get("type") != "B":
            continue
        ip_addr = path.get("ip_address", "")
        if prefix_ip not in ip_addr:
            continue
        nh = path.get("nexthop", []) or []
        if const.LEAF2_VXLAN_IP in nh:
            return True
    st.log("IPv6 VRF route {} via {} not found on {}".format(
        prefix_ip, const.LEAF2_VXLAN_IP, vtep_host))
    return False


def verify_ipv6_route_multihomed_host(nodes, prefix_ip, dut_name, vrf):
    """
    Verify IPv6 ECMP host route (or prefix route) for the multihomed host
    on the specified DUT. Walks parsed `show ipv6 route vrf` output and
    asserts a BGP route for prefix_ip has BOTH LEAF0 and LEAF1 in its
    nexthop list.

    Args:
        nodes (WA)      : WorkArea objects (DUTs)
        prefix_ip (str) : IPv6 prefix to look for (e.g. "<lag_ip6>/128"
                          for the Type-2 host route, or "<subnet>/64").
        dut_name (str)  : DUT name to query (typically leaf2)
        vrf (str)       : VRF name
    Returns:
        True if an ECMP BGP route with both LEAF0 and LEAF1 nexthops exists
    """
    parsed = _parse_ipv6_route(nodes[dut_name], vrf)
    if not parsed:
        st.log("Empty `show ipv6 route vrf {}` on {}".format(vrf, dut_name))
        return False
    for path in parsed:
        if path.get("type") != "B":
            continue
        ip_addr = path.get("ip_address", "")
        if prefix_ip not in ip_addr:
            continue
        nh = path.get("nexthop", []) or []
        if const.LEAF0_VXLAN_IP in nh and const.LEAF1_VXLAN_IP in nh:
            return True
    st.log("{} not installed as ECMP (LEAF0+LEAF1) in FRR on {}".format(
        prefix_ip, dut_name))
    return False


def get_mac_static_dynamic(nodes, dut, mac):
    """
    get_mac_static_dynamic
    Args:
        nodes (WA)      : WorkArea objects (DUTs)
        dut (str)       : dut of interest
        mac (str)       : MAC address to check
    Returns:
        tuple: (static, dynamic) - True if static or dynamic MAC exists, False otherwise
    """
    static = False
    dynamic = False
    #Verify MH mac is static on 1 leaf and dynamic on another
    output = st.show(nodes[dut], 'show mac -a {}'.format(mac), skip_tmpl=True, skip_error_check=True)
    parsed = st.parse_show(nodes[dut], 'show mac', output, 'show_mac.tmpl')
    st.log(parsed)
    if len(parsed) == 1:
        st.log("empty mac output")
    for path in parsed:
        if path['type'] == 'Dynamic':
            dynamic = True
        elif path['type'] == 'Static':
            static = True
    return static, dynamic


def reload_config(node):
    """
    reload_config
    Args:
        nodes (WA)      : WorkArea objects (DUTs)
    Returns:
        None
    """
    configure_cmd(node, "sudo config reload -y")


def restart_container(dut, container):
    """
    restart_daemon
    Args:
        nodes (WA)      : WorkArea objects (DUTs)
        dut_name (str)  : Dut
        container (str) : Container name
    Returns:
        None
    """
    configure_cmd(dut, "sudo docker restart {}".format(container))
    # wait for 20 seconds
    # to allow the restart to take effect
    # and the system to stabilize
    st.wait(20)
