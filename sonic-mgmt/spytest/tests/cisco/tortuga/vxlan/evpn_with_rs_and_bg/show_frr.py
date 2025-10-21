from spytest import st


def show_bgp_summary(dut, vrf=None, **kwargs):
    """
    Args:
        dut (WorkArea): device under test
        vrf (str): VRF name to filter by
        **kwargs: Additional arguments to pass to the command
                    skip_tmpl=False,
                    skip_error_check=True
    Returns:
        dict: BGP summary information
    Show BGP summary information.
    """
    commands = {
        "ipv4": (
            "show bgp vrf {vrf} ipv4 summary".format(vrf=vrf)
            if vrf
            else "show bgp ipv4 summary"
        ),
        "ipv6": (
            "show bgp vrf {vrf} ipv6 summary".format(vrf=vrf)
            if vrf
            else "show bgp ipv6 summary"
        ),
    }

    if not vrf:
        commands["l2vpn"] = "show bgp l2vpn evpn summary"

    output = {"ipv4": [], "ipv6": [], "l2vpn": []}
    for key, command in commands.items():
        f_cmd = "sudo vtysh -c '{cmd}'".format(cmd=command)
        cmd_output = st.show(dut, f_cmd, **kwargs)
        parsed_output = [[{}]]
        if key != "l2vpn":
            parsed_output = st.parse_show(
                dut, command, cmd_output, "show_ip_bgp_summary.tmpl"
            )
        else:
            parsed_output = st.parse_show(
                dut, command, cmd_output, "show_bgp_l2vpn_evpn_summary.tmpl"
            )
        output[key].append(parsed_output)
    return output


def show_ipv6_unicast_routes(dut, vrf, **kwargs):
    """
    Args:
        dut (WorkArea): device under test
        vrf (str): VRF name to filter by
        **kwargs: Additional arguments to pass to the command
                    skip_tmpl=False,
                    skip_error_check=True
    Returns:
        dict: IPv6 Unicast Routes information
    Show IPv6 Unicast Routes information (first 50 lines).
    """
    command = "show bgp vrf {vrf} ipv6".format(vrf=vrf)
    f_cmd = "vtysh -c '{cmd}' | head -n 50".format(cmd=command)
    output = st.show(dut, f_cmd, **kwargs)
    return st.parse_show(dut, command, output, "show_bgp_vrf_routes.tmpl")


def show_ipv4_unicast_routes(dut, vrf, **kwargs):
    """
    Args:
        dut (WorkArea): device under test
        vrf (str): VRF name to filter by
        **kwargs: Additional arguments to pass to the command
                    skip_tmpl=False,
                    skip_error_check=True
    Returns:
        dict: IPv4 Unicast Routes information
    Show IPv4 Unicast Routes information (first 50 lines).
    """
    command = "show bgp vrf {vrf} ipv4".format(vrf=vrf)
    f_cmd = "vtysh -c '{cmd}' | head -n 50".format(cmd=command)
    output = st.show(dut, f_cmd, **kwargs)
    return st.parse_show(dut, command, output, "show_bgp_vrf_routes.tmpl")


def show_bgp_type_2_routes(dut, **kwargs):
    """
    Args:
        dut (WorkArea): device under test
        **kwargs: Additional arguments to pass to the command
                    skip_tmpl=False,
                    skip_error_check=True
    Returns:
        dict: BGP Type 2 Routes information
    Show BGP Type 2 Routes information.
    """
    command = "show bgp l2vpn evpn route type 2"
    f_cmd = "sudo vtysh -c '{cmd}'".format(cmd=command)
    output = st.show(dut, f_cmd, **kwargs)
    return st.parse_show(dut, command, output, "show_bgp_l2vpn_evpn_route_type_2.tmpl")


def show_bgp_type_5_routes(dut, **kwargs):
    """
    Args:
        dut (WorkArea): device under test
        **kwargs: Additional arguments to pass to the command
                    skip_tmpl=False,
                    skip_error_check=True
    Returns:
        dict: BGP Type 5 Routes information
    Show BGP Type 5 Routes information.
    """
    command = "show bgp l2vpn evpn route type 5"
    f_cmd = "sudo vtysh -c '{cmd}'".format(cmd=command)
    output = st.show(dut, f_cmd, **kwargs)
    return st.parse_show(dut, command, output, "show_bgp_l2vpn_evpn_route_type_5.tmpl")


def show_routes(dut, network_type="ip", vrf=None, count=False, **kwargs):
    """
    Args:
        dut (WorkArea): device under test
        network_type (str): Type of routes to show (ip, ipv6)
        vrf (str): VRF name to filter by
        count (bool): If True, show the count of routes
        **kwargs: Additional arguments to pass to the command
                    skip_tmpl=False,
                    skip_error_check=True
    Returns:
        dict: Routes information
    Show Routes information.
    """
    command = "show {network_type} route".format(network_type=network_type)
    if vrf:
        command += " vrf {vrf}".format(vrf=vrf)
    f_cmd = "sudo vtysh -c '{cmd}'".format(cmd=command)
    if not count:
        output = st.show(dut, f_cmd, **kwargs)
        return st.parse_show(dut, command, output, "show_ip_route.tmpl")
    return st.config(dut, command + " | wc -l").split("\n")[0].strip()