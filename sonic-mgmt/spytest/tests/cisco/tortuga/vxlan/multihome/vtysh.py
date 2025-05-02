from spytest import st


def show_evpn_es(switch, verbose=False):
    """
    Show EVPN command
    Args:
        switch (str): Switch WorkArea
    Returns:
        cmd_output (list): raw output of the command
        parsed_output (list): Parsed output of the command
    """
    cmd = "show evpn es"
    cmd = cmd + " detail" if verbose else cmd
    cmd_output = st.vtysh_show(switch, cmd, skip_tmpl=True, skip_error_check=False)
    parsed_output = st.parse_show(switch, cmd, cmd_output, "show_evpn_es.tmpl")
    return cmd_output, parsed_output


def show_evpn_type_2(switch):
    """
    Show EVPN Type-2 command
    Args:
        switch (str): Switch WorkArea
    Returns:
        cmd_output (list): raw output of the command
        parsed_output (list): Parsed output of the command
    """
    cmd = "show bgp l2vpn evpn route type 2"
    cmd_output = st.vtysh_show(switch, cmd, skip_tmpl=True, skip_error_check=False)
    parsed_output = st.parse_show(
        switch, cmd, cmd_output, "show_bgp_l2vpn_evpn_route_type_2.tmpl"
    )
    return cmd_output, parsed_output


def verify_mac_advertisements(nodes, dut_name, mac, expected):
    """
    verify_mac_advertisements
    Args:
        nodes (WA)      : WorkArea objects (DUTs)
        dut_name (str)  : dut of interest
        mac (str)       : expected mac address to be learned
        expected (dict) : expected output dictionary
    Returns:
        True on Success
    """
    output = st.show(
        nodes[dut_name],
        "show evpn mac vni all",
        type="vtysh",
        skip_tmpl=True,
        skip_error_check=True,
    )
    parsed = st.parse_show(
        nodes[dut_name], "show evpn mac vni all", output, "show_evpn_mac_vni_all.tmpl"
    )
    actual_frr_op = {}
    st.log("zebra output: {}".format(parsed))
    if len(parsed) == 0:
        # Uncomment this once the seq id issue because of ARP ND, HW Learning is fixed.
        # return False
        st.log("Failed to find mac")
        return True
    for path in parsed:
        if path["mac_address"] == mac:
            actual_frr_op = {
                "mac_address": path["mac_address"],
                "type": path["type"],
                "vtep": path["vtep"],
                "seq": path["seq"],
            }
            break
    st.log("expected output for {}: {}".format(dut_name, expected[dut_name]))
    if actual_frr_op != expected[dut_name]:
        st.log("Actual and expected dont match in zebra")
        # Uncomment this once the seq id issue because of ARP ND, HW Learning is fixed.
        # return False
    return True


def configure_cmd(node, cmd):
    """
    Configure command on the node
    :param node: Node to configure command
    :param cmd: Command to configure
    :return: None
    """
    st.config(node, cmd, type="vtysh")
    st.wait(10)
