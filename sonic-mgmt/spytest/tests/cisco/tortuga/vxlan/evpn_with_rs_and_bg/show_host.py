from spytest import st


def show_remote_vtep(dut, count=False, **kwargs):
    """
    Args:
        dut (WorkArea): device under test
        count (bool): If True, show the count of remote VTEPs
        **kwargs: Additional arguments to pass to the command
                    skip_tmpl=False,
                    skip_error_check=True,
    Returns:
        dict/str: Remote VTEP/Count information
    Show remote VTEP information.
    """
    command = "show vxlan remotevtep"
    if not count:
        return st.show(dut, command, **kwargs)
    return (
        st.config(dut, command + " | grep Total").split("\n")[0].split(":")[1].strip()
    )


def show_bridge_fdb(
    dut, mac_prefix=None, vlan=None, type=None, interface=None, count=False, **kwargs
):
    """
    Args:
        dut (WorkArea): device under test
        mac_prefix (str): MAC address prefix to filter by
        vlan (str): VLAN ID to filter by
        type (str): Type of FDB entry to filter by
        count (bool): If True, show the count of FDB entries
        **kwargs: Additional arguments to pass to the command
                    skip_tmpl=False,
                    skip_error_check=True,
    Returns:
        dict: Bridge FDB information
    Show bridge FDB information.
    """
    command = "bridge fdb show"
    if mac_prefix:
        command += f" | grep {mac_prefix}"
    if vlan:
        command += f" | grep {vlan}"
    if type:
        command += f" | grep {type}"
    if interface:
        command += f" | grep {interface}"
    if not count:
        return st.show(dut, command, **kwargs)
    return st.config(dut, command + " | wc -l").split("\n")[0].strip()


def show_mac(dut, type=None, count=False, **kwargs):
    """
    Args:
        dut (WorkArea): device under test
        interface (str): Interface to filter by
        type (str): Type of MAC entry to filter by (Static/Dynamic)
        count (bool): If True, show the count of MAC entries
        **kwargs: Additional arguments to pass to the command
                    skip_tmpl=False,
                    skip_error_check=True,
    Returns:
        dict/str: MAC/Count information
    Show MAC information.
    """
    command = f"show mac"
    if type:
        command += f" | grep {type}"
    if not count:
        return st.show(dut, command, **kwargs)
    return st.config(dut, command + " | wc -l").split("\n")[0].strip()
