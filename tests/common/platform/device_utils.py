from tests.common.helpers.dut_ports import encode_dut_port_name

"""
Helper script for fanout switch operations
"""

def fanout_switch_port_lookup(fanout_switches, dut_name, dut_port):
    """
        look up the fanout switch instance and the fanout switch port
        connecting to the dut_port

        Args:
            fanout_switches (list FanoutHost): list of fanout switch
                                               instances.
            dut_name (str): the host name of the DUT
            dut_port (str): port name on the DUT

        Returns:
            None, None if fanout switch instance and port is not found
            FanoutHost, Portname(str) if found
    """
    dut_host_port = encode_dut_port_name(dut_name, dut_port)
    for _, fanout in fanout_switches.items():
        if dut_host_port in fanout.host_to_fanout_port_map:
            return fanout, fanout.host_to_fanout_port_map[dut_host_port]

    return None, None


def get_dut_psu_line_pattern(dut):
    if "201811" in dut.os_version or "201911" in dut.os_version:
        psu_line_pattern = re.compile(r"PSU\s+(\d)+\s+(OK|NOT OK|NOT PRESENT)")
    else:
        """
        Changed the pattern to match space (s+) and non-space (S+) only.
        w+ cannot match following examples properly:

        example 1:
            PSU 1  PWR-500AC-R  L8180S01HTAVP  N/A            N/A            N/A          OK        green
            PSU 2  PWR-500AC-R  L8180S01HFAVP  N/A            N/A            N/A          OK        green
        example 2:
            PSU 1  N/A      N/A               12.05           3.38        40.62  OK        green
            PSU 2  N/A      N/A               12.01           4.12        49.50  OK        green

        """
        psu_line_pattern = re.compile(r"PSU\s+(\d+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(OK|NOT OK|NOT PRESENT)\s+(green|amber|red|off)")
    return psu_line_pattern
