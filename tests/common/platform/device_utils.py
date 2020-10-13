"""
Helper script for fanout switch operations
"""

def fanout_switch_port_lookup(fanout_switches, dut_port):
    """
        look up the fanout switch instance and the fanout switch port
        connecting to the dut_port

        Args:
            fanout_switches (list FanoutHost): list of fanout switch
                                               instances.
            dut_port (str): port name on the DUT

        Returns:
            None, None if fanout switch instance and port is not found
            FanoutHost, Portname(str) if found
    """
    for _, fanout in fanout_switches.items():
        if dut_port in fanout.host_to_fanout_port_map:
            return fanout, fanout.host_to_fanout_port_map[dut_port]

    return None, None
