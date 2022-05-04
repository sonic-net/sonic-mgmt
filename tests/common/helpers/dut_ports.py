from tests.common.platform.device_utils import fanout_switch_port_lookup


def encode_dut_port_name(dutname, portname):
    return dutname + '|' + portname


def decode_dut_port_name(dut_portname):
    tokens = dut_portname.split('|')
    if len(tokens) >= 2:
        dutname = tokens[0]
        portname = tokens[1]
    elif len(tokens) == 1:
        dutname = None
        portname = dut_portname
    else:
        dutname = None
        portname = None
    return dutname, portname


def list_dut_fanout_connections(dut, fanouthosts):
    """
    Lists connected dut-fanout ports

    Args:
        dut: DUT host object
        fanouthosts: List of fanout switch instances.

    Returns:
        A list of tuple with DUT's port, fanout port
        and fanout
    """
    candidates = []

    status = dut.show_interface(command='status')['ansible_facts']['int_status']

    for dut_port in status.keys():
        fanout, fanout_port = fanout_switch_port_lookup(fanouthosts, dut.hostname, dut_port)

        if fanout and fanout_port and status[dut_port]['admin_state'] != 'down':
            candidates.append((dut_port, fanout, fanout_port))

    return candidates
