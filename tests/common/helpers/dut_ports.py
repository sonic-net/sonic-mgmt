import logging

logger = logging.getLogger(__name__)

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

def get_duthost_with_name(duthosts, dut_name):
    for duthost in duthosts:
        if dut_name in [ 'unknown', duthost.hostname ]:
            return duthost
    logger.error("Can't find duthost with name {}.".format(dut_name))
    return
