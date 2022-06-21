import logging
import pytest
import json
from tests.common.utilities import wait

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('wan'),
    pytest.mark.sanity_check(skip_sanity=True)
]

""" 
Verify hello_padding parameter in ISIS_INTERFACE behaviour.
hello_padding:ENABLE or not set means IS-IS pads each hello packet to full MTU.
hello_padding:DISABLE or not set means IS-IS turns off hello padding.
"""

CONFIG_PATH = '/var/tmp/'
DEFAULT_MTU = 1500
EXPECTED_PADDING_PACKET_LENGTH = str(DEFAULT_MTU - 3) # This is verified with Cisco peer only.

def set_hello_padding(isis_json_obj, itf, value):
    obj = isis_json_obj[itf]
    obj['hello_padding'] = value
    return isis_json_obj

def stop_pushconfig_start_pcap(duthosts, rand_one_dut_hostname, enum_frontend_asic_index, padding):
    duthost = duthosts[rand_one_dut_hostname]
    logger.info("set hello padding on dut {} {}".format(duthost.hostname, padding))
    running_config = duthost.get_running_config_facts()

    if not 'ISIS_INTERFACE' in running_config:
        assert 'ISIS_INTERFACE' in running_config, "ISIS_INTERFACE is NOT in running_config"

    itf = None
    for k, v in running_config['ISIS_INTERFACE'].items():
        if 'circuit_type' in v:
            itf = k
            break

    # New ISIS interface configuration.
    isis_itf_cfg = os.path.join(CONFIG_PATH, 'isis_config')
    shell_cmd = "echo '{}' > {}".format('{"ISIS_INTERFACE":' + json.dumps(set_hello_padding(running_config['ISIS_INTERFACE'], itf, padding)) + '}', isis_itf_cfg)
    duthost.shell(shell_cmd)
    logger.info(duthost.get_running_config_facts()['ISIS_INTERFACE'])

    # Stop interface, write ISIS interface configuration, start interface again.
    sonic_cli = 'sudo config interface shutdown {}'.format(itf)
    duthost.command(sonic_cli)
    wait(3, 'Wait {} shutdown'.format(itf))

    duthost.command('sonic-cfggen -j {} --write-to-db'.format(isis_itf_cfg))

    sonic_cli = 'sudo config interface startup {}'.format(itf)
    duthost.command(sonic_cli)
    
    #pcap to detect padding in hello packet.
    pcap_path = os.path.join(CONFIG_PATH, 'sonic_isis.pcap')
    shell_cmd = "sudo tcpdump -i {} -s 0 -c 50 -w {}".format(itf, pcap_path)
    duthost.shell(shell_cmd)
    shell_cmd = "sudo tcpdump -qns 0 -X -r {} 2>&1 | grep 'IS-IS, p2p IIH' | rev | cut -d ' ' -f 1 | rev | sort -u".format(pcap_path)
    return duthost.shell(shell_cmd)

def test_padding_on(duthosts, rand_one_dut_hostname, enum_frontend_asic_index):
    output = stop_pushconfig_start_pcap(duthosts, rand_one_dut_hostname, enum_frontend_asic_index, "ENABLE")
    for pktLen in output['stdout_lines']:
        logger.info(pktLen)
        assert EXPECTED_PADDING_PACKET_LENGTH == pktLen, "Hello packet is less then default full MTU {}".format(DEFAULT_MTU)
    
def test_padding_off(duthosts, rand_one_dut_hostname, enum_frontend_asic_index):
    output = stop_pushconfig_start_pcap(duthosts, rand_one_dut_hostname, enum_frontend_asic_index, 'DISABLE')

    non_padding = False;
    for pktLen in output['stdout_lines']:
        if (EXPECTED_PADDING_PACKET_LENGTH != pktLen):
            non_padding = True;

    assert non_padding, "There should some hello packets are less then default full MTU {}".format(DEFAULT_MTU)