import re
import sys

import pytest
import random
import time
import logging
import json
from test_chassis import TestChassis, get_expected_module_data
from tests.common.fixtures.duthost_utils import shutdown_ebgp


# from srltest.library import logging

# pytestmark_config_check = pytest.mark.srl_skip_config_check
# pytestmark_skip_fib_agent = pytest.mark.srl_skip_fib_agent
# pytestmark = pytest.mark.register(level='regular', owner='falodiya')

import platform_ndk.platform_ndk_pb2 as platform_ndk_pb2
import platform_ndk.platform_ndk_pb2_grpc as platform_ndk_pb2_grpc
from ndk_common import generate_grpc_channel, get_component_expecetd_data_dict, get_expecetd_data,\
    verify_response_is_valid, get_expected_hwsku_data, time_taken_by_api
from tests.conftest import verify_midplane_connectivity, check_midplane_connectivity, verify_midplane_bw, \
    localhost, creds_all_duts

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('ndk')
]

WAIT_TIME = 60
def test_ethmgr_auto_restart(duthosts, shutdown_ebgp, verify_midplane_connectivity):
    """Test etmgr can restart bt itself if killed """
    for duthost in duthosts:
        if duthost.is_supervisor_node():
            output = duthost.shell('pidof eth_switch')
            if output['stdout'] == "":
                pytest.fail('Ethmgr is not running on duthost {}'.format(duthost.hostname))
            logging.info('Ethmgr is running on duthost {} with pid {}'.format(duthost.hostname, output['stdout']))
            logging.info("killing ethmgr process")
            duthost.shell('kill -9 {}'.format(output['stdout']))
            logging.info('Waiting for ethmgr process to start for {}sec.'.format(WAIT_TIME))
            time.sleep(WAIT_TIME)
            output = duthost.shell('pidof eth_switch')
            if output['stdout'] == "":
                pytest.fail('Ethmgr did not start on duthost {} after {}sec'.format(duthost.hostname, WAIT_TIME))

            logging.info('Ethmgr process started on duthost {} after {}sec.'.format(duthost.hostname, WAIT_TIME))
            cmd = "sudo cat /tmp/pass | /opt/srlinux/bin/sr_platform_ndk_cli -w --port 60070 -c ps"
            out = duthost.shell(cmd)
            output = out['stdout_lines']
            logging.info('port status after ethmgr restart is {}'.format(out['stdout_lines']))
            pat = r'xe0.*up'
            pat2 = r'xe1.*up'
            interface_up = False
            for i in range(len(output)):
                if re.search(pat, output[i]):
                    interface_up = True
                    xe0_status = re.search(pat, output[i])
                    logging.info('interface xe0 is up {}.'.format(xe0_status.group()))
            if not interface_up:
                interface_up = False
                pytest.fail('interface xe0 is not up.')

            for i in range(len(output)):
                if re.search(pat2, output[i]):
                    interface_up = True
                    xe1_status = re.search(pat2, output[i])
                    logging.info('interface xe1 is up {}.'.format(xe1_status.group()))

            if not interface_up:
                pytest.fail('interface xe1 is not up.')


def test_devmgr_auto_restart(duthosts, shutdown_ebgp, verify_midplane_connectivity):
    """Test debmgr can restart bt itself if killed """
    for duthost in duthosts:
        time.sleep(30)
        output = duthost.shell('pidof sr_device_mgr')
        if output['stdout'] == "":
            pytest.fail('Devmgr is not running on duthost {}'.format(duthost.hostname))
        logging.info('Devmgr is running on duthost {} with pid {}'.format(duthost.hostname, output['stdout']))
        logging.info("killing device mgr process")
        duthost.shell('kill -9 {}'.format(output['stdout']))
        logging.info('Waiting for devmgr process to start for {}sec.'.format(WAIT_TIME))
        time.sleep(WAIT_TIME)
        output = duthost.shell('pidof sr_device_mgr')
        if output['stdout'] == "":
            pytest.fail('Devmgr did not start on duthost {} after {}sec'.format(duthost.hostname, WAIT_TIME))

        logging.info('Devmgr process started on duthost {} after {}sec.'.format(duthost.hostname, WAIT_TIME))
        cmd = "sudo cat /tmp/pass | /opt/srlinux/bin/sr_platform_ndk_cli -w -c 'Cli::GetVersionJson'"
        out = duthost.shell(cmd)
        logging.info("NDK version running on dut {}: {}".format(duthost, out['stdout']))
        if duthost.is_supervisor_node():
            chassis_grpc_info = TestChassis.get_chassis_grpc_info(duthost)
            hw_slots = TestChassis.get_module_hw_slot(chassis_grpc_info.get('chassis_stub'), 'HW_MODULE_TYPE_FABRIC')
            hw_slot = list(map(int, hw_slots))
            for slot in hw_slot:
                expected_status = get_expected_module_data(duthost.hostname, 'HW_MODULE_TYPE_FABRIC', slot, 'status')
                if expected_status == 'Online':
                    cmd = "cat /tmp/pass | /opt/srlinux/bin/sr_platform_ndk_cli -w -c 'hwPconShowChannelsSfmJson {}'".format(slot - 14)
                    out = duthost.shell(cmd)

                    if out['stdout'] == "":
                        pytest.fail('Sfm info is not displayed after devmgr restart')
                    logging.info("SFM channel info on dut {} after devmgr restart is {}".format(duthost, out['stdout']))


def test_qfpga_auto_restart(duthosts, shutdown_ebgp, verify_midplane_connectivity):
    """Test qfpga mgr can restart bt itself if killed """
    dut_hosts = [duthost for duthost in duthosts if duthost.is_frontend_node()]

    for duthost in dut_hosts:
        time.sleep(30)
        output = duthost.shell('pidof ndk_qfpga_mgr')
        if output['stdout'] == "":
            pytest.fail('Qfpga is not running on duthost {}'.format(duthost.hostname))
        logging.info('Qfpga is running on duthost {} with pid {}'.format(duthost.hostname, output['stdout']))
        logging.info("killing qfpga mgr process")
        duthost.shell('kill -9 {}'.format(output['stdout']))
        logging.info('Waiting for Qfpga process to start for {}sec.'.format(WAIT_TIME))
        time.sleep(WAIT_TIME)
        output = duthost.shell('pidof ndk_qfpga_mgr')
        if output['stdout'] == "":
            pytest.fail('Qfpga mgr did not start on duthost {} after {}sec'.format(duthost.hostname, WAIT_TIME))

        logging.info('Qfpga mgr process started on duthost {} after {}sec.'.format(duthost.hostname, WAIT_TIME))
        cmd = "cat /tmp/pass | /opt/srlinux/bin/sr_platform_ndk_cli -w --port 50067 -c QfpgaJson::show-ports"
        output = duthost.shell(cmd)
        output = json.loads(output['stdout'])
        for port, status in output['Port'].items():
            if port == 'Port1' and status['OperStatus'] != "down":
                pytest.fail('The oper status of Port1 is {}, Expected was down'.format(status['OperStatus']))
            if port != 'Port1' and status['OperStatus'] != "up":
                pytest.fail('The oper status of Port {} is {}, Expected was up'.format(port,status['OperStatus']))
            logging.info('The oper status of Port {} is {}.'.format(port,status['OperStatus']))




