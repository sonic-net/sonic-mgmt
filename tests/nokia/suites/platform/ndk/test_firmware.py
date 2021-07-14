import pytest
import logging

# from srltest.library import test_log

# pytestmark_config_check = pytest.mark.srl_skip_config_check
# pytestmark_skip_fib_agent = pytest.mark.srl_skip_fib_agent
# pytestmark = pytest.mark.register(level='regular', owner='falodiya')

import platform_ndk.platform_ndk_pb2 as platform_ndk_pb2
import platform_ndk.platform_ndk_pb2_grpc as platform_ndk_pb2_grpc
from ndk_common import get_expecetd_data, generate_grpc_channel, time_taken_by_api

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('ndk')
]


class TestFirmware(object):
    """Test firmware service"""
    HW_FIRMWARE_LIST = [platform_ndk_pb2.HW_FIRMWARE_DEVICE_BIOS,
                        platform_ndk_pb2.HW_FIRMWARE_DEVICE_FPGA1,
                        platform_ndk_pb2.HW_FIRMWARE_DEVICE_FPGA2]
    expected_data = None
    if expected_data is None:
        expected_data = get_expecetd_data()

    @staticmethod
    def get_firmware_grpc_info(dut):
        """Get firmware grpc info"""
        channel = generate_grpc_channel(dut)
        firmware_stub = platform_ndk_pb2_grpc.FirmwarePlatformNdkServiceStub(channel)
        firmware_info = {
            'channel': channel,
            'firmware_stub': firmware_stub,
        }
        return firmware_info


@time_taken_by_api
def req_hw_firmware_verion(stub, dev_type):
    """Request hw firmware version"""
    response = stub.ReqHwFirmwareVersion(platform_ndk_pb2.ReqHwFirmwareInfoPb(dev_type=dev_type))
    return response.version


@time_taken_by_api
def get_hw_firmware_components(stub):
    """Get hardware firmware components"""
    response = stub.HwFirmwareGetComponents(platform_ndk_pb2.ReqHwFirmwareInfoPb())
    return response.firmware_info.component


def get_expected_firmware_version(dut, cmd):
    """Get response from NDK cli command"""
    response = dut.shell("cat /tmp/pass | /opt/srlinux/bin/sr_platform_ndk_cli -w -c '{}'"
                         .format(cmd))
    data = response['stdout']
    return data


def test_req_hw_firmware_version(duthosts):
    """Test request hardware version"""
    msg_list = list()
    for dut in duthosts.nodes:
        try:
            grpc_info = TestFirmware.get_firmware_grpc_info(dut)
            response_data = get_expected_firmware_version(dut, 'DeviceMgr::DbgFirmwareVersion')
            for dev_type in TestFirmware.HW_FIRMWARE_LIST:
                firmware_version = req_hw_firmware_verion(grpc_info.get('firmware_stub'), dev_type)
                if firmware_version == 'Default version':
                    continue
                logging.info('Firmware version on dut {} is {} for dev type {}'
                             .format(dut.hostname, firmware_version, dev_type))
                if firmware_version not in response_data:
                    msg = 'Firmware version on dut {} is {}, expected was {}'\
                        .format(dut.hostname, firmware_version, response_data)
                    msg_list.append(msg)
                logging.info('Firmware version on dut {} is {}, expected was {}'
                             .format(dut.hostname, firmware_version, response_data))
        finally:
            grpc_info.get('channel').close()

    if len(msg_list):
        pytest.fail(msg_list)
