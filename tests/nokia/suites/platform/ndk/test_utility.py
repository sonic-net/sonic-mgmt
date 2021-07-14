import pytest
import logging
import re

# from srltest.library import logging

# pytestmark_config_check = pytest.mark.srl_skip_config_check
# pytestmark_skip_fib_agent = pytest.mark.srl_skip_fib_agent
# pytestmark = pytest.mark.register(level='regular', owner='falodiya')

import platform_ndk.platform_ndk_pb2 as platform_ndk_pb2
import platform_ndk.platform_ndk_pb2_grpc as platform_ndk_pb2_grpc
from ndk_common import generate_grpc_channel, get_expecetd_data, get_expected_hwsku_data, time_taken_by_api

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('ndk')
]

class TestUtility(object):
    """Test Utility service"""
    FILEPATH = '/tmp/admin_tech'
    expected_data = None
    if expected_data is None:
        expected_data = get_expecetd_data()

    @staticmethod
    def get_sfm_grpc_info(dut):
        """Get sfm platform_ndk info"""
        channel = generate_grpc_channel(dut)
        sfm_stub = platform_ndk_pb2_grpc.UtilPlatformNdkServiceStub(channel)
        sfm_info = {
            'channel': channel,
            'sfm_stub': sfm_stub,
        }
        return sfm_info

    @staticmethod
    def get_sfm_info(stub):
        """Get sfm info"""
        sfm_type = platform_ndk_pb2.ReqSfmOpsType.SFM_OPS_SHOW_SUMMARY
        response = stub.ReqSfmInfo(platform_ndk_pb2.ReqSfmInfoPb(type=sfm_type))
        return response.sfm_summary.sfm_info

    @staticmethod
    @time_taken_by_api
    def get_imm_info(stub, imm_slot):
        """Get imm info"""
        imm_type = platform_ndk_pb2.ReqSfmOpsType.SFM_OPS_SHOW_IMMLINKS
        response = stub.ReqSfmInfo(platform_ndk_pb2.ReqSfmInfoPb(type=imm_type, imm_slot=imm_slot))
        return response.sfm_summary.sfm_info

    @staticmethod
    @time_taken_by_api
    def get_sfm_imm_total_links(stub, imm_slot):
        """Get total sfm imm links"""
        imm_type = platform_ndk_pb2.ReqSfmOpsType.SFM_OPS_SHOW_IMMLINKS
        response = stub.ReqSfmInfo(platform_ndk_pb2.ReqSfmInfoPb(type=imm_type, imm_slot=imm_slot))
        return response.sfm_imm_info.total_links


@time_taken_by_api
def request_admin_tech(stub, filepath):
    """Request admin tech"""
    stub.ReqAdminTech(platform_ndk_pb2.ReqAdminTechPb(admintech_path=filepath))


def test_get_sfm_info(duthosts):
    """Test get sfm info API"""
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = TestUtility.get_sfm_grpc_info(dut)
        try:
            sfm_info_list = TestUtility.get_sfm_info(grpc_info.get('sfm_stub'))
            for sfm in sfm_info_list:
                if sfm.is_initialized == sfm.failed and sfm.presence:
                    msg = ('Sfm presence is {} but sfm is_initialized {} and sfm failed {} on dut {} are same,'
                           ' Expected if sfm is initialized should not be failed.'
                           .format(sfm.presence, sfm.is_initialized, sfm.failed, dut.hostname))
                    msg_list.append(msg)
                if sfm.presence != sfm.is_initialized:
                    if sfm.presence != sfm.failed:
                       msg = ('Sfm presence is {} but sfm is_initialized {} on dut {},' 
                              ' Expected was should be same'.format(sfm.presence, sfm.is_initialized, dut.hostname))
                       msg_list.append(msg)
                logging.info('Sfm presenec is {}, sfm is_initialized is {} on dut {}'
                             .format(sfm.presence, sfm.is_initialized, dut.hostname))
        finally:
            grpc_info.get('channel').close()
    if len(msg_list):
        pytest.fail(msg_list)


def test_get_imm_slot_info(duthosts):
    """Test get sfm imm slot info"""
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = TestUtility.get_sfm_grpc_info(dut)
        try:
            max_line_num = get_expected_hwsku_data(dut.hostname, TestUtility.expected_data, 'max_line_num')
            for slot in range(1, (max_line_num+1)):
                total_sfm_imm_links = TestUtility.get_sfm_imm_total_links(grpc_info.get('sfm_stub'), imm_slot=slot)
                expected_sfm_imm_links = get_expected_hwsku_data(dut.hostname,
                                                                 TestUtility.expected_data, 'total_sfm_imm_links')
                if total_sfm_imm_links != expected_sfm_imm_links:
                    msg = 'SFM IMMM links returned by API {} is not same as expected {} on dut {}'\
                        .format(total_sfm_imm_links, expected_sfm_imm_links, dut.hostname)
                    msg_list.append(msg)
                logging.info('SFM IMM links returned by API is {}, expected was {} on dut {}'
                             .format(total_sfm_imm_links, expected_sfm_imm_links, dut.hostname))
        finally:
            grpc_info.get('channel').close()
    if len(msg_list):
        pytest.fail(msg_list)


def test_req_admin_tech(duthosts):
    """Test request admin tech"""
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = TestUtility.get_sfm_grpc_info(dut)
        try:
            dut.shell('sudo rm -rf {}'.format(TestUtility.FILEPATH))
            request_admin_tech(grpc_info.get('sfm_stub'), TestUtility.FILEPATH)
            new_filepath = '{}.txt'.format(TestUtility.FILEPATH)
            res = dut.shell('du {}'.format(new_filepath))
            if re.match('^0\s+', res['stdout']):
                msg = 'Request admin tech did not generates tech data on dut {}, size of the file is {}'\
                    .format(dut.hostname, res['stdout'])
                msg_list.append(msg)

            logging.info('Request admin tech generated tech logs on dut {}, size of the file is {}'
                         .format(dut.hostname, res['stdout']))

        finally:
            grpc_info.get('channel').close()

    if len(msg_list):
        pytest.fail(msg_list)
