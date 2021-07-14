import pytest
import random
import logging
from tests.common.fixtures.duthost_utils import shutdown_ebgp

# from srltest.library import logging

# pytestmark_config_check = pytest.mark.srl_skip_config_check
# pytestmark_skip_fib_agent = pytest.mark.srl_skip_fib_agent
# pytestmark = pytest.mark.register(level='regular', owner='falodiya')
import json
import platform_ndk.platform_ndk_pb2 as platform_ndk_pb2
import platform_ndk.platform_ndk_pb2_grpc as platform_ndk_pb2_grpc
from ndk_common import generate_grpc_channel, get_component_expecetd_data_dict,\
    get_expecetd_data, get_expected_hwsku_data, time_taken_by_api

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('ndk')
]

class TestSfp(object):
    """Test SFP service"""
    expected_data = None
    if expected_data is None:
        expected_data = get_expecetd_data()

    @staticmethod
    @time_taken_by_api
    def is_xcvr_dac(stub, index):
        """Get connection type of sfp"""
        op_type_1 = platform_ndk_pb2.ReqSfpJSONOpsType.SFP_JSON_OPS_DATA
        response = stub.GetSfpInfoJSON(platform_ndk_pb2.ReqSfpJSONOpsPb(type=op_type_1, hw_port_id_begin=index, hw_port_id_end=index))
        res = json.loads(response.data)
        if res['data_info'] and res['data_info'][0]['connector_type'] == 'NO_SEPARABLE_CONNECTOR':
            return True
        return False



    @staticmethod
    @time_taken_by_api
    def get_num_of_sfp(stub):
        """Get number of sfp"""
        response = stub.GetSfpNumAndType(platform_ndk_pb2.ReqSfpOpsPb())
        return response.sfp_num_type.num_ports

    @staticmethod
    @time_taken_by_api
    def get_sfp_presence(stub, index):
        """Get SDP presence"""
        op_type = platform_ndk_pb2.ReqSfpOpsType.SFP_OPS_REQ_PRESENCE
        response = stub.GetSfpPresence(platform_ndk_pb2.ReqSfpOpsPb(type=op_type,
                                                                    hw_port_id_begin=index))
        return response.sfp_status.status


    @staticmethod
    def get_sfp_grpc_info(dut):
        """Get sfp platform_ndk info"""
        channel = generate_grpc_channel(dut)
        sfp_stub = platform_ndk_pb2_grpc.XcvrPlatformNdkServiceStub(channel)
        sfp_info = {
            'channel': channel,
            'sfp_stub': sfp_stub,
        }
        return sfp_info

    @staticmethod
    def validate_sfp_on_dut(sfp_num, dut):
        """validate dut has sfp"""
        expected_sfp_num = get_expected_hwsku_data(dut, TestSfp.expected_data, 'num_sfp')
        if sfp_num == 0 and expected_sfp_num == 0:
            logging.info('Dut {} does not have sfp'.format(dut))
            return False
        if sfp_num != expected_sfp_num:
            pytest.fail('Number of sfp present on dut {} are {}, Expected was {}'
                        .format(dut, sfp_num, expected_sfp_num))

        logging.info('Number of sfp present on dut {} are {}'.format(dut, sfp_num))
        return True

def compare_response_and_expected_data(actual_data, expected_data, index, dut, key=None):
    """Compare actual data with expected data"""
    failed = False
    msg = ""
    if actual_data != expected_data:
        msg = 'Actual {} {}, Expected was {} for index {} on dut {}'\
            .format(key, actual_data, expected_data, index, dut)
        failed = True

    logging.info('Actual sfp {} is {}, Expected {} for index {} on dut {}'
                  .format(key, actual_data, expected_data, index, dut))
    return failed, msg

def get_sfp_status(stub, index):
    """Get sfp status"""
    pass


@time_taken_by_api
def get_sfp_multi_port_presence(stub, start_index, end_index):
    """Get multi port sfp presence"""
    op_type = platform_ndk_pb2.ReqSfpOpsType.SFP_OPS_GET_MPORT_STATUS
    response = stub.GetSfpPresence(platform_ndk_pb2.ReqSfpOpsPb(type=op_type,
                                                                hw_port_id_begin=start_index,
                                                                hw_port_id_end=end_index))
    sfp_mstatus = response.sfp_mstatus.port_status
    return sfp_mstatus


@time_taken_by_api
def reqest_sfp_reset(stub, index):
    """Reqest sfp reset"""
    op_type = platform_ndk_pb2.ReqSfpOpsType.SFP_OPS_NORMAL
    response = stub.ReqSfpReset(platform_ndk_pb2.ReqSfpOpsPb(type=op_type,
                                                             hw_port_id_begin=index))
    return response


@time_taken_by_api
def get_sfp_reset_status(stub, index):
    """Get sfp reset status"""
    op_type = platform_ndk_pb2.ReqSfpOpsType.SFP_OPS_NORMAL
    response = stub.GetSfpResetStatus(platform_ndk_pb2.ReqSfpOpsPb(type=op_type,
                                                                   hw_port_id_begin=index))
    return response


@time_taken_by_api
def request_sfp_lp_mode(stub, index, mode):
    """Request reset sf lp mode """
    op_type = platform_ndk_pb2.ReqSfpOpsType.SFP_OPS_NORMAL
    if mode:
        lpmode = 1
    else:
        lpmode = 0
    response = stub.ReqSfpLPMode(platform_ndk_pb2.ReqSfpOpsPb(type=op_type,
                                                              hw_port_id_begin=index, val=lpmode))
    return response.sfp_status.status


@time_taken_by_api
def get_sfp_lp_mode_status(stub, index):
    """Get sfp lp mode status"""
    op_type = platform_ndk_pb2.ReqSfpOpsType.SFP_OPS_NORMAL
    response = stub.GetSfpLPStatus(platform_ndk_pb2.ReqSfpOpsPb(type=op_type,
                                                                hw_port_id_begin=index))
    return response.sfp_status.status


def get_sfp_lp_mode_response_status(stub, index):
    """Get sfp lp mode response status"""
    op_type = platform_ndk_pb2.ReqSfpOpsType.SFP_OPS_NORMAL
    response = stub.GetSfpLPStatus(platform_ndk_pb2.ReqSfpOpsPb(type=op_type,
                                                                hw_port_id_begin=index))
    return response.response_status.status_code

"""
(Pdb) response
response_status {
  status_code: NDK_ERR_RESOURCE_NOT_FOUND
}
sfp_status {
}
"""

def test_get_sfp_presence(duthosts, shutdown_ebgp):
    """ Tests SFP presence"""
    # testhandle = duthosts
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = TestSfp.get_sfp_grpc_info(dut)
        dut = dut.hostname
        number_of_sfp = TestSfp.get_num_of_sfp(grpc_info.get('sfp_stub'))
        if not TestSfp.validate_sfp_on_dut(number_of_sfp, dut):
            grpc_info.get('channel').close()
            continue
        try:
            for index in range(1, number_of_sfp+1):
                expected_data = get_component_expecetd_data_dict(TestSfp.expected_data.get(dut),
                                                                 'sfp', index, 'presence')
                if expected_data is None:
                    expected_data = False
                sfp_presence = TestSfp.get_sfp_presence(grpc_info.get('sfp_stub'), index)
                failed, msg = compare_response_and_expected_data(sfp_presence, expected_data, index,
                                                                 dut, key='presence')
                if failed:
                    msg_list.append(msg)
        finally:
            grpc_info.get('channel').close()
    if len(msg_list):
        pytest.fail(msg_list)

def test_get_sfp_status(duthosts, shutdown_ebgp):
    """Tests get sfp status"""
    # testhandle = duthosts
    pass


def test_sfp_mport_presence(duthosts, shutdown_ebgp):
    """Tests Get multi port presence"""
    # testhandle = duthosts
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = TestSfp.get_sfp_grpc_info(dut)
        dut = dut.hostname
        number_of_sfp = TestSfp.get_num_of_sfp(grpc_info.get('sfp_stub'))
        if not TestSfp.validate_sfp_on_dut(number_of_sfp, dut):
            grpc_info.get('channel').close()
            continue
        try:
            start_index = random.choice(range(1, int(number_of_sfp/2)))
            end_index = random.choice(range(int(number_of_sfp/2)+2, number_of_sfp))
            mport_data = get_sfp_multi_port_presence(grpc_info.get('sfp_stub'), start_index, end_index)

            failed, msg = compare_response_and_expected_data(mport_data[0].port_idx, start_index, start_index, dut,
                                               key='multi-port response starts at')
            if failed:
                msg_list.append(msg)
            failed, msg = compare_response_and_expected_data(mport_data[-1].port_idx, end_index, end_index, dut,
                                               key='multi-port response ends at')
            if failed:
                msg_list.append(msg)

            for index in range(start_index, end_index+1):
                expected_data = get_component_expecetd_data_dict(TestSfp.expected_data.get(dut), 'sfp', index, 'presence')
                if expected_data is None:
                    expected_data = False
                sfp_presence = TestSfp.get_sfp_presence(grpc_info.get('sfp_stub'), index)
                failed, msg = compare_response_and_expected_data(sfp_presence, expected_data, index, dut,
                                                                 key='presence')
                if failed:
                    msg_list.append(msg)
        finally:
            grpc_info.get('channel').close()
    if len(msg_list):
        pytest.fail(msg_list)


def test_request_get_sfp_reset(duthosts, shutdown_ebgp):
    """Test Request/get sfp reset"""
    pass
    # As per Marc comments reset is not good
    # testhandle = duthosts
    # for dut in duthosts.nodes:
    #     grpc_info = TestSfp.get_sfp_grpc_info(dut)
    #     dut = dut.hostname
    #     try:
    #         number_of_sfp = TestSfp.get_num_of_sfp(dut)
    #         for index in range(1, number_of_sfp):
    #             # if TestSfp.get_sfp_presence(setup.get('sfp_stub'), index):
    #             # import  ipdb; ipdb.set_trace()
    #             res = reqest_sfp_reset(grpc_info.get('sfp_stub'), index)
    #             logging.info(res)
    #             # response = get_sfp_reset_status(grpc_info.get('sfp_stub'), index)
    #     finally:
    #         grpc_info.get('channel').close()


def test_request_sfp_lp_mode(duthosts, shutdown_ebgp):
    """Test request/get sfp lp mode"""
    # testhandle = duthosts
    pytest.skip("Skipping for now")
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = TestSfp.get_sfp_grpc_info(dut)
        dut = dut.hostname
        number_of_sfp = TestSfp.get_num_of_sfp(grpc_info.get('sfp_stub'))
        if not TestSfp.validate_sfp_on_dut(number_of_sfp, dut):
            grpc_info.get('channel').close()
            continue
        try:
            for index in range(1, number_of_sfp+1):
                pre_lp_mode = None
                if TestSfp.is_xcvr_dac(grpc_info.get('sfp_stub'), index):
                    logging.info("test_request_sfp_lp_mode: Skipping transceiver {} (not supported on this platform)".format(index))
                    continue
                try:
                    pre_lp_mode = get_sfp_lp_mode_status(grpc_info.get('sfp_stub'), index)
                    if pre_lp_mode:
                        set_lp_mode = False
                    else:
                        set_lp_mode = True
                    request_sfp_lp_mode(grpc_info.get('sfp_stub'), index, set_lp_mode)
                    response_status = get_sfp_lp_mode_response_status(grpc_info.get('sfp_stub'), index)
                    post_lp_mode = get_sfp_lp_mode_status(grpc_info.get('sfp_stub'), index)
                    # if sfp is not present, the return sfp lp mode status is same as pre_lp_mode
                    if response_status == 3 and post_lp_mode == pre_lp_mode:
                        logging.info('SFP is not present at index {}'.format(index))
                        # expected sfp_lp_mode would be same as pre_lp_mode
                        set_lp_mode = pre_lp_mode
                    failed, msg = compare_response_and_expected_data(post_lp_mode, set_lp_mode,
                                                                     index, dut, key='lp mode returned by "get lp mode"')
                    if failed:
                        msg_list.append(msg)

                finally:
                    request_sfp_lp_mode(grpc_info.get('sfp_stub'), index, pre_lp_mode)

        finally:
            grpc_info.get('channel').close()
    if len(msg_list):
        pytest.fail(msg_list)