import pytest
import logging
import time
import random
# from srltest.library import test_log

# pytestmark_config_check = pytest.mark.srl_skip_config_check
# pytestmark_skip_fib_agent = pytest.mark.srl_skip_fib_agent
# pytestmark = pytest.mark.register(level='regular', owner='falodiya')

import platform_ndk.platform_ndk_pb2 as platform_ndk_pb2
import platform_ndk.platform_ndk_pb2_grpc as platform_ndk_pb2_grpc
from ndk_common import get_expecetd_data, generate_grpc_channel, get_ndk_cli_response, time_taken_by_api
from test_chassis import TestChassis


pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('ndk')
]


class TestThermal(object):
    """Test Thermal service"""
    invalid_temp = [-128, 127]
    delta = 5
    expected_data = None
    if expected_data is None:
        expected_data = get_expecetd_data()

    @staticmethod
    def get_thermal_grpc_info(dut):
        """Get thermal grpc info"""
        channel = generate_grpc_channel(dut)
        thermal_stub = platform_ndk_pb2_grpc.ThermalPlatformNdkServiceStub(channel)
        thermal_info = {
            'channel': channel,
            'thermal_stub': thermal_stub,
        }
        return thermal_info

@time_taken_by_api
def set_thermal_asic_info(stub,name, temp, threshold):
    """Set thermal asic info"""
    logging.info("Setting thermal asic info")
    asic_entry = platform_ndk_pb2.AsicTempPb.AsicTempDevicePb(name=name, current_temp=temp, threshold=threshold)
    asic_devices = []
    asic_devices.append(asic_entry)
    asic_temp_all = platform_ndk_pb2.AsicTempPb(temp_device = asic_devices)
    stub.SetThermalAsicInfo(platform_ndk_pb2.ReqTempParamsPb(asic_temp=asic_temp_all))


@time_taken_by_api
def get_thermal_asic_info(stub):
    """Get thermal asic info"""
    response = stub.GetThermalAsicInfo(platform_ndk_pb2.ReqTempParamsPb())
    return response.asic_temp_devices.temp_device

@time_taken_by_api
def get_thermal_devices_info(stub):
    """Get thermal devices info"""
    response = stub.GetThermalDevicesInfo(platform_ndk_pb2.ReqTempParamsPb())
    return response.temp_devices.temp_device


@time_taken_by_api
def get_thermal_curr_temp(stub, index):
    """Get thermal current temperature"""
    response = stub.GetThermalCurrTemp(platform_ndk_pb2.ReqTempParamsPb(idx=index))
    return response.curr_temp


@time_taken_by_api
def get_thermal_min_temp(stub, index):
    """Get thermal min temperature"""
    response = stub.GetThermalMinTemp(platform_ndk_pb2.ReqTempParamsPb(idx=index))
    return response.min_temp


@time_taken_by_api
def get_thermal_max_temp(stub, index):
    """Get thermal max temperature"""
    response = stub.GetThermalMaxTemp(platform_ndk_pb2.ReqTempParamsPb(idx=index))
    return response.max_temp


@time_taken_by_api
def get_thermal_low_threshold(stub, index):
    """Get thermal low threshold"""
    response = stub.GetThermalLowThreshold(platform_ndk_pb2.ReqTempParamsPb(idx=index))
    return response.low_threshold


@time_taken_by_api
def get_thermal_high_threshold(stub, index):
    """Get thermal high threshold"""
    response = stub.GetThermalHighThreshold(platform_ndk_pb2.ReqTempParamsPb(idx=index))
    return response.high_threshold


@time_taken_by_api
def update_temp_info(stub, slot, current_temp, min_temp, max_temp, margin):
    """Update temp info"""
    update_hwslot_temp = platform_ndk_pb2.UpdateTempInfoPb(slot_num=slot, current_temp=current_temp,
                                                            min_temp=min_temp, max_temp=max_temp, margin=margin)
    response = stub.UpdateThermalHwSlot(platform_ndk_pb2.ReqTempParamsPb(hwslot_temp=update_hwslot_temp))
    return response


def get_dut_hwsku(dut):
    """Gets dut hwsku"""
    expected_dut_data = TestThermal.expected_data.get(dut)
    return expected_dut_data.get('card_hwsku')


def get_expected_thermal_data(dut):
    """Gets expected thermal data"""
    expected_dut_data = TestThermal.expected_data.get(dut)
    chassis_type = expected_dut_data.get('chassis_type')
    card_hwsku = expected_dut_data.get('card_hwsku')
    if 'card_data' in expected_dut_data:
        expected_thermal_data = TestThermal.expected_data.get(chassis_type).get(expected_dut_data.get('card_data'))
    else:
        expected_thermal_data = TestThermal.expected_data.get(chassis_type).get(card_hwsku)
    return expected_thermal_data


def get_online_sfm(dut):
    sfm_online = list()
    sfms = TestThermal.expected_data.get(dut).get('fabric')
    for sfm in sfms.keys():
        if sfms[sfm].get("status") == 'Online':
            sfm_online.append(sfm)

    return sfm_online


def get_expected_thermal_sfm(dut):
    """Gets expected sfm thermal"""
    if 'cpm' in get_dut_hwsku(dut):
        expected_thermal_data = get_expected_thermal_data(dut)
        expected_thermal_sfm = expected_thermal_data.get('max_sfm_num')
        thermal_per_sfm = expected_thermal_data.get('num_thermal_per_sfm')
        sfm_online = get_online_sfm(dut)
        expected_total_sfm = len(sfm_online) * thermal_per_sfm
        logging.info('Expected number of sfm thermal on {} is {}'.format(dut, expected_total_sfm))
        return expected_total_sfm
    else:
        return 0


def get_expected_temp_thermal(dut):
    """Gets expected tem thermal"""
    expected_thermal_data = get_expected_thermal_data(dut)
    logging.info('Expected temp thermal num on dut {} is {}'.format(dut,
                                                                    expected_thermal_data.get('max_temp_thermal_num')))
    max_thermal_num = expected_thermal_data.get('max_temp_thermal_num')
    return max_thermal_num


def get_total_expected_thermal(dut):
    """Get total expected thermal on a dut"""
    total_temp_thermal = get_expected_temp_thermal(dut)
    total_sfm_thermal = get_expected_thermal_sfm(dut)
    logging.info('Total expected thermal on dut {} are {}'.format(dut, (total_temp_thermal + total_sfm_thermal)))

    return total_temp_thermal + total_sfm_thermal


def get_thermal_index_name_map(stub):
    """Get expected current temp"""
    index_name_map = dict()
    device_thermal_info = get_thermal_devices_info(stub)
    for thermal_info in device_thermal_info:
        sensor_name = thermal_info.sensor_name
        index_name_map[thermal_info.device_idx] = sensor_name
    return index_name_map


def get_expected_cur_temp(response_data, name):
    """Get expected cur temp"""
    for data in response_data:
        if data.get('name') == name:
            if data.get('remote_sensor'):
                return data.get('remote')
            return data.get('local')


def get_hwslot_thermal_info(stub, hw_slot):
    """Get thermal info of a hw slot"""
    response = stub.ShowThermalInfo(platform_ndk_pb2.ReqTempParamsPb())
    summary_list = response.temp_show.temp_summary
    for summary in summary_list:
        if summary.slot_num == hw_slot:
            return summary.current_temp, summary.min_temp, summary.max_temp, summary.margin


def get_expected_threshold(response_data, name, threshold='low'):
    for data in response_data:
        if data.get('sensor_name') == name:
            if threshold == 'low':
                return data.get('min_threshold')
            return data.get('max_threshold')

def get_expected_curr_asic_temp(response_data, name):
    for data in response_data:
        if data.get('sensor_name') == name:
            return data.get('current_temp')

def test_thermal_device_info(duthosts):
    """Test thermal devices info"""
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = TestThermal.get_thermal_grpc_info(dut)
        device_thermal_info = get_thermal_devices_info(grpc_info.get('thermal_stub'))
        logging.info('Device thermal info on dut {} is {}'.format(dut.hostname, device_thermal_info))
        total_thermal = get_total_expected_thermal(dut.hostname)
        try:
            if len(device_thermal_info) != total_thermal:
                msg = 'Number of thermal returned by API on dut {} are {}, Expected was {}'\
                    .format(dut.hostname, len(device_thermal_info), total_thermal)
                msg_list.append(msg)
            logging.info('Number of thermal returned by API on dut {} are {}, Expected {}'
                         .format(dut.hostname, len(device_thermal_info), total_thermal))
        finally:
            grpc_info.get('channel').close()
    if len(msg_list):
        pytest.fail(msg_list)


def test_get_thermal_curr_temp(duthosts):
    """Test get thermal current temp"""
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = TestThermal.get_thermal_grpc_info(dut)
        index_name_map = get_thermal_index_name_map(grpc_info.get('thermal_stub'))
        total_thermal = get_total_expected_thermal(dut.hostname)
        index_name_map_keys = index_name_map.keys()
        try:
            for index in range(total_thermal):
                thermal_cur_temp = get_thermal_curr_temp(grpc_info.get('thermal_stub'), index)
                response_data = get_ndk_cli_response(dut, 'displayTempsVerticalJson 1')
                expected_curr_temp = get_expected_cur_temp(response_data, index_name_map[index_name_map_keys[index]])
                if (expected_curr_temp + 1) <= thermal_cur_temp <= (expected_curr_temp - 1):
                        msg = 'Thermal current temp return by API is {} on {}, Expected was {} for thermal {}'\
                            .format(thermal_cur_temp, dut.hostname, expected_curr_temp, index_name_map[index_name_map_keys[index]])
                        msg_list.append(msg)
                logging.info('Thermal temp returned by API is {} on dut {}, Expected {} for thermal {}'
                             .format(thermal_cur_temp, dut.hostname, expected_curr_temp, index_name_map[index_name_map_keys[index]]))
        finally:
            grpc_info.get('channel').close()
    if len(msg_list):
        pytest.fail(msg_list)


def test_get_thermal_min_temp(duthosts):
    """Test get thermal min temp"""
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = TestThermal.get_thermal_grpc_info(dut)
        total_thermal = get_total_expected_thermal(dut.hostname)
        try:
            for index in range(total_thermal):
                thermal_min_temp = get_thermal_min_temp(grpc_info.get('thermal_stub'), index)
                if thermal_min_temp in TestThermal.invalid_temp:
                    continue
                thermal_cur_temp = get_thermal_curr_temp(grpc_info.get('thermal_stub'), index)
                if thermal_min_temp > thermal_cur_temp:
                    msg = 'Min thermal temp on dut {} at index {} is {}, which is more than current temp {}'\
                        .format(dut.hostname, index, thermal_min_temp, thermal_cur_temp)
                    msg_list.append(msg)
                logging.info('Min thermal temp on dut {} at index {} is {}, current temp is {}'
                             .format(dut.hostname, index, thermal_min_temp, thermal_cur_temp))

        finally:
            grpc_info.get('channel').close()

    if len(msg_list):
        pytest.fail(msg_list)


def test_get_thermal_max_temp(duthosts):
    """Test get thermal max temp"""
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = TestThermal.get_thermal_grpc_info(dut)
        total_thermal = get_total_expected_thermal(dut.hostname)
        try:
            for index in range(total_thermal):
                thermal_max_temp = get_thermal_max_temp(grpc_info.get('thermal_stub'), index)
                if thermal_max_temp in TestThermal.invalid_temp:
                    continue
                thermal_cur_temp = get_thermal_curr_temp(grpc_info.get('thermal_stub'), index)
                if thermal_max_temp < thermal_cur_temp:
                    msg = 'Max thermal temp on dut {} at index {} is {}, which is less than current temp {}'\
                        .format(dut.hostname, index, thermal_max_temp, thermal_cur_temp)
                    msg_list.append(msg)
                logging.info('Max thermal temp on dut {} at index {} is {}, current temp is {}'
                             .format(dut.hostname, index, thermal_max_temp, thermal_cur_temp))

        finally:
            grpc_info.get('channel').close()

    if len(msg_list):
        pytest.fail(msg_list)


def test_get_thermal_low_threshold(duthosts):
    """Get thermal low threshold"""
    msg_list = list()
    for dut in duthosts.nodes:
        response_data = get_ndk_cli_response(dut, 'TempSensorMgr::DisplayTempThresholdsJson')
        grpc_info = TestThermal.get_thermal_grpc_info(dut)
        index_name_map = get_thermal_index_name_map(grpc_info.get('thermal_stub'))
        total_thermal = get_total_expected_thermal(dut.hostname)
        index_name_map_keys = index_name_map.keys()
        try:
            for index in range(total_thermal):
                thermal_index_from_map = index_name_map_keys[index]
                thermal_low_threshold = get_thermal_low_threshold(grpc_info.get('thermal_stub'), thermal_index_from_map)
                logging.info('Thermal low threshold temp on dut {} is {}'.format(dut.hostname, thermal_low_threshold))
                expected_low_threshold = get_expected_threshold(response_data, index_name_map[thermal_index_from_map])
                if thermal_low_threshold != expected_low_threshold:
                    msg = 'Thermal low threshold on dut {} at index {} is {}, Expecetd was {}' \
                        .format(dut.hostname, index, thermal_low_threshold, expected_low_threshold)
                    msg_list.append(msg)
                logging.info('Thermal low threshold on dut {} at index {} is {}, Expected {}'
                             .format(dut.hostname, index, thermal_low_threshold, expected_low_threshold))

        finally:
            grpc_info.get('channel').close()
    if len(msg_list):
        pytest.fail(msg_list)


def test_get_thermal_high_threshold(duthosts):
    """Tests get thermal high threshold"""
    msg_list = list()
    for dut in duthosts.nodes:
        response_data = get_ndk_cli_response(dut, 'TempSensorMgr::DisplayTempThresholdsJson')
        grpc_info = TestThermal.get_thermal_grpc_info(dut)
        index_name_map = get_thermal_index_name_map(grpc_info.get('thermal_stub'))
        total_thermal = get_total_expected_thermal(dut.hostname)
        index_name_map_keys = index_name_map.keys()
        try:
            for index in range(total_thermal):
                thermal_index_from_map = index_name_map_keys[index]
                thermal_high_threshold = get_thermal_high_threshold(grpc_info.get('thermal_stub'), thermal_index_from_map)
                logging.info('Thermal high threshold temp on dut {} is {}'.format(dut.hostname, thermal_high_threshold))
                expected_high_threshold = get_expected_threshold(response_data, index_name_map[thermal_index_from_map], threshold='high')
                if thermal_high_threshold != expected_high_threshold:
                    msg = 'Thermal high threshold on dut {} at index {} is {}, Expecetd was {}' \
                        .format(dut.hostname, index, thermal_high_threshold, expected_high_threshold)
                    msg_list.append(msg)
                logging.info('Thermal high threshold on dut {} at index {} is {}, Expected {}'
                             .format(dut.hostname, index, thermal_high_threshold, expected_high_threshold))

        finally:
            grpc_info.get('channel').close()

    if len(msg_list):
        pytest.fail(msg_list)


def test_update_thermal_hw_slot(duthosts):
    """Test thermal hw_slot"""
    msg_list = list()
    for dut in duthosts.supervisor_nodes:
        grpc_info = TestThermal.get_thermal_grpc_info(dut)
        chassis_grpc_info = TestChassis.get_chassis_grpc_info(dut)
        try:
            hw_slot_list = TestChassis.get_module_hw_slot(chassis_grpc_info.get('chassis_stub'),
                                                          module_type='HW_MODULE_TYPE_LINE')
            for hw_slot in hw_slot_list:
                if (TestChassis.get_module_status(chassis_grpc_info.get('chassis_stub'),
                                                  'HW_MODULE_TYPE_LINE', hw_slot)) != 'Online':
                    continue
                before_test_thermal_info = None
                try:
                    before_test_thermal_info = get_hwslot_thermal_info(grpc_info.get('thermal_stub'),
                                                                       hw_slot)
                    logging.info('Before test thermal info {} on dut {} for hw_slot {}'
                                 .format(before_test_thermal_info, dut.hostname, hw_slot))
                    set_curr_temp = before_test_thermal_info[0] + TestThermal.delta
                    if before_test_thermal_info[1] not in TestThermal.invalid_temp:
                        set_min_temp = before_test_thermal_info[1] + TestThermal.delta
                    else:
                        set_min_temp = before_test_thermal_info[1]
                    set_max_temp = before_test_thermal_info[2] + TestThermal.delta
                    set_margin = before_test_thermal_info[3] + TestThermal.delta
                    update_temp_info(grpc_info.get('thermal_stub'), hw_slot, set_curr_temp,
                                     set_min_temp, set_max_temp, set_margin)
                    time.sleep(3)
                    after_test_thermal_info = get_hwslot_thermal_info(grpc_info.get('thermal_stub'),
                                                                      hw_slot)
                    logging.info('After test thermal info {} on dut {} for hw_slot {}'
                                 .format(after_test_thermal_info, dut.hostname, hw_slot))

                    if after_test_thermal_info != (set_curr_temp, set_min_temp, set_max_temp, set_margin):
                        msg = 'Thermal info after changes are {} for hw_slot {} on dut {}, expected was {}'\
                            .format(after_test_thermal_info, hw_slot, dut.hostname,
                                    (set_curr_temp, set_min_temp, set_max_temp, set_margin))
                        msg_list.append(msg)
                    logging.info('Thermal info after changes are {} for hw_slot {} on dut {}, expected was {}'
                                 .format(after_test_thermal_info, hw_slot, dut.hostname,
                                         (set_curr_temp, set_min_temp, set_max_temp, set_margin)))
                finally:
                    update_temp_info(grpc_info.get('thermal_stub'), hw_slot, before_test_thermal_info[0],
                                     before_test_thermal_info[1], before_test_thermal_info[2],
                                     before_test_thermal_info[3])
            if len(msg_list):
                pytest.fail(msg_list)
        finally:
            grpc_info.get('channel').close()
            chassis_grpc_info.get('channel').close()


def test_get_thermal_asic_info(duthosts):
    msg_list = list()
    try:
        for duthost in duthosts.frontend_nodes:
            grpc_info = TestThermal.get_thermal_grpc_info(duthost)
            thermal_asic_info = get_thermal_asic_info(grpc_info.get('thermal_stub'))
            response_data = get_ndk_cli_response(duthost, 'displayTempsVerticalJson 1')
            for i in range(len(thermal_asic_info)):
                for j in range(len(response_data)):
                    if response_data[j]['name'] == thermal_asic_info[i].name:
                        if not (response_data[j]['remote'])-2 <= thermal_asic_info[i].current_temp <= (response_data[j]['remote'])+2:
                            msg = 'asic_name={}, Expected current_temp = {}, Actual current_temp = {}'.format(thermal_asic_info[i].name, response_data[j]['remote'], thermal_asic_info[i].current_temp)
                            msg_list.append(msg)
                        elif not thermal_asic_info[i].threshold == response_data[j]['remote_threshold']:
                            msg = 'asic_name={}, Expected threshold = {}, Actual threshold = {}'.format(thermal_asic_info[i].name, response_data[j]['remote_threshold'], thermal_asic_info[i].threshold)
                            msg_list.append(msg)
                        else:
                            logging.info("Thermal Asic Info: Asic name: {}, current_temp= {}, threshold = {}".format(thermal_asic_info[i].name, thermal_asic_info[i].current_temp, thermal_asic_info[i].threshold))
                        break
        if len(msg_list):
            logging.info(msg_list)
            pytest.fail(msg_list)
    finally:
        grpc_info.get('channel').close()


def test_set_thermal_asic_info(duthosts):
    msg_list = list()
    try:
        for duthost in duthosts.frontend_nodes:
            grpc_info = TestThermal.get_thermal_grpc_info(duthost)
            pre_thermal_asic_info = get_thermal_asic_info(grpc_info.get('thermal_stub'))
            pre_response_data = get_ndk_cli_response(duthost, 'displayTempsVerticalJson 1')
            for i in range(len(pre_thermal_asic_info)):
                for j in range(len(pre_response_data)):
                    if pre_thermal_asic_info[i].name == pre_response_data[j]['name']:
                        set_temp = random.randint(0,pre_thermal_asic_info[i].threshold)
                        set_thermal_asic_info(grpc_info.get('thermal_stub'),pre_thermal_asic_info[i].name, set_temp, pre_thermal_asic_info[i].threshold)
                        post_thermal_asic_info = get_thermal_asic_info(grpc_info.get('thermal_stub'))
                        post_response_data = get_ndk_cli_response(duthost, 'displayTempsVerticalJson 1')
                        if not post_thermal_asic_info[i].current_temp == set_temp:
                            msg = 'Asic {}, current temp expected to be set to {}. Actual value: {}'.format(
                                post_thermal_asic_info[i].name, set_temp, post_response_data[j]['remote'] )
                            msg_list.append(msg)
                        else:
                            logging.info("Asic {}. Current temp successfully set to {}".format(post_thermal_asic_info[i].name,post_response_data[j]['remote']))

        if len(msg_list):
            pytest.fail(msg_list)
    finally:
        grpc_info.get('channel').close()