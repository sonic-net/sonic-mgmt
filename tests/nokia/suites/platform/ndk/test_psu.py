import pytest
import logging

# from srltest.library import logging
from ndk_common import generate_grpc_channel, get_component_expecetd_data_dict,\
    get_expecetd_data, get_expected_hwsku_data

# pytestmark_config_check = pytest.mark.srl_skip_config_check
# pytestmark_skip_fib_agent = pytest.mark.srl_skip_fib_agent
# pytestmark = pytest.mark.register(level='regular', owner='falodiya')

import platform_ndk.platform_ndk_pb2 as platform_ndk_pb2
import platform_ndk.platform_ndk_pb2_grpc as platform_ndk_pb2_grpc
from ndk_common import time_taken_by_api

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('ndk')
]

class TestPsu(object):
    """Psu service"""
    expected_data = None
    if expected_data is None:
        expected_data = get_expecetd_data()

    @staticmethod
    @time_taken_by_api
    def get_psu_num(stub):
        """Get number of psu"""
        response = stub.GetPsuNum(platform_ndk_pb2.ReqPsuInfoPb())
        logging.info('number of psu {}'.format(response.num_psus))
        return response.num_psus

    @staticmethod
    def validate_psu_on_dut(psu_num, dut):
        """validate dut has psu"""
        expected_psu_num = get_expected_hwsku_data(dut, TestPsu.expected_data, 'num_psu')
        if psu_num == 0 and expected_psu_num == 0:
            logging.info('Dut {} does not have psu'.format(dut))
            return False
        if psu_num != expected_psu_num:
            pytest.fail('Number of psu present on dut {} are {}, Expected was {}'
                        .format(dut, psu_num, expected_psu_num))

        logging.info('Number of psu present on dut {} are {}'.format(dut, psu_num))
        return True

    @staticmethod
    @time_taken_by_api
    def get_psu_status(stub, index):
        """Get psu status"""
        response = stub.GetPsuStatus(platform_ndk_pb2.ReqPsuInfoPb(psu_idx=index))
        return response.psu_status

    @staticmethod
    def get_psu_grpc_info(dut):
        """Get psu platform_ndk info"""
        channel = generate_grpc_channel(dut)
        psu_stub = platform_ndk_pb2_grpc.PsuPlatformNdkServiceStub(channel)
        psu_info = {
            'channel': channel,
            'psu_stub': psu_stub,
        }
        return psu_info

# PSU Helper functions
@time_taken_by_api
def get_psu_presence(stub, index):
    """Get psu presence"""
    response = stub.GetPsuPresence(platform_ndk_pb2.ReqPsuInfoPb(psu_idx=index))
    psu_presence = response.psu_presence
    return psu_presence

@time_taken_by_api
def get_psu_identity_data(stub, index, field):
    """Get PSU model/serial/product name"""
    res = None
    if field == 'model':
        response = stub.GetPsuModel(platform_ndk_pb2.ReqPsuInfoPb(psu_idx=index))
        res = response.fru_info.part_number

    if field == 'serial':
        response = stub.GetPsuSerial(platform_ndk_pb2.ReqPsuInfoPb(psu_idx=index))
        res = response.fru_info.serial_number

    if field == 'name':
        response = stub.GetPsuModel(platform_ndk_pb2.ReqPsuInfoPb(psu_idx=index))
        res = response.fru_info.product_name

    return res


@time_taken_by_api
def get_psu_output_current(stub, index):
    """Get psu output current"""
    response = stub.GetPsuOutputCurrent(platform_ndk_pb2.ReqPsuInfoPb(psu_idx=index))
    psu_current = response.output_current
    return psu_current


@time_taken_by_api
def get_psu_output_voltage(stub, index):
    """Get psu output voltage"""
    response = stub.GetPsuOutputVoltage(platform_ndk_pb2.ReqPsuInfoPb(psu_idx=index))
    psu_voltage = response.output_voltage
    return psu_voltage


@time_taken_by_api
def get_psu_output_power(stub, index):
    """Get psu output power"""
    response = stub.GetPsuOutputPower(platform_ndk_pb2.ReqPsuInfoPb(psu_idx=index))
    psu_power = response.output_power
    return psu_power


@time_taken_by_api
def get_psu_temperature(stub, index):
    """Get psu temperature"""
    response = stub.GetPsuTemperature(platform_ndk_pb2.ReqPsuInfoPb(psu_idx=index))
    psu_ambient_temp = response.ambient_temp
    return psu_ambient_temp


@time_taken_by_api
def get_psu_max_output_voltage(stub, index):
    """Get psu max output voltage"""
    response = stub.GetPsuMaxOutputVoltage(platform_ndk_pb2.ReqPsuInfoPb(psu_idx=index))
    psu_max_voltage = response.fault_info.max_voltage
    return psu_max_voltage


@time_taken_by_api
def get_psu_min_output_voltage(stub, index):
    """Get psu min output voltage"""
    response = stub.GetPsuMinOutputVoltage(platform_ndk_pb2.ReqPsuInfoPb(psu_idx=index))
    psu_min_voltage = response.fault_info.min_voltage
    return psu_min_voltage


@time_taken_by_api
def get_psu_max_temp(stub, index):
    """Get psu max temp"""
    response = stub.GetPsuMaxTemperature(platform_ndk_pb2.ReqPsuInfoPb(psu_idx=index))
    psu_max_temp = response.fault_info.max_temperature
    return psu_max_temp


@time_taken_by_api
def get_psu_max_power(stub, index):
    """Get psu max power"""
    response = stub.GetPsuMaximumPower(platform_ndk_pb2.ReqPsuInfoPb(psu_idx=index))
    psu_max_power = response.supplied_power
    return psu_max_power


def compare_actual_and_expected_data(actual_data, expected_data, field, index, dut):
    """Compares actual and expecetd data"""
    failed = False
    msg = ''
    if actual_data != expected_data:
        msg = 'Returned psu {} by api is {}, Expected was {} for {} on {}'\
            .format(field, actual_data, expected_data, index, dut)
        failed = True
    logging.info('Returned PSU {} by API is {}, Expected {} for index {} on {}'
                 .format(field, actual_data, expected_data, index, dut))

    return failed, msg


# PSU Test Cases
def test_get_psu_presence(duthosts):
    """Test PSU presence"""
    # import ipdb;ipdb.set_trace()
    # testhandle = duthosts
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = TestPsu.get_psu_grpc_info(dut)
        # to keep backward with srltest code as srltest returns name list of dut
        dut = dut.hostname
        psu_num = TestPsu.get_psu_num(grpc_info.get('psu_stub'))
        if not TestPsu.validate_psu_on_dut(psu_num, dut):
            grpc_info.get('channel').close()
        try:
            for psu_idx in range(1, psu_num+1):
                psu_presence = get_psu_presence(grpc_info.get('psu_stub'), psu_idx)
                if get_component_expecetd_data_dict(TestPsu.expected_data.get(dut),
                                                    'psu', psu_idx, 'presence'):
                    expected_psu_presence = get_component_expecetd_data_dict(TestPsu.expected_data.get(dut),
                                                                             'psu', psu_idx, 'presence')
                else:
                    expected_psu_presence = False

                failed, msg = compare_actual_and_expected_data(psu_presence,
                                                               expected_psu_presence, 'presence', psu_idx, dut)
                if failed:
                    msg_list.append(msg)
        finally:
            grpc_info.get('channel').close()
    if len(msg_list):
        pytest.fail(msg_list)


def test_get_psu_model(duthosts):
    """Tests psu model number"""
    # testhandle = duthosts
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = TestPsu.get_psu_grpc_info(dut)
        # to keep backward with srltest code
        dut = dut.hostname
        psu_num = TestPsu.get_psu_num(grpc_info.get('psu_stub'))
        if not TestPsu.validate_psu_on_dut(psu_num, dut):
            grpc_info.get('channel').close()
        try:
            for psu_idx in range(1, psu_num+1):
                psu_model = get_psu_identity_data(grpc_info.get('psu_stub'), psu_idx, field='model')
                if get_component_expecetd_data_dict(TestPsu.expected_data.get(dut), 'psu', psu_idx, 'model'):
                    expected_psu_model = get_component_expecetd_data_dict(TestPsu.expected_data.get(dut),
                                                                          'psu', psu_idx, 'model')
                else:
                    expected_psu_model = ''

                failed, msg = compare_actual_and_expected_data(psu_model, expected_psu_model, 'model', psu_idx, dut)
                if failed:
                    msg_list.append(msg)
        finally:
            grpc_info.get('channel').close()

    if len(msg_list):
        pytest.fail(msg_list)


def test_get_psu_status(duthosts):
    """Test psu status"""
    # testhandle = duthosts
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = TestPsu.get_psu_grpc_info(dut)
        # to keep backward with srltest code
        dut = dut.hostname
        psu_num = TestPsu.get_psu_num(grpc_info.get('psu_stub'))
        if not TestPsu.validate_psu_on_dut(psu_num, dut):
            grpc_info.get('channel').close()
        try:
            for psu_idx in range(1, psu_num+1):
                psu_status = TestPsu.get_psu_status(grpc_info.get('psu_stub'), psu_idx)
                if get_component_expecetd_data_dict(TestPsu.expected_data.get(dut),
                                                    'psu', psu_idx, 'status'):
                    expected_psu_status = get_component_expecetd_data_dict(TestPsu.expected_data.get(dut),
                                                                           'psu', psu_idx, 'status')
                else:
                    expected_psu_status = False
                failed, msg = compare_actual_and_expected_data(psu_status, expected_psu_status, 'status', psu_idx, dut)
                if failed:
                    msg_list.append(msg)
        finally:
            grpc_info.get('channel').close()
    if len(msg_list):
        pytest.fail(msg_list)


def test_get_psu_serial(duthosts):
    """Tests psu serial number"""
    # testhandle = duthosts
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = TestPsu.get_psu_grpc_info(dut)
        # to keep backward with srltest code
        dut = dut.hostname
        psu_num = TestPsu.get_psu_num(grpc_info.get('psu_stub'))
        if not TestPsu.validate_psu_on_dut(psu_num, dut):
            grpc_info.get('channel').close()
        try:
            for psu_idx in range(1, psu_num+1):
                psu_serial = get_psu_identity_data(grpc_info.get('psu_stub'), psu_idx, field='serial')

                if get_component_expecetd_data_dict(TestPsu.expected_data.get(dut),
                                                    'psu', psu_idx, 'serial'):
                    expected_psu_serial = get_component_expecetd_data_dict(
                        TestPsu.expected_data.get(dut), 'psu', psu_idx, 'serial')
                else:
                    expected_psu_serial = ''

                failed, msg = compare_actual_and_expected_data(psu_serial, expected_psu_serial, 'serial', psu_idx, dut)
                if failed:
                    msg_list.append(msg)
        finally:
            grpc_info.get('channel').close()
    if len(msg_list):
        pytest.fail(msg_list)


def test_get_psu_product_name(duthosts):
    """Tests psu product name"""
    # testhandle = duthosts
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = TestPsu.get_psu_grpc_info(dut)
        # to keep backward with srltest code
        dut = dut.hostname
        psu_num = TestPsu.get_psu_num(grpc_info.get('psu_stub'))
        if not TestPsu.validate_psu_on_dut(psu_num, dut):
            grpc_info.get('channel').close()

        try:
            for psu_idx in range(1, psu_num+1):
                psu_product_name = get_psu_identity_data(grpc_info.get('psu_stub'), psu_idx, field='name')
                if get_component_expecetd_data_dict(TestPsu.expected_data.get(dut),
                                                    'psu', psu_idx, 'product_name'):
                    expected_psu_product_name = get_component_expecetd_data_dict(
                        TestPsu.expected_data.get(dut), 'psu', psu_idx, 'product_name')
                else:
                    expected_psu_product_name = ''
                failed, msg = compare_actual_and_expected_data(psu_product_name, expected_psu_product_name,
                                                 'product_name', psu_idx, dut)
                if failed:
                    msg_list.append(msg)
        finally:
            grpc_info.get('channel').close()
    if len(msg_list):
        pytest.fail(msg_list)


def test_get_psu_output_current(duthosts):
    """Test psu output current"""
    # testhandle = duthosts
    for dut in duthosts.nodes:
        grpc_info = TestPsu.get_psu_grpc_info(dut)
        # to keep backward with srltest code
        dut = dut.hostname
        psu_num = TestPsu.get_psu_num(grpc_info.get('psu_stub'))
        if not TestPsu.validate_psu_on_dut(psu_num, dut):
            grpc_info.get('channel').close()
        try:
            for psu_idx in range(1, psu_num+1):
                psu_output_current = get_psu_output_current(grpc_info.get('psu_stub'), psu_idx)
                psu_max_output_voltage = get_psu_max_output_voltage(grpc_info.get('psu_stub'), psu_idx)
                psu_output_power = get_psu_output_power(grpc_info.get('psu_stub'), psu_idx)
                psu_presence = get_psu_presence(grpc_info.get('psu_stub'), psu_idx)

                if psu_presence:
                    if round(psu_output_power/psu_max_output_voltage, 2) >= round(psu_output_current, 2):
                        pytest.fail('PSU max output voltage {}, output current {} and output power {}'
                                    .format(psu_max_output_voltage, psu_output_current, psu_output_power))

                    logging.info('PSU max output voltage {}, output current {} and output power {}'
                                  .format(psu_max_output_voltage, psu_output_current, psu_output_power))
                else:
                    if psu_output_power != 0 and psu_output_current != 0:
                        pytest.fail('PSU max output voltage {}, output current {} and output power {}'
                                    .format(psu_max_output_voltage, psu_output_current, psu_output_power))

                    logging.info('PSU max output voltage {}, output current {} and output power {}'
                                 .format(psu_max_output_voltage, psu_output_current, psu_output_power))
        finally:
            grpc_info.get('channel').close()


def test_get_psu_output_voltage(duthosts):
    """Tests get psu output voltage"""
    # testhandle = duthosts
    for dut in duthosts.nodes:
        grpc_info = TestPsu.get_psu_grpc_info(dut)
        # to keep backward with srltest code
        dut = dut.hostname
        psu_num = TestPsu.get_psu_num(grpc_info.get('psu_stub'))
        if not TestPsu.validate_psu_on_dut(psu_num, dut):
            grpc_info.get('channel').close()

        try:
            for psu_idx in range(1, psu_num+1):
                psu_output_voltage = get_psu_output_voltage(grpc_info.get('psu_stub'), psu_idx)
                psu_max_output_voltage = get_psu_max_output_voltage(grpc_info.get('psu_stub'), psu_idx)
                psu_min_output_voltage = get_psu_min_output_voltage(grpc_info.get('psu_stub'), psu_idx)
                psu_presence = get_psu_presence(grpc_info.get('psu_stub'), psu_idx)
                if psu_presence:
                    if psu_max_output_voltage < psu_output_voltage < psu_min_output_voltage:
                        pytest.fail('PSU output voltage returned by API is {}, '
                                    'Expected was between max {} and min {} output voltage.'
                                    .format(psu_output_voltage, psu_max_output_voltage, psu_min_output_voltage))

                    logging.info('PSU output voltage returned by API {} is between max {} and min {} output voltage.'
                                  .format(psu_output_voltage, psu_max_output_voltage, psu_min_output_voltage))
                else:
                    if psu_output_voltage != 0:
                        pytest.fail('PSU output voltage returned by API is {}, '
                                    'Expected was 0'
                                    .format(psu_output_voltage))

                    logging.info('PSU output voltage returned by API {}'
                                  .format(psu_output_voltage))
        finally:
            grpc_info.get('channel').close()


def test_get_psu_output_power(duthosts):
    """Tests get psu output power"""
    # testhandle = duthosts
    for dut in duthosts.nodes:
        grpc_info = TestPsu.get_psu_grpc_info(dut)
        # to keep backward with srltest code
        dut = dut.hostname
        psu_num = TestPsu.get_psu_num(grpc_info.get('psu_stub'))
        if not TestPsu.validate_psu_on_dut(psu_num, dut):
            grpc_info.get('channel').close()

        try:
            for psu_idx in range(1, psu_num+1):
                psu_output_power = get_psu_output_power(grpc_info.get('psu_stub'), psu_idx)
                psu_max_power = get_psu_max_power(grpc_info.get('psu_stub'), psu_idx)
                psu_presence = get_psu_presence(grpc_info.get('psu_stub'), psu_idx)
                psu_min_output_voltage = get_psu_min_output_voltage(grpc_info.get('psu_stub'), psu_idx)
                psu_output_current = get_psu_output_current(grpc_info.get('psu_stub'), psu_idx)
                if psu_presence:
                    if (psu_min_output_voltage * psu_output_current) < psu_output_power > psu_max_power:
                        pytest.fail('PSU output power {} is more than psu max power {} and less than {}'
                                    .format(psu_output_power, psu_max_power,
                                            (psu_min_output_voltage * psu_output_current)))
                    logging.info('PSU output power {} is less than or equal to psu max power {} '
                                  'and more than or equal to {}'
                                  .format(psu_output_power, psu_max_power,
                                          (psu_min_output_voltage * psu_output_current)))
                else:
                    if psu_output_power != 0:
                        pytest.fail('PSU output power is {}, Expecetd was 0'.format(psu_output_power))

                    logging.info('PSU output power is {}'.format(psu_output_power))
        finally:
            grpc_info.get('channel').close()


def test_get_psu_temperature(duthosts):
    """Tests get psu temprature"""
    # testhandle = duthosts
    for dut in duthosts.nodes:
        grpc_info = TestPsu.get_psu_grpc_info(dut)
        # to keep backward with srltest code
        dut = dut.hostname
        psu_num = TestPsu.get_psu_num(grpc_info.get('psu_stub'))
        if not TestPsu.validate_psu_on_dut(psu_num, dut):
            grpc_info.get('channel').close()

        try:
            for psu_idx in range(1, psu_num+1):
                psu_temperature = get_psu_temperature(grpc_info.get('psu_stub'), psu_idx)
                psu_max_temp = get_psu_max_temp(grpc_info.get('psu_stub'), psu_idx)
                psu_presence = get_psu_presence(grpc_info.get('psu_stub'), psu_idx)
                if psu_presence:
                    if psu_temperature > psu_max_temp:
                        pytest.fail('PSU temperature {} is more than PSU max temperature {}'
                                    .format(psu_temperature, psu_max_temp))

                    logging.info('PSU temperature {} is less than PSU max temperature {}'
                                  .format(psu_temperature, psu_max_temp))
                else:
                    if psu_temperature != 0:
                        pytest.fail('PSU temperature is {}, Expected was 0 '
                                    .format(psu_temperature))
                    logging.info('PSU temperature is {}'.format(psu_temperature))
        finally:
            grpc_info.get('channel').close()
