import pytest
import logging

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

class TestEeprom(object):
    """Test eeprom service"""
    expected_data = None
    if expected_data is None:
        expected_data = get_expecetd_data()


def get_eeprom_grpc_info(dut):
    channel = generate_grpc_channel(dut)
    eeprom_stub = platform_ndk_pb2_grpc.EepromPlatformNdkServiceStub(channel)
    eeprom_info = {
        'channel': channel,
        'eeprom_stub': eeprom_stub,
    }
    return eeprom_info


@time_taken_by_api
def get_card_product_name(stub):
    """Get card product name"""
    op_type = platform_ndk_pb2.ReqEepromInfoType.EEPROM_OPS_CARD_PRODUCT_NAME
    response = stub.GetCardProductName(platform_ndk_pb2.ReqEepromInfoPb(type=op_type))
    return response.card_product_name


@time_taken_by_api
def get_card_vendor_name(stub):
    """Get card vendor name"""
    op_type = platform_ndk_pb2.ReqEepromInfoType.EEPROM_OPS_CARD_VENDOR_NAME
    response = stub.GetCardVendorName(platform_ndk_pb2.ReqEepromInfoPb(type=op_type))
    return response.card_vendor_name


@time_taken_by_api
def get_card_serial_number(stub):
    """Get card serial number"""
    op_type = platform_ndk_pb2.ReqEepromInfoType.EEPROM_OPS_CARD_SERIAL_NUM
    response = stub.GetCardSerialNumber(platform_ndk_pb2.ReqEepromInfoPb(type=op_type))
    return response.card_serial_num


@time_taken_by_api
def get_card_part_number(stub):
    """Get card part number"""
    op_type = platform_ndk_pb2.ReqEepromInfoType.EEPROM_OPS_CARD_PART_NUM
    response = stub.GetCardPartNumber(platform_ndk_pb2.ReqEepromInfoPb(type=op_type))
    return response.card_part_num


@time_taken_by_api
def get_card_base_mac(stub):
    """Get card base mac"""
    op_type = platform_ndk_pb2.ReqEepromInfoType.EEPROM_OPS_CARD_BASE_MAC
    response = stub.GetCardBaseMac(platform_ndk_pb2.ReqEepromInfoPb(type=op_type))
    return response.card_base_mac


@time_taken_by_api
def get_card_mac_count(stub):
    """Get card mac count"""
    op_type = platform_ndk_pb2.ReqEepromInfoType.EEPROM_OPS_CARD_MAC_COUNT
    response = stub.GetCardMacCount(platform_ndk_pb2.ReqEepromInfoPb(type=op_type))
    return response.card_mac_count


@time_taken_by_api
def get_card_eeprom_all_tlvs(stub):
    """Get card eeprom all tlvs"""
    op_type = platform_ndk_pb2.ReqEepromInfoType.EEPROM_OPS_CARD_ALL_TLVS
    response = stub.GetCardEepromAllTlvs(platform_ndk_pb2.ReqEepromInfoPb(type=op_type))
    return response.data


@time_taken_by_api
def get_card_hwsku(stub):
    """Get card hwsku"""
    op_type = platform_ndk_pb2.ReqEepromInfoType.EEPROM_OPS_CARD_HWSKU
    response = stub.GetCardHwsku(platform_ndk_pb2.ReqEepromInfoPb(type=op_type))
    return response.card_hwsku


@time_taken_by_api
def get_card_clei_number(stub):
    """Get card clei number"""
    op_type = platform_ndk_pb2.ReqEepromInfoType.EEPROM_OPS_CARD_CLEI_NUM
    response = stub.GetCardCleiNumber(platform_ndk_pb2.ReqEepromInfoPb(type=op_type))
    return response.card_clei_num


@time_taken_by_api
def get_card_mfg_date(stub):
    """Get card mfg date"""
    op_type = platform_ndk_pb2.ReqEepromInfoType.EEPROM_OPS_CARD_MFG_DATE
    response = stub.GetCardMfgDate(platform_ndk_pb2.ReqEepromInfoPb(type=op_type))
    return response.card_mfg_date


@time_taken_by_api
def get_chassis_eeprom(stub):
    """Get chassis eeprom"""
    op_type = platform_ndk_pb2.ReqEepromInfoType.EEPROM_OPS_CHASSIS_EEPROM
    response = stub.GetChassisEeprom(platform_ndk_pb2.ReqEepromInfoPb(type=op_type))
    return response.chassis_eeprom


def verify_actual_and_expected_data(actual_data, dut, field):
    failed = False
    msg = ''
    data = TestEeprom.expected_data.get(dut)
    if field == 'product_name':
        expected_data = get_expected_hwsku_data(dut, TestEeprom.expected_data, 'product_name')
    else:
        expected_data = data.get(field, "")
    if actual_data != expected_data:
        msg = '{} returned by api is {}, Expected was {} on dut {}'.format(field, actual_data, expected_data, dut)
        failed = True
    logging.info('{} returned by api is {} expected: {} on dut {}'
                 .format(field, actual_data, expected_data, dut))
    return failed, msg


def test_get_card_product_name(duthosts):
    """Tests get card product name"""
    # testhandle = duthosts
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = get_eeprom_grpc_info(dut)
        dut = dut.hostname
        try:
            actual_product_name = get_card_product_name(grpc_info.get('eeprom_stub'))
            failed, msg = verify_actual_and_expected_data(actual_product_name, dut, 'product_name')
            if failed:
                msg_list.append(msg)

        finally:
            grpc_info.get('channel').close()

    if len(msg_list):
        pytest.fail(msg_list)


def test_get_card_serial_number(duthosts):
    """Test get card serial number"""
    # testhandle = duthosts
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = get_eeprom_grpc_info(dut)
        dut = dut.hostname
        try:
            actual_serial_number = get_card_serial_number(grpc_info.get('eeprom_stub'))
            failed, msg = verify_actual_and_expected_data(actual_serial_number, dut, 'serial')
            if failed:
                msg_list.append(msg)
        finally:
            grpc_info.get('channel').close()
    if len(msg_list):
        pytest.fail(msg_list)


def test_get_card_base_mac(duthosts):
    """Tests get card base mac"""
    # testhandle = duthosts
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = get_eeprom_grpc_info(dut)
        dut = dut.hostname
        try:
            actual_card_base_mac = get_card_base_mac(grpc_info.get('eeprom_stub'))
            failed, msg = verify_actual_and_expected_data(actual_card_base_mac, dut, 'base_mac')
            if failed:
                msg_list.append(msg)
        finally:
            grpc_info.get('channel').close()
    if len(msg_list):
        pytest.fail(msg_list)

def test_get_card_part_number(duthosts):
    """Tests get card part number"""
    # testhandle = duthosts
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = get_eeprom_grpc_info(dut)
        dut = dut.hostname
        try:
            actual_part_number = get_card_part_number(grpc_info.get('eeprom_stub'))
            failed, msg = verify_actual_and_expected_data(actual_part_number, dut, 'model')
            if failed:
                msg_list.append(msg)
        finally:
            grpc_info.get('channel').close()
    if len(msg_list):
        pytest.fail(msg_list)


def test_get_card_mac_count(duthosts):
    """Tests get card mac count"""
    # testhandle = duthosts
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = get_eeprom_grpc_info(dut)
        dut = dut.hostname
        try:
            actual_card_mac_count = get_card_mac_count(grpc_info.get('eeprom_stub'))
            failed, msg = verify_actual_and_expected_data(actual_card_mac_count, dut, 'mac_count')
            if failed:
                msg_list.append(msg)
        finally:
            grpc_info.get('channel').close()
    if len(msg_list):
        pytest.fail(msg_list)


def test_get_card_vendor_name(duthosts):
    """Tests get card vendor name"""
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = get_eeprom_grpc_info(dut)
        dut = dut.hostname
        try:
            actual_vendor_name = get_card_vendor_name(grpc_info.get('eeprom_stub'))
            failed, msg = verify_actual_and_expected_data(actual_vendor_name, dut, 'vendor_name')
            if failed:
                msg_list.append(msg)
        finally:
            grpc_info.get('channel').close()
    if len(msg_list):
        pytest.fail(msg_list)


def test_get_card_hwsku(duthosts):
    """Test get card hwsku"""
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = get_eeprom_grpc_info(dut)
        dut = dut.hostname
        try:
            actual_card_hwsku = get_card_hwsku(grpc_info.get('eeprom_stub'))
            failed, msg = verify_actual_and_expected_data(actual_card_hwsku, dut, 'card_hwsku')
            if failed:
                msg_list.append(msg)
        finally:
            grpc_info.get('channel').close()
    if len(msg_list):
        pytest.fail(msg_list)


def test_get_card_clei_number(duthosts):
    """Test card clei number """
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = get_eeprom_grpc_info(dut)
        dut = dut.hostname
        try:
            actual_clei_num = get_card_clei_number(grpc_info.get('eeprom_stub'))
            failed, msg = verify_actual_and_expected_data(actual_clei_num, dut, 'clei_number')
            if failed:
                msg_list.append(msg)
        finally:
            grpc_info.get('channel').close()
    if len(msg_list):
        pytest.fail(msg_list)


def test_get_card_mfg_date(duthosts):
    """Test card mfg date """
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = get_eeprom_grpc_info(dut)
        dut = dut.hostname
        try:
            actual_mfg_date = get_card_mfg_date(grpc_info.get('eeprom_stub'))
            failed, msg = verify_actual_and_expected_data(actual_mfg_date, dut, 'mfg_date')
            if failed:
                msg_list.append(msg)
        finally:
            grpc_info.get('channel').close()
    if len(msg_list):
        pytest.fail(msg_list)


def test_get_chassis_eeprom(duthosts):
    """Test get chassis eeprom"""
    msg_list = list()
    for dut in duthosts.supervisor_nodes:
        grpc_info = get_eeprom_grpc_info(dut)
        dut = dut.hostname
        try:
            actual_chassis_eeprom = get_chassis_eeprom(grpc_info.get('eeprom_stub'))
            failed, msg = verify_actual_and_expected_data(actual_chassis_eeprom.chassis_serial_num, dut,
                                                          'chassis_serial_num')
            if failed:
                msg_list.append(msg)
            failed, msg = verify_actual_and_expected_data(actual_chassis_eeprom.chassis_part_num, dut,
                                                          'chassis_part_num')
            if failed:
                msg_list.append(msg)
            failed, msg = verify_actual_and_expected_data(actual_chassis_eeprom.chassis_base_mac, dut,
                                                          'chassis_base_mac')
            if failed:
                msg_list.append(msg)
            failed, msg = verify_actual_and_expected_data(actual_chassis_eeprom.chassis_mac_count, dut,
                                                          'chassis_mac_count')
            if failed:
                msg_list.append(msg)
            failed, msg = verify_actual_and_expected_data(actual_chassis_eeprom.chassis_clei_num, dut,
                                                          'chassis_clei_num')
            if failed:
                msg_list.append(msg)
            failed, msg = verify_actual_and_expected_data(actual_chassis_eeprom.chassis_mfg_date, dut,
                                                          'chassis_mfg_date')
            if failed:
                msg_list.append(msg)

        finally:
            grpc_info.get('channel').close()
    if len(msg_list):
        pytest.fail(msg_list)
