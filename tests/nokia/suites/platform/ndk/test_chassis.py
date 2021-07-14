import pytest
import logging

# from srltest.library import logging

# pytestmark_config_check = pytest.mark.srl_skip_config_check
# pytestmark_skip_fib_agent = pytest.mark.srl_skip_fib_agent
# pytestmark = pytest.mark.register(level='regular', owner='falodiya')

import platform_ndk.platform_ndk_pb2 as platform_ndk_pb2
import platform_ndk.platform_ndk_pb2_grpc as platform_ndk_pb2_grpc
from ndk_common import generate_grpc_channel, get_component_expecetd_data_dict,\
    get_expecetd_data, get_expected_hwsku_data, time_taken_by_api

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('ndk')
]


class TestChassis(object):
    """Test Chassis service"""
    expected_data = None
    HW_MODULE_TYPE = {0: 'HW_MODULE_TYPE_INVALID', 1: 'HW_MODULE_TYPE_CONTROL', 2: 'HW_MODULE_TYPE_LINE',
                      3: 'HW_MODULE_TYPE_FABRIC', 4: 'HW_MODULE_TYPE_PSU', 5: 'HW_MODULE_TYPE_FANTRAY',
                      6: 'HW_MODULE_TYPE_MASTER_PSU'}
    HW_CHASSIS_TYPE = {0: 'HW_CHASSIS_TYPE_INVALID', 1: 'HW_CHASSIS_TYPE_IXR6',
                       2: 'HW_CHASSIS_TYPE_IXR10', 3: 'HW_CHASSIS_TYPE_7220_H3',
                       4: 'HW_CHASSIS_TYPE_IXR6E', 5: 'HW_CHASSIS_TYPE_IXR10E'}
    HW_MODULE_TYPE_LIST = ['HW_MODULE_TYPE_CONTROL', 'HW_MODULE_TYPE_LINE', 'HW_MODULE_TYPE_FABRIC']
    HW_MODULE_POWER_LIST = ['HW_MODULE_TYPE_CONTROL', 'HW_MODULE_TYPE_LINE', 'HW_MODULE_TYPE_FABRIC']
    HW_MODULE_STATUS = {0: 'HW_MODULE_STATUS_INVALID', 1: 'HW_MODULE_STATUS_EMPTY',
                        2: 'HW_MODULE_STATUS_OFFLINE', 3: 'HW_MODULE_STATUS_POWERED_DOWN',
                        4: 'HW_MODULE_STATUS_PRESENT', 5: 'HW_MODULE_STATUS_FAULT', 6: 'HW_MODULE_STATUS_ONLINE'}

    if expected_data is None:
        expected_data = get_expecetd_data()

    @staticmethod
    def get_chassis_grpc_info(dut):
        """Get chassis grpc info"""
        channel = generate_grpc_channel(dut)
        chassis_stub = platform_ndk_pb2_grpc.ChassisPlatformNdkServiceStub(channel)
        chassis_info = {
            'channel': channel,
            'chassis_stub': chassis_stub,
        }
        return chassis_info

    @staticmethod
    def get_hw_property(stub):
        """Get chassis properties"""
        response = stub.GetChassisProperties(platform_ndk_pb2.ReqModuleInfoPb())
        return response.chassis_property.hw_property

    @staticmethod
    def get_num_of_sfm(stub):
        """Get number of sfm"""
        hw_property = TestChassis.get_hw_property(stub)
        for property in hw_property:
            if TestChassis.HW_MODULE_TYPE.get(property.module_type) == 'HW_MODULE_TYPE_FABRIC':
                return property.max_num


    @staticmethod
    def validate_sfm_on_dut(sfm_num, dut):
        """validate dut has sfm"""
        expected_sfm_num = TestChassis.expected_data.get(dut).get('max_sfm_num', 0)
        if sfm_num == 0 and expected_sfm_num == 0:
            logging.info('Dut {} does not have sfm'.format(dut))
            return False
        if sfm_num != expected_sfm_num:
            pytest.fail('Number of sfm present on dut {} are {}, Expected was {}'
                        .format(dut, sfm_num, expected_sfm_num))

        logging.info('Number of sfm present on dut {} are {}'.format(dut, sfm_num))
        return True

    @staticmethod
    def get_module_hw_slot(stub, module_type):
        """Get hw slot"""
        hw_property = TestChassis.get_hw_property(stub)
        for property in hw_property:
            if TestChassis.HW_MODULE_TYPE.get(property.module_type) == module_type:
                return property.slot

    @staticmethod
    @time_taken_by_api
    def get_module_status(stub, module_type, hw_slot):
        """Get module status"""
        convert_module_type_to_protobuff(module_type)
        response = stub.GetModuleStatus(platform_ndk_pb2.ReqModuleInfoPb(module_type=module_type, hw_slot=hw_slot))
        return response.status


def convert_module_type_to_protobuff(module_type):
    """Converts module type to proto buff"""
    if module_type == 'HW_MODULE_TYPE_CONTROL':
        module_type = platform_ndk_pb2.HwModuleType.HW_MODULE_TYPE_CONTROL
    elif module_type == 'HW_MODULE_TYPE_LINE':
        module_type = platform_ndk_pb2.HwModuleType.HW_MODULE_TYPE_LINE
    elif module_type == 'HW_MODULE_TYPE_FABRIC':
        module_type = platform_ndk_pb2.HwModuleType.HW_MODULE_TYPE_FABRIC
    return module_type

def convert_module_status_to_readable(module_status):
    """Converts module status from protobuff message to readable form eg. 6 --> 'Online'"""
    module_status = TestChassis.HW_MODULE_STATUS.get(module_status)
    if module_status == 'HW_MODULE_STATUS_ONLINE':
        return 'Online'
    if module_status == 'HW_MODULE_STATUS_OFFLINE':
        return 'Offline'
    if module_status == 'HW_MODULE_STATUS_FAULT':
        return 'Fault'
    if module_status == 'HW_MODULE_STATUS_EMPTY':
        return 'Empty'


@time_taken_by_api
def get_module_name(stub, module_type, hw_slot):
    """Get module name"""
    convert_module_type_to_protobuff(module_type)
    response = stub.GetModuleName(platform_ndk_pb2.ReqModuleInfoPb(module_type=module_type, hw_slot=hw_slot))
    return response.name


@time_taken_by_api
def get_module_max_num(stub, module_type):
    """Get module max num"""
    hw_property = TestChassis.get_hw_property(stub)
    for property in hw_property:
        if TestChassis.HW_MODULE_TYPE.get(property.module_type) == module_type:
            return property.max_num


@time_taken_by_api
def get_chassis_status(stub):
    """Get chassis status"""
    response = stub.GetChassisStatus(platform_ndk_pb2.ReqModuleInfoPb())
    return response


@time_taken_by_api
def get_chassis_type(stub):
    """Get chassis type"""
    response = stub.GetChassisType(platform_ndk_pb2.ReqModuleInfoPb())
    return response.chassis_type


@time_taken_by_api
def get_my_slot(stub):
    """Get my slot"""
    response = stub.GetMySlot(platform_ndk_pb2.ReqModuleInfoPb())
    return response.my_slot


@time_taken_by_api
def get_midplane_ip(stub, module_type, hw_slot):
    """Get midplane ip"""
    convert_module_type_to_protobuff(module_type)
    response = stub.GetMidplaneIP(platform_ndk_pb2.ReqModuleInfoPb(module_type=module_type, hw_slot=hw_slot))
    return response.midplane_ip


@time_taken_by_api
def is_midplane_reachable(stub, module_type, hw_slot):
    """get midplane reachablity"""
    convert_module_type_to_protobuff(module_type)
    response = stub.IsMidplaneReachable(platform_ndk_pb2.ReqModuleInfoPb(module_type=module_type, hw_slot=hw_slot))
    return response.midplane_status


@time_taken_by_api
def ping_midplane_ip(stub, module_type, hw_slot):
    """Ping midplane ip"""
    convert_module_type_to_protobuff(module_type)
    response = stub.PingHealthCheck(platform_ndk_pb2.ReqModuleInfoPb(module_type=module_type, hw_slot=hw_slot))
    return response.ping_status_str


def get_expected_module_data(dut, module_type, slot, field):
    """Gets expected name"""
    module_data = None
    if module_type == 'HW_MODULE_TYPE_CONTROL':
        module_data = get_component_expecetd_data_dict(TestChassis.expected_data.get(dut), "control", slot, field)
    elif module_type == 'HW_MODULE_TYPE_LINE':
        module_data = get_component_expecetd_data_dict(TestChassis.expected_data.get(dut), "line", slot, field)
    elif module_type == 'HW_MODULE_TYPE_FABRIC':
        module_data = get_component_expecetd_data_dict(TestChassis.expected_data.get(dut), "fabric", slot, field)

    if module_data is None:
        return ''

    return module_data


def get_expected_max_num(dut, module_type):
    if module_type == 'HW_MODULE_TYPE_CONTROL':
        expected_max_num = get_expected_hwsku_data(dut, TestChassis.expected_data, 'max_control_num')
    elif module_type == 'HW_MODULE_TYPE_LINE':
        expected_max_num = get_expected_hwsku_data(dut, TestChassis.expected_data, 'max_line_num')
    elif module_type == 'HW_MODULE_TYPE_FABRIC':
        expected_max_num = get_expected_hwsku_data(dut, TestChassis.expected_data, 'max_fabric_num')
    return expected_max_num


def get_expected_max_power(dut, module_type):
    if module_type == 'HW_MODULE_TYPE_CONTROL':
        expected_max_power = get_expected_hwsku_data(dut, TestChassis.expected_data, 'control_max_power')
    elif module_type == 'HW_MODULE_TYPE_LINE':
        expected_max_power = get_expected_hwsku_data(dut, TestChassis.expected_data, 'line_max_power')
    elif module_type == 'HW_MODULE_TYPE_FABRIC':
        expected_max_power = get_expected_hwsku_data(dut, TestChassis.expected_data, 'fabric_max_power')
    elif module_type == 'HW_MODULE_TYPE_FANTRAY':
        expected_max_power = get_expected_hwsku_data(dut, TestChassis.expected_data, 'fantray_max_power')
    return expected_max_power


@time_taken_by_api
def get_max_power(stub):
    """Get module power"""
    response = stub.GetModuleMaxPower(platform_ndk_pb2.ReqModuleInfoPb())
    return response.power_info.module_power


def get_module_max_power(module_type, module_power):
    for power in module_power:
        if TestChassis.HW_MODULE_TYPE.get(power.module_type) == module_type:
            return power.module_maxpower


def reboot_slot(stub, slot):
    response = stub.RebootSlot(platform_ndk_pb2.ReqModuleInfoPb(hw_slot=slot))
    return response


def get_fabric_pcie_info(stub, slot, localhost):
    """Get fabric pcie info
    response_status {
    }
    pcie_info {
      asic_entry {
        asic_idx: 12
        asic_pcie_id: "nokia-bdb:7:0"
      }
      asic_entry {
        asic_idx: 13
        asic_pcie_id: "nokia-bdb:7:1"
      }
    }
    """
    import os
    BASE_DIR = os.getcwd()
    PARENT_PATH = os.path.abspath(os.path.join(BASE_DIR, os.pardir))
    path = os.path.join(PARENT_PATH, 'platform_ndk', 'platform_ndk_pb2_grpc.py')
    cmd = "grep -r 'GetFabricPcieInfo' {}".format(path)
    out = localhost.shell(cmd)
    logging.info('protobuff file has pcie info {}'.format(out['stdout']))
    response = stub.GetFabricPcieInfo(platform_ndk_pb2.ReqModuleInfoPb(module_type='HW_MODULE_TYPE_FABRIC',hw_slot=slot))
    return response


def compare_actual_and_expected_chassis_data(dut, actual_data, expected_data, field, module_type=None, slot=None):
    """Compares actual and expected data"""
    msg = ''
    failed = False
    if actual_data != expected_data:
        msg = '{} return by api is {}, Expected was {} on dut {} for module type {} on slot {}'\
            .format(field, actual_data, expected_data, dut, module_type, slot)
        failed = True

    logging.info('{} returned by API is {} on dut {}, Expecetd {} for module type {} on slot {}'
                 .format(field, actual_data, dut, expected_data, module_type, slot))
    return failed, msg


def test_module_max_num(duthosts):
    """Test get module max num"""
    msg_list = list()
    for dut in duthosts.supervisor_nodes:
        chassis_grpc_info = TestChassis.get_chassis_grpc_info(dut)
        try:
            for module_type in TestChassis.HW_MODULE_TYPE_LIST:
                module_max_num = get_module_max_num(chassis_grpc_info.get('chassis_stub'), module_type)
                expected_max_num = get_expected_max_num(dut.hostname, module_type)
                failed, msg = compare_actual_and_expected_chassis_data(dut.hostname,
                                                                       module_max_num, expected_max_num,
                                                                       'Module max num', module_type)
                if failed:
                    msg_list.append(msg)
                hw_slot = TestChassis.get_module_hw_slot(chassis_grpc_info.get('chassis_stub'), module_type)
                failed, msg = compare_actual_and_expected_chassis_data(dut.hostname, module_max_num, len(hw_slot),
                                                                       'Compare Module max num and slot list'
                                                                       ' returned by API,'
                                                                       ' module max num or length of slot list',
                                                                       module_type)
                if failed:
                    msg_list.append(msg)
        finally:
            chassis_grpc_info.get('channel').close()

    if len(msg_list):
        pytest.fail(msg_list)


def test_get_module_name(duthosts):
    """Test get module name"""
    msg_list = list()
    for dut in duthosts.supervisor_nodes:
        chassis_grpc_info = TestChassis.get_chassis_grpc_info(dut)
        try:
            for module_type in TestChassis.HW_MODULE_TYPE_LIST:
                hw_slot = TestChassis.get_module_hw_slot(chassis_grpc_info.get('chassis_stub'), module_type)
                if module_type == 'HW_MODULE_TYPE_LINE' and dut.is_supervisor_node():
                    slot_connected = TestChassis.expected_data.get(dut.hostname).get('line').keys()
                    hw_slot = list(map(int, slot_connected))
                for slot in hw_slot:
                    module_name = get_module_name(chassis_grpc_info.get('chassis_stub'), module_type, slot)
                    logging.info('Module name is {} for slot {}'
                                 .format(module_name, slot))
                    expected_name = get_expected_module_data(dut.hostname, module_type, slot, 'name')
                    if module_name == 'line-card' and expected_name == '':
                        expected_name = module_name
                    if module_name == 'unknown' and expected_name == '':
                        expected_name = module_name
                    failed, msg = compare_actual_and_expected_chassis_data(dut.hostname, module_name,
                                                                           expected_name, 'Product name', module_type)
                    if failed:
                        msg_list.append(msg)
        finally:
            chassis_grpc_info.get('channel').close()

    if len(msg_list):
        pytest.fail(msg_list)


def test_get_module_status(duthosts):
    """Test get module status"""
    msg_list = list()
    for dut in duthosts.supervisor_nodes:
        chassis_grpc_info = TestChassis.get_chassis_grpc_info(dut)
        try:
            for module_type in TestChassis.HW_MODULE_TYPE_LIST:
                hw_slot = TestChassis.get_module_hw_slot(chassis_grpc_info.get('chassis_stub'), module_type)
                if module_type == 'HW_MODULE_TYPE_LINE' and dut.is_supervisor_node():
                    slot_connected = TestChassis.expected_data.get(dut.hostname).get('line').keys()
                    hw_slot = list(map(int, slot_connected))

                for slot in hw_slot:
                    module_status = TestChassis.get_module_status(chassis_grpc_info.get('chassis_stub'),
                                                                  module_type, slot)
                    module_status = convert_module_status_to_readable(module_status)
                    expected_status = get_expected_module_data(dut.hostname, module_type, slot, 'status')
                    if module_status == 'Empty' and expected_status == '':
                        expected_status = module_status
                    if module_status == 'Fault' and expected_status == '':
                        expected_status = module_status
                    if module_status is None and expected_status == '':
                        expected_status = module_status
                    failed, msg = compare_actual_and_expected_chassis_data(dut.hostname, module_status,
                                                                           expected_status,
                                                                           'Product status', module_type, slot)
                    if failed:
                        msg_list.append(msg)
        finally:
            chassis_grpc_info.get('channel').close()

    if len(msg_list):
        pytest.fail(msg_list)


def test_get_chassis_type(duthosts):
    """Test get chassis type"""
    msg_list = list()
    for dut in duthosts.supervisor_nodes:
        chassis_grpc_info = TestChassis.get_chassis_grpc_info(dut)
        try:
            chassis_type = get_chassis_type(chassis_grpc_info.get('chassis_stub'))
            logging.info('Chassis type is {} on dut {}'
                         .format(TestChassis.HW_CHASSIS_TYPE.get(chassis_type), dut.hostname))
            expected_chassis_type = TestChassis.expected_data.get(dut.hostname).get('chassis_type')
            failed, msg = compare_actual_and_expected_chassis_data(dut.hostname,
                                                                   TestChassis.HW_CHASSIS_TYPE.get(chassis_type),
                                                                   expected_chassis_type, 'Chassis type')
            if failed:
                msg_list.append(msg)

        finally:
            chassis_grpc_info.get('channel').close()

    if len(msg_list):
        pytest.fail(msg_list)


def test_get_my_slot(duthosts):
    """Test get my slot"""
    msg_list = list()
    for dut in duthosts.nodes:
        chassis_grpc_info = TestChassis.get_chassis_grpc_info(dut)
        try:
            actual_my_slot = get_my_slot(chassis_grpc_info.get('chassis_stub'))
            expected_my_slot = TestChassis.expected_data.get(dut.hostname).get('my_slot')
            failed, msg = compare_actual_and_expected_chassis_data(dut.hostname, actual_my_slot,
                                                     expected_my_slot, 'My Slot')
            if failed:
                msg_list.append(msg)
        finally:
            chassis_grpc_info.get('channel').close()

    if len(msg_list):
        pytest.fail(msg_list)


def test_get_midplane_ip(duthosts):
    msg_list = list()
    for dut in duthosts.supervisor_nodes:
        chassis_grpc_info = TestChassis.get_chassis_grpc_info(dut)
        try:
            hw_slot = TestChassis.get_module_hw_slot(chassis_grpc_info.get('chassis_stub'), 'HW_MODULE_TYPE_CONTROL')
            for slot in hw_slot:
                module_ip = get_midplane_ip(chassis_grpc_info.get('chassis_stub'), 'HW_MODULE_TYPE_CONTROL', slot)
                expected_ip = get_expected_module_data(dut.hostname, 'HW_MODULE_TYPE_CONTROL', slot, 'midplane_ip')
                failed, msg = compare_actual_and_expected_chassis_data(dut.hostname, module_ip,
                                                                       expected_ip, 'Midplane ip')
                if failed:
                    msg_list.append(msg)
        finally:
            chassis_grpc_info.get('channel').close()

    if len(msg_list):
        pytest.fail(msg_list)


def test_is_midplane_reachable(duthosts):
    """Test midplane reachablity"""
    msg_list = list()
    for dut in duthosts.nodes:
        chassis_grpc_info = TestChassis.get_chassis_grpc_info(dut)
        try:
            for module_type in TestChassis.HW_MODULE_TYPE_LIST:
                if dut.is_supervisor_node():
                    hw_slot = TestChassis.get_module_hw_slot(chassis_grpc_info.get('chassis_stub'), module_type)
                    if module_type == 'HW_MODULE_TYPE_LINE' and dut.is_supervisor_node():
                        slot_connected = TestChassis.expected_data.get(dut.hostname).get('line').keys()
                        hw_slot = list(map(int, slot_connected))
                    for slot in hw_slot:
                        module_reachable = is_midplane_reachable(chassis_grpc_info.get('chassis_stub'),
                                                                 module_type, slot)
                        expected_reachable = get_expected_module_data(dut.hostname, module_type,
                                                                      slot, 'midplane_reachable')
                        if expected_reachable == '':
                            expected_reachable = False
                        cmd = "DevMgrNdkUtils::DisplayMidplanePresenceJson"
                        response = dut.shell('cat /tmp/pass | /opt/srlinux/bin/sr_platform_ndk_cli -w -c "{}"'.format(cmd))
                        logging.info('{} response is {}'.format(cmd, response['stdout']))
                        failed, msg = compare_actual_and_expected_chassis_data(dut.hostname, module_reachable,
                                                                               expected_reachable, 'Midplane reachable',
                                                                               module_type, slot)
                else:
                    if module_type == 'HW_MODULE_TYPE_CONTROL':
                        module_reachable = is_midplane_reachable(chassis_grpc_info.get('chassis_stub'), module_type, 0)
                        expected_reachable = get_expected_module_data(dut.hostname, module_type,
                                                                      0, 'midplane_reachable')
                        if expected_reachable == '':
                            expected_reachable = False
                        cmd = "DevMgrNdkUtils::DisplayMidplanePresenceJson"
                        response = dut.shell('cat /tmp/pass | /opt/srlinux/bin/sr_platform_ndk_cli -w -c "{}"'.format(cmd))
                        logging.info('{} response is {}'.format(cmd, response['stdout']))
                        failed, msg = compare_actual_and_expected_chassis_data(dut.hostname, module_reachable,
                                                                               expected_reachable, 'Midplane reachable',
                                                                               module_type, 0)

            if failed:
                msg_list.append(msg)
        finally:
            chassis_grpc_info.get('channel').close()

    if len(msg_list):
        pytest.fail(msg_list)


def test_module_max_power(duthosts):
    """Test module max power"""
    msg_list = list()
    for dut in duthosts.supervisor_nodes:
        chassis_grpc_info = TestChassis.get_chassis_grpc_info(dut)
        try:
            max_power = get_max_power(chassis_grpc_info.get('chassis_stub'))
            for module_type in TestChassis.HW_MODULE_POWER_LIST:
                module_max_power = get_module_max_power(module_type, max_power)
                expected_module_max_power = get_expected_max_power(dut.hostname, module_type)
                failed, msg = compare_actual_and_expected_chassis_data(dut.hostname, module_max_power,
                                                                       expected_module_max_power, 'Module max power')
                if failed:
                    msg_list.append(msg)
        finally:
            chassis_grpc_info.get('channel').close()

    if len(msg_list):
        pytest.fail(msg_list)


def test_ping_midplane_ip(duthosts):
    msg_list = list()
    for dut in duthosts.supervisor_nodes:
        chassis_grpc_info = TestChassis.get_chassis_grpc_info(dut)
        try:
            hw_slot = TestChassis.get_module_hw_slot(chassis_grpc_info.get('chassis_stub'), 'HW_MODULE_TYPE_LINE')
            for slot in hw_slot:
                module_ip = get_midplane_ip(chassis_grpc_info.get('chassis_stub'), 'HW_MODULE_TYPE_LINE', slot)
                ping_midplane_ip(chassis_grpc_info.get('chassis_stub'), 'HW_MODULE_TYPE_LINE', slot)
                slot_connected = TestChassis.expected_data.get(dut.hostname).get('line').keys()
                slot_present = list(map(int, slot_connected))
                # if failed:
                #     msg_list.append(msg)
        finally:
            chassis_grpc_info.get('channel').close()

    if len(msg_list):
        pytest.fail(msg_list)


def test_get_fabric_pcie_info(duthosts, localhost):
    for dut in duthosts.supervisor_nodes:
        chassis_grpc_info = TestChassis.get_chassis_grpc_info(dut)
        try:
            hw_slots = TestChassis.get_module_hw_slot(chassis_grpc_info.get('chassis_stub'), 'HW_MODULE_TYPE_FABRIC')
            hw_slot = list(map(int, hw_slots))
            idx = -1
            for slot in hw_slot:
                nokia_cmd_output = dut.shell('nokia_cmd show fabric-pcie {}'.format(slot))
                logging.info('Pcie info from nokia cmd is {}'.format(nokia_cmd_output['stdout']))
                response = get_fabric_pcie_info(chassis_grpc_info.get('chassis_stub'), slot, localhost)
                expected_status = get_expected_module_data(dut.hostname, 'HW_MODULE_TYPE_FABRIC', slot, 'status')
                expected_asics = int(get_expected_module_data(dut.hostname,'HW_MODULE_TYPE_FABRIC', slot, 'asics'))
                idx = idx + expected_asics
                if expected_status == 'Online' and response.response_status.status_code:
                    pytest.fail('status code returned for SFM slot {} is {}, Expected: false'
                                .format(slot, response.response_status.status_code))
                if expected_status == 'Online':
                    if len(response.pcie_info.asic_entry) != expected_asics:
                        pytest.fail('Expected asic_entry returned by API {}, Expected {}'
                                    .format(response.pcie_info.asic_entry, expected_asics))
                    if response.pcie_info.asic_entry[0].asic_idx != idx -1:
                        pytest.fail('Expected asic_idx returned by API {}, Expected {}'
                                    .format(response.pcie_info.asic_entry[1].asic_idx, idx))
                    if response.pcie_info.asic_entry[1].asic_idx != idx:
                        pytest.fail('Expected asic_idx returned by API {}, Expected {}'
                                    .format(response.pcie_info.asic_entry[1].asic_idx, idx))
                    logging.info('Expected asic_entry returned by API {}, Expected {}'
                                .format(response.pcie_info.asic_entry, expected_asics))
                    logging.info('Expected asic_idx returned by API {}, Expected {}'
                                .format(response.pcie_info.asic_entry[1].asic_idx, idx))
        finally:
            chassis_grpc_info.get('channel').close()


def wait_for_linecard_to_be_unreachable(dut, ip, timeout=50):
    cmd = "ping {ip} -w {to}".format(ip=ip, to=timeout)
    output = dut.shell(cmd)
    if "0% packet loss" in output['stdout_lines'][-2]:
        logging.info('LineCard with ip {} did not reboot after {} sec expected was rebooting'.format(ip, 20))
        pytest.fail('Linecard did not reboot')
    logging.info('LineCard with ip {} is rebooting'.format(ip))


def wait_for_linecard_to_be_reachable(dut, ip, timeout=60):
    cmd = "ping {ip} -w {to}".format(ip=ip, to=timeout)
    output = dut.shell(cmd)
    if "100% packet loss" in output['stdout_lines'][-2]:
        logging.info('LineCard with ip {} is not up after {} sec expected was rebooting'.format(ip, 30))
        pytest.fail('Linecard is not up after reboot')
    logging.info('LineCard with ip {} is up after reboot'.format(ip))


@pytest.mark.skip
def test_reboot_slot_from_cpm(duthosts):
    for dut in duthosts.supervisor_nodes:
        chassis_grpc_info = TestChassis.get_chassis_grpc_info(dut)
        try:
            slot_connected = TestChassis.expected_data.get(dut.hostname).get('line').keys()
            slot_present = list(map(int, slot_connected))
            for slot in slot_present:
                response = reboot_slot(chassis_grpc_info.get('chassis_stub'), slot)
                ip = "10.0.5.{}".format(slot)
                if response.response_status:
                    wait_for_linecard_to_be_unreachable(dut, ip)
                wait_for_linecard_to_be_reachable(dut, ip)
                break
        finally:
            chassis_grpc_info.get('channel').close()

@pytest.mark.skip
def test_reboot_own_slot(duthosts, localhost):
    for dut in duthosts:
        chassis_grpc_info = TestChassis.get_chassis_grpc_info(dut)
        try:
            my_slot = get_my_slot(chassis_grpc_info.get('chassis_stub'))
            response = reboot_slot(chassis_grpc_info.get('chassis_stub'), my_slot)
            mgmt_ip = dut.mgmt_ip
            if response.response_status:
                time.sleep(10)
                wait_for_linecard_to_be_unreachable(localhost, mgmt_ip, timeout=50)

            wait_for_linecard_to_be_reachable(localhost, mgmt_ip, timeout=200)
            break
        finally:
            chassis_grpc_info.get('channel').close()
