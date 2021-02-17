import ast
import logging
import pytest
import re
import time

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_require
from tests.platform_tests.thermal_control_test_helper import mocker_factory

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical')
]

STATE_DB = 'STATE_DB'
TABLE_NAME_SEPARATOR_VBAR = '|'
FAN_MOCK_WAIT_TIME = 75

# From RFC 2737, 1 means replaceable, 2 means not replaceable
REPLACEABLE = 1
NOT_REPLACEABLE = 2

# Physical Class From RFC 2737
PHYSICAL_CLASS_OTHER = 1
PHYSICAL_CLASS_UNKNOWN = 2
PHYSICAL_CLASS_CHASSIS = 3
PHYSICAL_CLASS_BACKPLANE = 4
PHYSICAL_CLASS_CONTAINER = 5
PHYSICAL_CLASS_POWERSUPPLY = 6
PHYSICAL_CLASS_FAN = 7
PHYSICAL_CLASS_SENSOR = 8
PHYSICAL_CLASS_MODULE = 9
PHYSICAL_CLASS_PORT = 10
PHYSICAL_CLASS_STACK = 11

# OID generating rule definition
# Moduel Type Definition
MODULE_TYPE_MULTIPLE = 100000000
MODULE_INDEX_MULTIPLE = 1000000
MODULE_TYPE_MGMT = 2 * MODULE_TYPE_MULTIPLE
MODULE_TYPE_FAN_DRAWER = 5 * MODULE_TYPE_MULTIPLE
MODULE_TYPE_PSU = 6 * MODULE_TYPE_MULTIPLE
MODULE_TYPE_PORT = 1000000000

# Device Type Definition
DEVICE_TYPE_MULTIPLE = 10000
DEVICE_INDEX_MULTIPLE = 100
DEVICE_TYPE_PS = 1 * DEVICE_TYPE_MULTIPLE
DEVICE_TYPE_FAN = 2 * DEVICE_TYPE_MULTIPLE
DEVICE_TYPE_CHASSIS_THERMAL = 99 * DEVICE_TYPE_MULTIPLE
DEVICE_TYPE_POWER_MONITOR = 24 * DEVICE_TYPE_MULTIPLE

# Sensor Type Definition
SENSOR_TYPE_MULTIPLE = 10
SENSOR_TYPE_TEMP = 1 * SENSOR_TYPE_MULTIPLE
SENSOR_TYPE_FAN = 2 * SENSOR_TYPE_MULTIPLE
SENSOR_TYPE_POWER = 3 * SENSOR_TYPE_MULTIPLE
SENSOR_TYPE_CURRENT = 4 * SENSOR_TYPE_MULTIPLE
SENSOR_TYPE_VOLTAGE = 5 * SENSOR_TYPE_MULTIPLE

# Port entPhysicalIndex Definition
PORT_IFINDEX_MULTIPLE = 100
SENSOR_TYPE_PORT_TX_POWER = 2 * SENSOR_TYPE_MULTIPLE
SENSOR_TYPE_PORT_RX_POWER = 3 * SENSOR_TYPE_MULTIPLE
SENSOR_TYPE_PORT_TX_BIAS = 4 * SENSOR_TYPE_MULTIPLE

CHASSIS_SUB_ID = 1
CHASSIS_MGMT_SUB_ID = MODULE_TYPE_MGMT

# field_name : (name, position)
PSU_SENSOR_INFO = {
    'temp': ('Temperature', 1, SENSOR_TYPE_TEMP),
    'power': ('Power', 2, SENSOR_TYPE_POWER),
    'current': ('Current', 3, SENSOR_TYPE_CURRENT),
    'voltage': ('Voltage', 4, SENSOR_TYPE_VOLTAGE),
}

# The sort factor values are got from https://github.com/Azure/sonic-snmpagent/blob/dfde06e2f5d70e23882af6c0f1af4ae43ec2fa43/src/sonic_ax_impl/mibs/ietf/transceiver_sensor_data.py#L18
XCVR_SENSOR_PATTERN = {
    'temperature': {'sort_factor': 0, 'oid_base': SENSOR_TYPE_TEMP, 'extract_line_number': False},
    'voltage': {'sort_factor': 9000, 'oid_base': SENSOR_TYPE_VOLTAGE, 'extract_line_number': False},
    'tx(\d+)power': {'sort_factor': 1000, 'oid_base': SENSOR_TYPE_PORT_TX_POWER, 'extract_line_number': True},
    'rx(\d+)power': {'sort_factor': 2000, 'oid_base': SENSOR_TYPE_PORT_RX_POWER, 'extract_line_number': True},
    'tx(\d+)bias': {'sort_factor': 3000, 'oid_base': SENSOR_TYPE_PORT_TX_BIAS, 'extract_line_number': True}}

# Constants
CHASSIS_KEY = 'chassis 1'
FAN_DRAWER_KEY_TEMPLATE = 'FAN_DRAWER_INFO|{}'
FAN_KEY_TEMPLATE = 'FAN_INFO|{}'
PSU_KEY_TEMPLATE = 'PSU_INFO|{}'
THERMAL_KEY_TEMPLATE = 'TEMPERATURE_INFO|{}'
PHYSICAL_ENTITY_KEY_TEMPLATE = 'PHYSICAL_ENTITY_INFO|{}'
XCVR_KEY_TEMPLATE = 'TRANSCEIVER_INFO|{}'
XCVR_DOM_KEY_TEMPLATE = 'TRANSCEIVER_DOM_SENSOR|{}'


@pytest.fixture(autouse=True, scope="module")
def check_image_version(duthost):
    """Skip the test for unsupported images."""
    pytest_require("201911" not in duthost.os_version, "Test not supported for 201911 images. Skipping the test")
    yield


@pytest.fixture(scope="module")
def snmp_physical_entity_info(duthost, localhost, creds):
    """
    Module level fixture for getting physical entity information from snmp fact
    :param duthost: DUT host object
    :param localhost: localhost object
    :param creds: Credential for snmp
    :return:
    """
    return get_entity_mib(duthost, localhost, creds)


def get_entity_mib(duthost, localhost, creds):
    """
    Get physical entity information from snmp fact
    :param duthost: DUT host object
    :param localhost: localhost object
    :param creds: Credential for snmp
    :return:
    """
    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    snmp_facts = localhost.snmp_facts(host=hostip, version="v2c", community=creds["snmp_rocommunity"])['ansible_facts']
    entity_mib = {}
    for oid, info in snmp_facts['snmp_physical_entities'].items():
        entity_mib[int(oid)] = info
    return entity_mib


def test_fan_drawer_info(duthost, snmp_physical_entity_info):
    """
    Verify fan drawer information in physical entity mib with redis database
    :param duthost: DUT host object
    :param snmp_physical_entity_info: Physical entity information from snmp fact
    :return:
    """
    keys = redis_get_keys(duthost, STATE_DB, FAN_DRAWER_KEY_TEMPLATE.format('*'))
    # Ignore the test if the platform does not support fan drawer
    if not keys:
        pytest.skip('Fan drawer information does not exist in DB, skipping this test')
    for key in keys:
        drawer_info = redis_hgetall(duthost, STATE_DB, key)
        name = key.split(TABLE_NAME_SEPARATOR_VBAR)[-1]
        entity_info_key = PHYSICAL_ENTITY_KEY_TEMPLATE.format(name)
        entity_info = redis_hgetall(duthost, STATE_DB, entity_info_key)
        position = int(entity_info['position_in_parent'])
        expect_oid = MODULE_TYPE_FAN_DRAWER + position * MODULE_INDEX_MULTIPLE
        assert expect_oid in snmp_physical_entity_info, 'Cannot find fan drawer {} in physical entity mib'.format(name)

        drawer_snmp_fact = snmp_physical_entity_info[expect_oid]
        assert drawer_snmp_fact['entPhysDescr'] == name
        assert drawer_snmp_fact['entPhysContainedIn'] == CHASSIS_SUB_ID
        assert drawer_snmp_fact['entPhysClass'] == PHYSICAL_CLASS_CONTAINER
        assert drawer_snmp_fact['entPhyParentRelPos'] == position
        assert drawer_snmp_fact['entPhysName'] == name
        assert drawer_snmp_fact['entPhysHwVer'] == ''
        assert drawer_snmp_fact['entPhysFwVer'] == ''
        assert drawer_snmp_fact['entPhysSwVer'] == ''
        assert drawer_snmp_fact['entPhysSerialNum'] == '' if is_null_str(drawer_info['serial']) else drawer_info[
            'serial']
        assert drawer_snmp_fact['entPhysMfgName'] == ''
        assert drawer_snmp_fact['entPhysModelName'] == '' if is_null_str(drawer_info['model']) else drawer_info['model']
        assert drawer_snmp_fact['entPhysIsFRU'] == REPLACEABLE if drawer_info[
                                                                      'is_replaceable'] == 'True' else NOT_REPLACEABLE


def test_fan_info(duthost, snmp_physical_entity_info):
    """
    Verify fan information in physical entity mib with redis database
    :param duthost: DUT host object
    :param snmp_physical_entity_info: Physical entity information from snmp fact
    :return:
    """
    keys = redis_get_keys(duthost, STATE_DB, FAN_KEY_TEMPLATE.format('*'))
    assert keys, 'Fan information does not exist in DB'
    for key in keys:
        fan_info = redis_hgetall(duthost, STATE_DB, key)
        name = key.split(TABLE_NAME_SEPARATOR_VBAR)[-1]
        entity_info_key = PHYSICAL_ENTITY_KEY_TEMPLATE.format(name)
        entity_info = redis_hgetall(duthost, STATE_DB, entity_info_key)
        position = int(entity_info['position_in_parent'])
        parent_name = entity_info['parent_name']
        if parent_name == CHASSIS_KEY:
            parent_oid = MODULE_TYPE_FAN_DRAWER + position * MODULE_INDEX_MULTIPLE
        else:
            parent_entity_info = redis_hgetall(duthost, STATE_DB, PHYSICAL_ENTITY_KEY_TEMPLATE.format(parent_name))
            parent_position = int(parent_entity_info['position_in_parent'])
            if 'PSU' in parent_name:
                parent_oid = MODULE_TYPE_PSU + parent_position * MODULE_INDEX_MULTIPLE
            else:
                parent_oid = MODULE_TYPE_FAN_DRAWER + parent_position * MODULE_INDEX_MULTIPLE
        expect_oid = parent_oid + DEVICE_TYPE_FAN + position * DEVICE_INDEX_MULTIPLE
        assert expect_oid in snmp_physical_entity_info, 'Cannot find fan {} in physical entity mib'.format(name)
        fan_snmp_fact = snmp_physical_entity_info[expect_oid]
        assert fan_snmp_fact['entPhysDescr'] == name
        assert fan_snmp_fact['entPhysContainedIn'] == CHASSIS_SUB_ID if parent_name == CHASSIS_KEY else parent_oid
        assert fan_snmp_fact['entPhysClass'] == PHYSICAL_CLASS_FAN
        assert fan_snmp_fact['entPhyParentRelPos'] == position
        assert fan_snmp_fact['entPhysName'] == name
        assert fan_snmp_fact['entPhysHwVer'] == ''
        assert fan_snmp_fact['entPhysFwVer'] == ''
        assert fan_snmp_fact['entPhysSwVer'] == ''
        assert fan_snmp_fact['entPhysSerialNum'] == '' if is_null_str(fan_info['serial']) else fan_info[
            'serial']
        assert fan_snmp_fact['entPhysMfgName'] == ''
        assert fan_snmp_fact['entPhysModelName'] == '' if is_null_str(fan_info['model']) else fan_info['model']
        assert fan_snmp_fact['entPhysIsFRU'] == REPLACEABLE if fan_info['is_replaceable'] == 'True' else NOT_REPLACEABLE

        if not is_null_str(fan_info['speed']):
            tachometers_oid = expect_oid + SENSOR_TYPE_FAN
            assert tachometers_oid in snmp_physical_entity_info, 'Cannot find fan tachometers info in physical entity mib'
            tachometers_fact = snmp_physical_entity_info[tachometers_oid]
            assert tachometers_fact['entPhysDescr'] == 'Tachometers for {}'.format(name)
            assert tachometers_fact['entPhysContainedIn'] == expect_oid
            assert tachometers_fact['entPhysClass'] == PHYSICAL_CLASS_SENSOR
            assert tachometers_fact['entPhyParentRelPos'] == 1
            assert tachometers_fact['entPhysName'] == 'Tachometers for {}'.format(name)
            assert tachometers_fact['entPhysHwVer'] == ''
            assert tachometers_fact['entPhysFwVer'] == ''
            assert tachometers_fact['entPhysSwVer'] == ''
            assert tachometers_fact['entPhysSerialNum'] == ''
            assert tachometers_fact['entPhysMfgName'] == ''
            assert tachometers_fact['entPhysModelName'] == ''
            assert tachometers_fact['entPhysIsFRU'] == NOT_REPLACEABLE


def test_psu_info(duthost, snmp_physical_entity_info):
    """
    Verify PSU information in physical entity mib with redis database
    :param duthost: DUT host object
    :param snmp_physical_entity_info: Physical entity information from snmp fact
    :return:
    """
    keys = redis_get_keys(duthost, STATE_DB, PSU_KEY_TEMPLATE.format('*'))
    assert keys, 'PSU information does not exist in DB'
    for key in keys:
        psu_info = redis_hgetall(duthost, STATE_DB, key)
        name = key.split(TABLE_NAME_SEPARATOR_VBAR)[-1]
        entity_info_key = PHYSICAL_ENTITY_KEY_TEMPLATE.format(name)
        entity_info = redis_hgetall(duthost, STATE_DB, entity_info_key)
        position = int(entity_info['position_in_parent'])
        expect_oid = MODULE_TYPE_PSU + position * MODULE_INDEX_MULTIPLE
        if psu_info['presence'] != 'true':
            assert expect_oid not in snmp_physical_entity_info
            continue

        assert expect_oid in snmp_physical_entity_info, 'Cannot find PSU {} in physical entity mib'.format(name)
        psu_snmp_fact = snmp_physical_entity_info[expect_oid]
        assert psu_snmp_fact['entPhysDescr'] == name
        assert psu_snmp_fact['entPhysContainedIn'] == CHASSIS_SUB_ID
        assert psu_snmp_fact['entPhysClass'] == PHYSICAL_CLASS_POWERSUPPLY
        assert psu_snmp_fact['entPhyParentRelPos'] == position
        assert psu_snmp_fact['entPhysName'] == name
        assert psu_snmp_fact['entPhysHwVer'] == ''
        assert psu_snmp_fact['entPhysFwVer'] == ''
        assert psu_snmp_fact['entPhysSwVer'] == ''
        assert psu_snmp_fact['entPhysSerialNum'] == '' if is_null_str(psu_info['serial']) else psu_info[
            'serial']
        assert psu_snmp_fact['entPhysMfgName'] == ''
        assert psu_snmp_fact['entPhysModelName'] == '' if is_null_str(psu_info['model']) else psu_info['model']
        assert psu_snmp_fact['entPhysIsFRU'] == REPLACEABLE if psu_info['is_replaceable'] == 'True' else NOT_REPLACEABLE

        _check_psu_sensor(name, psu_info, expect_oid, snmp_physical_entity_info)


def _check_psu_sensor(psu_name, psu_info, psu_oid, snmp_physical_entity_info):
    """
    Check PSU sensor information in physical entity mib
    :param psu_name: PSU name
    :param psu_info: PSU information got from db
    :param psu_oid: PSU oid
    :param snmp_physical_entity_info: Physical entity information from snmp fact
    :return:
    """
    for field, sensor_tuple in PSU_SENSOR_INFO.items():
        expect_oid = psu_oid + DEVICE_TYPE_POWER_MONITOR + sensor_tuple[2]
        if is_null_str(psu_info[field]):
            assert expect_oid not in snmp_physical_entity_info
            continue

        assert expect_oid in snmp_physical_entity_info, 'Cannot find PSU sensor {} in physical entity mib'.format(field)
        sensor_snmp_fact = snmp_physical_entity_info[expect_oid]
        sensor_name = '{sensor_name} for {psu_name}'.format(sensor_name=sensor_tuple[0], psu_name=psu_name)
        assert sensor_snmp_fact['entPhysDescr'] == sensor_name
        assert sensor_snmp_fact['entPhysContainedIn'] == psu_oid
        assert sensor_snmp_fact['entPhysClass'] == PHYSICAL_CLASS_SENSOR
        assert sensor_snmp_fact['entPhyParentRelPos'] == sensor_tuple[1]
        assert sensor_snmp_fact['entPhysName'] == sensor_name
        assert sensor_snmp_fact['entPhysHwVer'] == ''
        assert sensor_snmp_fact['entPhysFwVer'] == ''
        assert sensor_snmp_fact['entPhysSwVer'] == ''
        assert sensor_snmp_fact['entPhysSerialNum'] == ''
        assert sensor_snmp_fact['entPhysMfgName'] == ''
        assert sensor_snmp_fact['entPhysModelName'] == ''
        assert sensor_snmp_fact['entPhysIsFRU'] == NOT_REPLACEABLE


def test_thermal_info(duthost, snmp_physical_entity_info):
    """
    Verify thermal information in physical entity mib with redis database
    :param duthost: DUT host object
    :param snmp_physical_entity_info: Physical entity information from snmp fact
    :return:
    """
    keys = redis_get_keys(duthost, STATE_DB, THERMAL_KEY_TEMPLATE.format('*'))
    assert keys, 'Thermal information does not exist in DB'
    for key in keys:
        thermal_info = redis_hgetall(duthost, STATE_DB, key)
        if is_null_str(thermal_info['temperature']):
            continue
        name = key.split(TABLE_NAME_SEPARATOR_VBAR)[-1]
        entity_info_key = PHYSICAL_ENTITY_KEY_TEMPLATE.format(name)
        entity_info = redis_hgetall(duthost, STATE_DB, entity_info_key)
        if not entity_info or entity_info['parent_name'] != CHASSIS_KEY:
            continue
        position = int(entity_info['position_in_parent'])
        expect_oid = CHASSIS_MGMT_SUB_ID + DEVICE_TYPE_CHASSIS_THERMAL + position * DEVICE_INDEX_MULTIPLE + SENSOR_TYPE_TEMP
        assert expect_oid in snmp_physical_entity_info, 'Cannot find thermal {} in physical entity mib'.format(name)
        thermal_snmp_fact = snmp_physical_entity_info[expect_oid]
        assert thermal_snmp_fact['entPhysDescr'] == name
        assert thermal_snmp_fact['entPhysContainedIn'] == CHASSIS_MGMT_SUB_ID
        assert thermal_snmp_fact['entPhysClass'] == PHYSICAL_CLASS_SENSOR
        assert thermal_snmp_fact['entPhyParentRelPos'] == position
        assert thermal_snmp_fact['entPhysName'] == name
        assert thermal_snmp_fact['entPhysHwVer'] == ''
        assert thermal_snmp_fact['entPhysFwVer'] == ''
        assert thermal_snmp_fact['entPhysSwVer'] == ''
        assert thermal_snmp_fact['entPhysSerialNum'] == ''
        assert thermal_snmp_fact['entPhysMfgName'] == ''
        assert thermal_snmp_fact['entPhysModelName'] == ''
        assert thermal_snmp_fact['entPhysIsFRU'] == NOT_REPLACEABLE


def test_transceiver_info(duthost, snmp_physical_entity_info):
    """
    Verify transceiver information in physical entity mib with redis database
    :param duthost: DUT host object
    :param snmp_physical_entity_info: Physical entity information from snmp fact
    :return:
    """
    keys = redis_get_keys(duthost, STATE_DB, XCVR_KEY_TEMPLATE.format('*'))
    assert keys, 'Transceiver information does not exist in DB'

    name_to_snmp_facts = {}
    for oid, values in snmp_physical_entity_info.items():
        values['oid'] = oid
        name_to_snmp_facts[values['entPhysName']] = values
    for key in keys:
        name = key.split(TABLE_NAME_SEPARATOR_VBAR)[-1]
        assert name in name_to_snmp_facts, 'Cannot find port {} in physical entity mib'.format(name)
        transceiver_info = redis_hgetall(duthost, STATE_DB, key)
        transceiver_snmp_fact = name_to_snmp_facts[name]
        assert transceiver_snmp_fact['entPhysDescr'] is not None
        assert transceiver_snmp_fact['entPhysContainedIn'] == CHASSIS_SUB_ID
        assert transceiver_snmp_fact['entPhysClass'] == PHYSICAL_CLASS_PORT
        assert transceiver_snmp_fact['entPhyParentRelPos'] == -1
        assert transceiver_snmp_fact['entPhysName'] == name
        assert transceiver_snmp_fact['entPhysHwVer'] == transceiver_info['hardware_rev']
        assert transceiver_snmp_fact['entPhysFwVer'] == ''
        assert transceiver_snmp_fact['entPhysSwVer'] == ''
        assert transceiver_snmp_fact['entPhysSerialNum'] == transceiver_info['serial']
        assert transceiver_snmp_fact['entPhysMfgName'] == transceiver_info['manufacturer']
        assert transceiver_snmp_fact['entPhysModelName'] == transceiver_info['model']
        assert transceiver_snmp_fact['entPhysIsFRU'] == REPLACEABLE if transceiver_info[
                                                                           'is_replaceable'] == 'True' else NOT_REPLACEABLE
        _check_transceiver_dom_sensor_info(duthost, name, transceiver_snmp_fact['oid'], snmp_physical_entity_info)


def _check_transceiver_dom_sensor_info(duthost, name, transceiver_oid, snmp_physical_entity_info):
    """
    Check transceiver DOM sensor information in physical entity mib
    :param duthost: DUT host object
    :param name: Transceiver name
    :param transceiver_oid: Transceiver oid
    :param snmp_physical_entity_info: Physical entity information from snmp fact
    :return:
    """
    sensor_data_list = _get_transceiver_sensor_data(duthost, name)
    for index, sensor_data in enumerate(sensor_data_list):
        expect_oid = transceiver_oid + sensor_data.oid_offset
        assert expect_oid in snmp_physical_entity_info, 'Cannot find port sensor in physical entity mib'
        sensor_snmp_fact = snmp_physical_entity_info[expect_oid]
        assert sensor_snmp_fact['entPhysDescr'] is not None
        assert sensor_snmp_fact['entPhysContainedIn'] == transceiver_oid
        assert sensor_snmp_fact['entPhysClass'] == PHYSICAL_CLASS_SENSOR
        assert sensor_snmp_fact['entPhyParentRelPos'] == index + 1
        assert sensor_snmp_fact['entPhysName'] is not None
        assert sensor_snmp_fact['entPhysHwVer'] == ''
        assert sensor_snmp_fact['entPhysFwVer'] == ''
        assert sensor_snmp_fact['entPhysSwVer'] == ''
        assert sensor_snmp_fact['entPhysSerialNum'] == ''
        assert sensor_snmp_fact['entPhysMfgName'] == ''
        assert sensor_snmp_fact['entPhysModelName'] == ''
        assert sensor_snmp_fact['entPhysIsFRU'] == NOT_REPLACEABLE


class SensorData(object):
    def __init__(self, key, value, sort_factor, oid_offset):
        self.key = key
        self.value = value
        self.sort_factor = sort_factor
        self.oid_offset = oid_offset


def _get_transceiver_sensor_data(duthost, name):
    key = XCVR_DOM_KEY_TEMPLATE.format(name)
    sensor_info = redis_hgetall(duthost, STATE_DB, key)
    sensor_data_list = []
    for field, value in sensor_info.items():
        for pattern, data in XCVR_SENSOR_PATTERN.items():
            match_result = re.match(pattern, field)
            if match_result:
                if data['extract_line_number']:
                    lane_number = int(match_result.group(1))
                    sort_factor = data['sort_factor'] + lane_number
                    oid_offset = data['oid_base'] + lane_number
                else:
                    sort_factor = data['sort_factor']
                    oid_offset = data['oid_base']
                sensor_data_list.append(SensorData(field, value, sort_factor, oid_offset))
                break

    sensor_data_list = sorted(sensor_data_list, key=lambda x: x.sort_factor)
    return sensor_data_list


@pytest.mark.disable_loganalyzer
def test_turn_off_pdu_and_check_psu_info(duthost, localhost, creds, pdu_controller):
    """
    Turn off one PSU and check all PSU sensor entity being removed because it can no longer get any value
    :param duthost: DUT host object
    :param localhost: localhost object
    :param creds: Credential for snmp
    :param pdu_controller: PDU controller
    :return:
    """
    if not pdu_controller:
        pytest.skip('pdu_controller is None, skipping this test')
    outlet_status = pdu_controller.get_outlet_status()
    if len(outlet_status) < 2:
        pytest.skip('At least 2 outlets required for rest of the testing in this case')

    # turn on all PSU
    for item in outlet_status:
        if not item['outlet_on']:
            pdu_controller.turn_on_outlet(item["outlet_id"])
    time.sleep(5)

    outlet_status = pdu_controller.get_outlet_status()
    for item in outlet_status:
        if not item['outlet_on']:
            pytest.skip('Not all outlet are powered on, skip rest of the testing in this case')

    # turn off the first PSU
    first_outlet_id = outlet_status[0]['outlet_id']
    pdu_controller.turn_off_outlet(first_outlet_id)
    assert wait_until(30, 5, check_outlet_status, pdu_controller, first_outlet_id, False)
    # wait for psud update the database
    assert wait_until(120, 20, _check_psu_status_after_power_off, duthost, localhost, creds)


def _check_psu_status_after_power_off(duthost, localhost, creds):
    """
    Check that at least one PSU is powered off and its sensor information should be removed from mib
    :param duthost: DUT host object
    :param localhost: localhost object
    :param creds: Credential for snmp
    :return: True if sensor information is removed from mib
    """
    mib_info = get_entity_mib(duthost, localhost, creds)
    keys = redis_get_keys(duthost, STATE_DB, PSU_KEY_TEMPLATE.format('*'))
    power_off_psu_found = False
    for key in keys:
        psu_info = redis_hgetall(duthost, STATE_DB, key)
        name = key.split(TABLE_NAME_SEPARATOR_VBAR)[-1]
        entity_info_key = PHYSICAL_ENTITY_KEY_TEMPLATE.format(name)
        entity_info = redis_hgetall(duthost, STATE_DB, entity_info_key)
        position = int(entity_info['position_in_parent'])
        expect_oid = MODULE_TYPE_PSU + position * MODULE_INDEX_MULTIPLE
        if psu_info['status'] != 'true':
            assert expect_oid in mib_info
            for field, sensor_tuple in PSU_SENSOR_INFO.items():
                sensor_oid = expect_oid + DEVICE_TYPE_POWER_MONITOR + sensor_tuple[2]
                if sensor_oid not in mib_info:
                    power_off_psu_found = True
                    break
    return power_off_psu_found


@pytest.mark.disable_loganalyzer
def test_remove_insert_fan_and_check_fan_info(duthost, localhost, creds, mocker_factory):
    """

    :param duthost: DUT host object
    :param localhost: localhost object
    :param creds: Credential for snmp
    :param mocker_factory: Factory to create fan mocker
    :return:
    """
    logging.info('Create mocker, it may take a few seconds...')
    single_fan_mocker = mocker_factory(duthost, 'SingleFanMocker')
    if not single_fan_mocker:
        pytest.skip('Fan mocker not support on this platform, skip the rest of the test')
    if not single_fan_mocker.is_fan_removable():
        pytest.skip('Fan is not removable on this platform, skip the rest of the test')
    logging.info('Mock FAN absence...')
    single_fan_mocker.mock_absence()

    logging.info('Wait {} seconds for thermalctld to update the fan information to DB'.format(FAN_MOCK_WAIT_TIME))
    time.sleep(FAN_MOCK_WAIT_TIME)

    keys = redis_get_keys(duthost, STATE_DB, FAN_KEY_TEMPLATE.format('*'))
    assert keys, 'Fan information does not exist in DB'
    mib_info = get_entity_mib(duthost, localhost, creds)
    for key in keys:
        fan_info = redis_hgetall(duthost, STATE_DB, key)
        if fan_info['presence'] == 'True':
            continue
        name = key.split(TABLE_NAME_SEPARATOR_VBAR)[-1]
        entity_info_key = PHYSICAL_ENTITY_KEY_TEMPLATE.format(name)
        entity_info = redis_hgetall(duthost, STATE_DB, entity_info_key)
        position = int(entity_info['position_in_parent'])
        parent_name = entity_info['parent_name']
        if 'PSU' in parent_name:
            continue
        if parent_name == CHASSIS_KEY:
            parent_oid = MODULE_TYPE_FAN_DRAWER + position * MODULE_INDEX_MULTIPLE
        else:
            parent_entity_info = redis_hgetall(duthost, STATE_DB, PHYSICAL_ENTITY_KEY_TEMPLATE.format(parent_name))
            parent_position = int(parent_entity_info['position_in_parent'])
            parent_oid = MODULE_TYPE_FAN_DRAWER + parent_position * MODULE_INDEX_MULTIPLE
        expect_oid = parent_oid + DEVICE_TYPE_FAN + position * DEVICE_INDEX_MULTIPLE
        assert expect_oid not in mib_info, 'Absence fan should not in mib'.format(name)

        if not is_null_str(fan_info['speed']):
            tachometers_oid = expect_oid + SENSOR_TYPE_FAN
            assert tachometers_oid not in mib_info, 'Absence fan tachometers info should not in mib'


def redis_get_keys(duthost, db_id, pattern):
    """
    Get all keys for a given pattern in given redis database
    :param duthost: DUT host object
    :param db_id: ID of redis database
    :param pattern: Redis key pattern
    :return: A list of key name in string
    """
    cmd = 'sonic-db-cli {} KEYS \"{}\"'.format(db_id, pattern)
    logging.debug('Getting keys from redis by command: {}'.format(cmd))
    output = duthost.shell(cmd)
    content = output['stdout'].strip()
    return content.split('\n') if content else None


def redis_hgetall(duthost, db_id, key):
    """
    Get all field name and values for a given key in given redis dataabse
    :param duthost: DUT host object
    :param db_id: ID of redis database
    :param key: Redis Key
    :return: A dictionary, key is field name, value is field value
    """
    cmd = 'sonic-db-cli {} HGETALL \"{}\"'.format(db_id, key)
    output = duthost.shell(cmd)
    content = output['stdout'].strip()
    if not content:
        return {}

    return ast.literal_eval(content)


def is_null_str(value):
    """
    Indicate if a string is None or 'None' or 'N/A'
    :param value: A string value
    :return: True if a string is None or 'None' or 'N/A'
    """
    return not value or value == str(None) or value == 'N/A'


def check_outlet_status(pdu_controller, outlet_id, expect_status):
    """
    Check if a given PSU is at expect status
    :param pdu_controller: PDU controller
    :param outlet_id: outlet id
    :param expect_status: Expect bool status, True means on, False means off
    :return: True if a given PSU is at expect status
    """
    status = pdu_controller.get_outlet_status(outlet_id)
    return 'outlet_on' in status[0] and status[0]['outlet_on'] == expect_status
