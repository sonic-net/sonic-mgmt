import ast
import logging
import pytest
import re
import time
import random
from enum import Enum, unique
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_require
from tests.common.helpers.snmp_helpers import get_snmp_facts
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.psu_helpers import turn_on_all_outlets, check_outlet_status, get_grouped_pdus_by_psu
from tests.common.helpers.thermal_control_test_helper import mocker_factory     # noqa F401

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
MODULE_TYPE_FABRIC_CARD = 7 * MODULE_TYPE_MULTIPLE
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


@unique
class EntitySensorDataType(int, Enum):
    """
    Enumeration of sensor data types according to RFC3433
    (https://tools.ietf.org/html/rfc3433)
    """

    OTHER = 1
    UNKNOWN = 2
    VOLTS_AC = 3
    VOLTS_DC = 4
    AMPERES = 5
    WATTS = 6
    HERTZ = 7
    CELSIUS = 8
    PERCENT_RH = 9
    RPM = 10
    CMM = 11
    TRUTHVALUE = 12


@unique
class EntitySensorDataScale(int, Enum):
    """
    Enumeration of sensor data scale types according to RFC3433
    (https://tools.ietf.org/html/rfc3433)
    """

    YOCTO = 1
    ZEPTO = 2
    ATTO = 3
    FEMTO = 4
    PICO = 5
    NANO = 6
    MICRO = 7
    MILLI = 8
    UNITS = 9
    KILO = 10
    MEGA = 11
    GIGA = 12
    TERA = 13
    EXA = 14
    PETA = 15
    ZETTA = 16
    YOTTA = 17


@unique
class EntitySensorStatus(int, Enum):
    """
    Enumeration of sensor operational status according to RFC3433
    (https://tools.ietf.org/html/rfc3433)
    """

    OK = 1
    UNAVAILABLE = 2
    NONOPERATIONAL = 3


# field_name : (name, position)
PSU_SENSOR_INFO = {
    'temp': ('Temperature', 1, SENSOR_TYPE_TEMP),
    'power': ('Power', 2, SENSOR_TYPE_POWER),
    'current': ('Current', 3, SENSOR_TYPE_CURRENT),
    'voltage': ('Voltage', 4, SENSOR_TYPE_VOLTAGE),
}

# The sort factor values are got from
# https://github.com/sonic-net/sonic-snmpagent/blob/dfde06e2f5d70e23882af6c0f1af4ae43ec2fa43/src/sonic_ax_impl/mibs/ietf/transceiver_sensor_data.py#L18     # noqa E501
XCVR_SENSOR_PATTERN = {
    'temperature': {'sort_factor': 0, 'oid_base': SENSOR_TYPE_TEMP, 'extract_line_number': False},
    'voltage': {'sort_factor': 9000, 'oid_base': SENSOR_TYPE_VOLTAGE, 'extract_line_number': False},
    r'tx(\d+)power': {'sort_factor': 1000, 'oid_base': SENSOR_TYPE_PORT_TX_POWER, 'extract_line_number': True},
    r'rx(\d+)power': {'sort_factor': 2000, 'oid_base': SENSOR_TYPE_PORT_RX_POWER, 'extract_line_number': True},
    r'tx(\d+)bias': {'sort_factor': 3000, 'oid_base': SENSOR_TYPE_PORT_TX_BIAS, 'extract_line_number': True}}

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
def check_image_version(duthosts):
    """Skip the test for unsupported images."""
    for duthost in duthosts:
        pytest_require("201911" not in duthost.os_version,
                       "Test not supported for 201911 images. Skipping the test")
    yield


def is_sensor_test_supported(duthost):
    """
    Check whether new sensor test is supported in the image.
    The new sensor test is not supported in 201811, 201911 and 202012
    The assumption is that image under test always has a correct version.
    If image version doesn't including above "version keyword", it will be considered
    as a newer version which support the new sensor test.
    """
    if "201811" in duthost.os_version or "201911" in duthost.os_version or "202012" in duthost.os_version:
        logging.info("Image doesn't support new sensor test, image version {}, test will be skipped".format(
            duthost.os_version))
        return False
    else:
        logging.info("Image support new sensor test, image version {}, test will be performed".format(
            duthost.os_version))
        return True


@pytest.fixture(scope="module")
def snmp_physical_entity_and_sensor_info(duthosts, enum_rand_one_per_hwsku_hostname, localhost, creds_all_duts):
    """
    Module level fixture for getting physical entity information from snmp fact for frontend dut
    :param duthost: DUT host object
    :param localhost: localhost object
    :param creds_all_duts: Credential for snmp
    :return:
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    return get_entity_and_sensor_mib(duthost, localhost, creds_all_duts)


def get_entity_and_sensor_mib(duthost, localhost, creds_all_duts):
    """
    Get physical entity information from snmp fact
    :param duthost: DUT host object
    :param localhost: localhost object
    :param creds_all_duts: Credential for snmp
    :return:
    """
    mib_info = {}
    hostip = duthost.host.options['inventory_manager'].get_host(
        duthost.hostname).vars['ansible_host']
    snmp_facts = get_snmp_facts(
        duthost, localhost, host=hostip, version="v2c",
        community=creds_all_duts[duthost.hostname]["snmp_rocommunity"], wait=True)['ansible_facts']
    entity_mib = {}
    sensor_mib = {}
    for oid, info in list(snmp_facts['snmp_physical_entities'].items()):
        entity_mib[int(oid)] = info
    for oid, info in list(snmp_facts['snmp_sensors'].items()):
        sensor_mib[int(oid)] = info

    mib_info["entity_mib"] = entity_mib
    mib_info["sensor_mib"] = sensor_mib

    return mib_info


def test_fabric_card_info(duthosts, enum_rand_one_per_hwsku_hostname, snmp_physical_entity_and_sensor_info):
    """
    Verify fabric module information in physical entity mib with redis database
    :param duthost: DUT host object
    :param snmp_physical_entity_info: Physical entity information from snmp fact
    :return:
    """
    snmp_physical_entity_info = snmp_physical_entity_and_sensor_info["entity_mib"]
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if not duthost.is_supervisor_node():
        pytest.skip("Not supported on non supervisor node")
    keys = redis_get_keys(
        duthost, STATE_DB, PHYSICAL_ENTITY_KEY_TEMPLATE.format('FABRIC-CARD*'))
    # Ignore the test if the platform does not support fan drawer
    if not keys:
        pytest.skip(
            'Fabric Card information does not exist in DB, skipping this test')
    for key in keys:
        fc_info = redis_hgetall(duthost, STATE_DB, key)
        name = key.split(TABLE_NAME_SEPARATOR_VBAR)[-1]
        entity_info_key = PHYSICAL_ENTITY_KEY_TEMPLATE.format(name)
        entity_info = redis_hgetall(duthost, STATE_DB, entity_info_key)
        position = int(entity_info['position_in_parent'])
        expect_oid = MODULE_TYPE_FABRIC_CARD + position * MODULE_INDEX_MULTIPLE
        assert expect_oid in snmp_physical_entity_info, (
            "Cannot find expected fan drawer OID '{}' in physical entity MIB."
        ).format(expect_oid)

        fc_snmp_fact = snmp_physical_entity_info[expect_oid]
        assert fc_snmp_fact['entPhysDescr'] == name, (
            "Fabric card description mismatch. Expected 'entPhysDescr' to be '{}', "
            "but got '{}'."
        ).format(
            name,
            fc_snmp_fact['entPhysDescr']
        )

        assert fc_snmp_fact['entPhysContainedIn'] == CHASSIS_SUB_ID, (
            "Fabric card containment mismatch. Expected '{}', but got '{}'."
        ).format(
            CHASSIS_SUB_ID,
            fc_snmp_fact['entPhysContainedIn']
        )

        assert fc_snmp_fact['entPhysClass'] == PHYSICAL_CLASS_MODULE, (
            "Fabric card class mismatch. Expected '{}', but got '{}'."
        ).format(
            PHYSICAL_CLASS_MODULE,
            fc_snmp_fact['entPhysClass']
        )

        assert fc_snmp_fact['entPhyParentRelPos'] == position, (
            "Fabric card relative position mismatch. Expected '{}', but got '{}'."
        ).format(
            position,
            fc_snmp_fact['entPhyParentRelPos']
        )

        assert fc_snmp_fact['entPhysName'] == name, (
            "Fabric card name mismatch. Expected '{}', but got '{}'."
        ).format(
            name,
            fc_snmp_fact['entPhysName']
        )

        assert fc_snmp_fact['entPhysHwVer'] == '', (
            "Fabric card hardware version is not empty. Expected empty string, but got '{}'."
        ).format(
            fc_snmp_fact['entPhysHwVer']
        )

        assert fc_snmp_fact['entPhysFwVer'] == '', (
            "Fabric card firmware version is not empty. Expected empty string, but got '{}'."
        ).format(
            fc_snmp_fact['entPhysFwVer']
        )

        assert fc_snmp_fact['entPhysSwVer'] == '', (
            "Fabric card software version is not empty. Expected empty string, but got '{}'."
        ).format(
            fc_snmp_fact['entPhysSwVer']
        )

        assert fc_snmp_fact['entPhysSerialNum'] == ('' if is_null_str(fc_info['serial']) else fc_info['serial']), (
            "Fabric card serial number mismatch.\n"
            "Expected serial: '{}'\n"
            "Actual serial from SNMP: '{}'"
        ).format(
            fc_info['serial'],
            fc_snmp_fact['entPhysSerialNum']
        )

        assert fc_snmp_fact['entPhysMfgName'] == '', (
            "Fabric card manufacturer name is not empty. Expected empty string, but got '{}'."
        ).format(
            fc_snmp_fact['entPhysMfgName']
        )

        assert fc_snmp_fact['entPhysModelName'] == '' if is_null_str(
            fc_info['model']) else fc_info['model'], (
            "Fabric card model name mismatch.\n"
            "Expected model: '{}'\n"
            "Actual model from SNMP: '{}'"
        ).format(
            fc_info['model'],
            fc_snmp_fact['entPhysModelName']
        )
        assert fc_snmp_fact['entPhysIsFRU'] == REPLACEABLE if fc_info[
            'is_replaceable'] == 'True' else NOT_REPLACEABLE, (
             "Fabric card is FRU mismatch. fc_info['is_replaceable'] is '{}', fc_snmp_fact['entPhysIsFRU'] is '{}'."
        ).format(
            fc_info['is_replaceable'],
            fc_snmp_fact['entPhysIsFRU']
        )


def test_fan_drawer_info(duthosts, enum_rand_one_per_hwsku_hostname, snmp_physical_entity_and_sensor_info):
    """
    Verify fan drawer information in physical entity mib with redis database
    :param duthost: DUT host object
    :param snmp_physical_entity_info: Physical entity information from snmp fact
    :return:
    """
    snmp_physical_entity_info = snmp_physical_entity_and_sensor_info["entity_mib"]
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    keys = redis_get_keys(
        duthost, STATE_DB, FAN_DRAWER_KEY_TEMPLATE.format('*'))
    # Ignore the test if the platform does not support fan drawer
    if not keys:
        pytest.skip(
            'Fan drawer information does not exist in DB, skipping this test')
    for key in keys:
        drawer_info = redis_hgetall(duthost, STATE_DB, key)
        name = key.split(TABLE_NAME_SEPARATOR_VBAR)[-1]
        entity_info_key = PHYSICAL_ENTITY_KEY_TEMPLATE.format(name)
        entity_info = redis_hgetall(duthost, STATE_DB, entity_info_key)
        position = int(entity_info['position_in_parent'])
        expect_oid = MODULE_TYPE_FAN_DRAWER + position * MODULE_INDEX_MULTIPLE
        assert expect_oid in snmp_physical_entity_info, (
            "Expected OID for fabric card not found in SNMP physical entity MIB.\n"
            "Expected OID: {}\n"
        ).format(expect_oid)

        drawer_snmp_fact = snmp_physical_entity_info[expect_oid]
        assert drawer_snmp_fact['entPhysDescr'] == name, (
            "Fan drawer description mismatch. Expected '{}', but got '{}'. "
        ).format(
            name,
            drawer_snmp_fact['entPhysDescr']
        )
        assert drawer_snmp_fact['entPhysContainedIn'] == CHASSIS_SUB_ID, (
            "Fan drawer containment mismatch. Expected 'entPhysContainedIn' to be '{}', "
            "but got '{}'. "
        ).format(
            CHASSIS_SUB_ID,
            drawer_snmp_fact['entPhysContainedIn']
        )
        assert drawer_snmp_fact['entPhysClass'] == PHYSICAL_CLASS_CONTAINER, (
            "Fan drawer class mismatch. Expected 'entPhysClass' to be '{}', "
            "but got '{}'."
        ).format(
            PHYSICAL_CLASS_CONTAINER,
            drawer_snmp_fact['entPhysClass']
        )
        assert drawer_snmp_fact['entPhyParentRelPos'] == position, (
            "Fan drawer relative position mismatch. Expected 'entPhyParentRelPos' to be '{}', "
            "but got '{}'."
        ).format(
            position,
            drawer_snmp_fact['entPhyParentRelPos']
        )
        assert drawer_snmp_fact['entPhysName'] == name, (
            "Fan drawer name mismatch. Expected '{}', but got '{}'. "
        ).format(
            name,
            drawer_snmp_fact['entPhysName']
        )
        assert drawer_snmp_fact['entPhysHwVer'] == '', (
            "Fan drawer hardware version mismatch. Expected empty string, but got '{}'. "
        ).format(
            drawer_snmp_fact['entPhysHwVer']
        )
        assert drawer_snmp_fact['entPhysFwVer'] == '', (
            "Fan drawer firmware version mismatch. Expected empty string, but got '{}'."
        ).format(
            drawer_snmp_fact['entPhysFwVer']
        )
        assert drawer_snmp_fact['entPhysSwVer'] == '', (
            "Fan drawer software version mismatch. Expected empty string, but got '{}'."
        ).format(
            drawer_snmp_fact['entPhysSwVer']
        )
        assert drawer_snmp_fact['entPhysSerialNum'] == (
            '' if is_null_str(drawer_info['serial']) else drawer_info['serial']
        ), (
            "Fan drawer serial number mismatch. Expected '{}', but got '{}'."
        ).format(
            drawer_info['serial'],
            drawer_snmp_fact['entPhysSerialNum']
        )
        assert drawer_snmp_fact['entPhysMfgName'] == '', (
            "Fan drawer manufacturer name mismatch. Expected empty string, but got '{}'."
        ).format(
            drawer_snmp_fact['entPhysMfgName']
        )
        assert drawer_snmp_fact['entPhysModelName'] == (
            '' if is_null_str(drawer_info['model']) else drawer_info['model']
        ), (
            "Fan drawer model name mismatch. drawer_info['model]: '{}', "
            "drawer_snmp_fact['entPhysModelName']: '{}'"
        ).format(
            drawer_info['model'],
            drawer_snmp_fact['entPhysModelName']
        )
        assert drawer_snmp_fact['entPhysIsFRU'] == (
            REPLACEABLE if drawer_info['is_replaceable'] == 'True' else NOT_REPLACEABLE
        ), (
            "Fan drawer replaceable mismatch. drawer_info['is_replaceable']: '{}', "
            "drawer_snmp_fact['entPhysIsFRU']: '{}'"
        ).format(
            drawer_info['is_replaceable'],
            drawer_snmp_fact['entPhysIsFRU']
        )


def test_fan_info(duthosts, enum_rand_one_per_hwsku_hostname, snmp_physical_entity_and_sensor_info):
    """
    Verify fan information in physical entity mib with redis database
    :param duthost: DUT host object
    :param snmp_physical_entity_info: Physical entity information from snmp fact
    :return:
    """
    snmp_physical_entity_info = snmp_physical_entity_and_sensor_info["entity_mib"]
    snmp_entity_sensor_info = snmp_physical_entity_and_sensor_info["sensor_mib"]
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    keys = redis_get_keys(duthost, STATE_DB, FAN_KEY_TEMPLATE.format('*'))
    # Ignore the test if the platform does not have fans (e.g Line card)
    if not keys:
        pytest.skip('Fan information does not exist in DB, skipping this test')
    for key in keys:
        fan_info = redis_hgetall(duthost, STATE_DB, key)
        name = key.split(TABLE_NAME_SEPARATOR_VBAR)[-1]
        entity_info_key = PHYSICAL_ENTITY_KEY_TEMPLATE.format(name)
        entity_info = redis_hgetall(duthost, STATE_DB, entity_info_key)
        position = int(entity_info['position_in_parent'])
        parent_name = entity_info['parent_name']
        if 'PSU' in parent_name:
            continue
        elif parent_name == CHASSIS_KEY:
            parent_oid = MODULE_TYPE_FAN_DRAWER + position * MODULE_INDEX_MULTIPLE
        else:
            parent_entity_info = redis_hgetall(
                duthost, STATE_DB, PHYSICAL_ENTITY_KEY_TEMPLATE.format(parent_name))
            parent_position = int(parent_entity_info['position_in_parent'])
            if 'FABRIC-CARD' in parent_name:
                parent_oid = MODULE_TYPE_FABRIC_CARD + parent_position * MODULE_INDEX_MULTIPLE
            else:
                parent_oid = MODULE_TYPE_FAN_DRAWER + parent_position * MODULE_INDEX_MULTIPLE
        expect_oid = parent_oid + DEVICE_TYPE_FAN + position * DEVICE_INDEX_MULTIPLE
        assert expect_oid in snmp_physical_entity_info, (
            "Expected OID for fabric card not found in SNMP physical entity MIB.\n"
            "Expected OID: {}\n"
        ).format(expect_oid)

        fan_snmp_fact = snmp_physical_entity_info[expect_oid]
        assert fan_snmp_fact['entPhysDescr'] == name, (
            "Fan description mismatch. Expected '{}', but got '{}'. "
        ).format(
            name,
            fan_snmp_fact['entPhysDescr']
        )
        assert fan_snmp_fact['entPhysContainedIn'] == CHASSIS_SUB_ID if parent_name == CHASSIS_KEY else parent_oid, (
            "Fan containment mismatch. Expected '{}', but got '{}'. "
            "Redis DB key: {}. Redis DB value: {}. "
        ).format(
            parent_oid,
            fan_snmp_fact['entPhysContainedIn'],
            key,
            fan_info
        )
        assert fan_snmp_fact['entPhysClass'] == PHYSICAL_CLASS_FAN, (
            "Fan class mismatch. Expected 'entPhysClass' to be '{}', but got '{}'. "
        ).format(
            PHYSICAL_CLASS_FAN,
            fan_snmp_fact['entPhysClass']
        )
        assert fan_snmp_fact['entPhyParentRelPos'] == position, (
            "Fan parent relative position mismatch. Expected '{}', but got '{}'. "
        ).format(
            position,
            fan_snmp_fact['entPhyParentRelPos']
        )
        assert fan_snmp_fact['entPhysName'] == name, (
            "Fan name mismatch. Expected '{}', but got '{}'. "
        ).format(
            name,
            fan_snmp_fact['entPhysName']
        )
        assert fan_snmp_fact['entPhysHwVer'] == '', (
            "Fan hardware version mismatch. Expected empty string, but got '{}'. "
        ).format(
            fan_snmp_fact['entPhysHwVer']
        )
        assert fan_snmp_fact['entPhysFwVer'] == '', (
            "Fan firmware version mismatch. Expected empty string, but got '{}'. "
        ).format(
            fan_snmp_fact['entPhysFwVer']
        )
        assert fan_snmp_fact['entPhysSwVer'] == '', (
            "Fan software version mismatch. Expected empty string, but got '{}'. "
        ).format(
            fan_snmp_fact['entPhysSwVer']
        )
        assert fan_snmp_fact['entPhysSerialNum'] == ('' if is_null_str(fan_info['serial']) else fan_info[
            'serial']), (
            "Fan serial number mismatch. Expected '{}', but got '{}'. "
        ).format(
            fan_info['serial'],
            fan_snmp_fact['entPhysSerialNum']
        )
        assert fan_snmp_fact['entPhysMfgName'] == '', (
            "Fan manufacturer mismatch. Expected empty string, but got '{}'. "
        ).format(
            fan_snmp_fact['entPhysMfgName']
        )
        assert fan_snmp_fact['entPhysModelName'] == '' if is_null_str(
            fan_info['model']) else fan_info['model'], (
            "Fan model name mismatch. Expected '{}', but got '{}'. "
        ).format(
            fan_info['model'],
            fan_snmp_fact['entPhysModelName']
        )
        assert fan_snmp_fact['entPhysIsFRU'] == (
            REPLACEABLE if fan_info['is_replaceable'] == 'True' else NOT_REPLACEABLE
        ), (
            "Fan replaceable mismatch. Expected '{}', but got '{}'. "
        ).format(
            fan_info['is_replaceable'],
            fan_snmp_fact['entPhysIsFRU']
        )

        if not is_null_str(fan_info['speed']):
            tachometers_oid = expect_oid + SENSOR_TYPE_FAN
            assert tachometers_oid in snmp_physical_entity_info, (
                "Cannot find fan tachometers info in physical entity MIB. "
                "Expected OID '{}'. "
            ).format(
                tachometers_oid
            )

            tachometers_fact = snmp_physical_entity_info[tachometers_oid]
            assert tachometers_fact['entPhysDescr'] == 'Tachometers for {}'.format(name), (
                "Fan tachometers description mismatch. Expected '{}', but got '{}'. "
            ).format(
                'Tachometers for {}'.format(name),
                tachometers_fact['entPhysDescr']
            )

            assert tachometers_fact['entPhysContainedIn'] == expect_oid, (
                "Fan tachometers containment mismatch. Expected '{}', but got '{}'. "
            ).format(
                expect_oid,
                tachometers_fact['entPhysContainedIn']
            )
            assert tachometers_fact['entPhysClass'] == PHYSICAL_CLASS_SENSOR, (
                "Fan tachometers class mismatch. Expected '{}', but got '{}'. "
            ).format(
                PHYSICAL_CLASS_SENSOR,
                tachometers_fact['entPhysClass']
            )
            assert tachometers_fact['entPhyParentRelPos'] == 1, (
                "Fan tachometers parent relative position mismatch. Expected '1', but got '{}'. "
            ).format(
                tachometers_fact['entPhyParentRelPos']
            )
            assert tachometers_fact['entPhysName'] == 'Tachometers for {}'.format(
                name), (
                "Fan tachometers name mismatch. Expected 'Tachometers for {}', but got '{}'. "
            ).format(
                name,
                tachometers_fact['entPhysName']
            )
            assert tachometers_fact['entPhysHwVer'] == '', (
                "Fan tachometers hardware version mismatch. Expected empty string, but got '{}'. "
            ).format(
                tachometers_fact['entPhysHwVer']
            )
            assert tachometers_fact['entPhysFwVer'] == '', (
                "Fan tachometers firmware version mismatch. Expected empty string, but got '{}'. "
            ).format(
                tachometers_fact['entPhysFwVer']
            )
            assert tachometers_fact['entPhysSwVer'] == '', (
                "Fan tachometers software version mismatch. Expected empty string, but got '{}'. "
            ).format(
                tachometers_fact['entPhysSwVer']
            )
            assert tachometers_fact['entPhysSerialNum'] == '', (
                "Fan tachometers serial number mismatch. Expected empty string, but got '{}'. "
            ).format(
                tachometers_fact['entPhysSerialNum']
            )
            assert tachometers_fact['entPhysMfgName'] == '', (
                "Fan tachometers manufacturer name mismatch. Expected empty string, but got '{}'. "
            ).format(
                tachometers_fact['entPhysMfgName']
            )
            assert tachometers_fact['entPhysModelName'] == '', (
                "Fan tachometers model name mismatch. Expected empty string, but got '{}'. "
            ).format(
                tachometers_fact['entPhysModelName']
            )
            assert tachometers_fact['entPhysIsFRU'] == NOT_REPLACEABLE, (
                "Fan tachometers replaceability mismatch. Expected NOT_REPLACEABLE, but got '{}'. "
            ).format(
                tachometers_fact['entPhysIsFRU']
            )

        # snmp_entity_sensor_info is only supported in image newer than 202012
        if is_sensor_test_supported(duthost):
            expect_sensor_oid = expect_oid + SENSOR_TYPE_FAN
            assert expect_sensor_oid in snmp_entity_sensor_info, (
                "Cannot find expected fan sensor in entity sensor MIB. Expected OID '{}' is missing. "
                "Entity sensor MIB: {}"
            ).format(
                expect_sensor_oid,
                snmp_entity_sensor_info
            )
            tachometers_sensor_fact = snmp_entity_sensor_info[expect_sensor_oid]
            assert tachometers_sensor_fact['entPhySensorType'] == str(
                int(EntitySensorDataType.UNKNOWN)), (
                "Fan tachometers type mismatch. Expected type 'UNKNOWN', but got '{}'. "
            ).format(
                tachometers_sensor_fact['entPhySensorType']
            )
            assert tachometers_sensor_fact['entPhySensorPrecision'] == '0', (
                "Fan tachometers precision mismatch. Expected precision '0', but got '{}'. "
            ).format(
                tachometers_sensor_fact['entPhySensorPrecision']
            )
            assert tachometers_sensor_fact['entPhySensorScale'] == EntitySensorDataScale.UNITS, (
                "Fan tachometers scale mismatch. Expected scale 'UNITS', but got '{}'. "
            ).format(
                tachometers_sensor_fact['entPhySensorScale']
            )
            # Fan tachometer sensor value(percent) is a int between 0 and 100
            assert 0 < int(tachometers_sensor_fact['entPhySensorValue']) <= 100, (
                "Fan tachometers sensor value out of range. Expected value between 1 and 100, but got '{}'. "
            ).format(
                tachometers_sensor_fact['entPhySensorValue']
            )
            assert tachometers_sensor_fact['entPhySensorOperStatus'] == str(int(EntitySensorStatus.OK)) \
                or tachometers_sensor_fact['entPhySensorOperStatus'] == str(int(EntitySensorStatus.NONOPERATIONAL)) \
                or tachometers_sensor_fact['entPhySensorOperStatus'] == str(int(EntitySensorStatus.UNAVAILABLE)), (
                "Tachometers sensor operational status mismatch. Expected one of '{}', '{}', or '{}', but got '{}'."
            ).format(
                str(int(EntitySensorStatus.OK)),
                str(int(EntitySensorStatus.NONOPERATIONAL)),
                str(int(EntitySensorStatus.UNAVAILABLE)),
                tachometers_sensor_fact['entPhySensorOperStatus']
            )


def test_psu_info(duthosts, enum_rand_one_per_hwsku_hostname, snmp_physical_entity_and_sensor_info):
    """
    Verify PSU information in physical entity mib with redis database
    :param duthost: DUT host object
    :param snmp_physical_entity_info: Physical entity information from snmp fact
    :return:
    """
    snmp_physical_entity_info = snmp_physical_entity_and_sensor_info["entity_mib"]
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if not duthost.is_supervisor_node():
        pytest.skip("Not supported on non supervisor node")
    keys = redis_get_keys(duthost, STATE_DB, PSU_KEY_TEMPLATE.format('*'))
    # Ignore the test if the platform does not have psus (e.g Line card)
    if not keys:
        pytest.skip('PSU information does not exist in DB, skipping this test')
    for key in keys:
        psu_info = redis_hgetall(duthost, STATE_DB, key)
        name = key.split(TABLE_NAME_SEPARATOR_VBAR)[-1]
        entity_info_key = PHYSICAL_ENTITY_KEY_TEMPLATE.format(name)
        entity_info = redis_hgetall(duthost, STATE_DB, entity_info_key)
        position = int(entity_info['position_in_parent'])
        expect_oid = MODULE_TYPE_PSU + position * MODULE_INDEX_MULTIPLE
        if psu_info['presence'] != 'true':
            assert expect_oid not in snmp_physical_entity_info, (
                "Unexpected OID found in SNMP physical entity MIB.\n"
                "Expected OID '{}' to be absent, but it is present.\n"
            ).format(expect_oid)

            continue

        assert expect_oid in snmp_physical_entity_info, (
            "Expected OID '{}' is missing in SNMP physical entity MIB.\n "
        ).format(
            expect_oid
        )
        psu_snmp_fact = snmp_physical_entity_info[expect_oid]
        assert psu_snmp_fact['entPhysDescr'] == name, (
            "PSU description mismatch. Expected 'entPhysDescr' to be '{}', "
            "but got '{}'."
        ).format(
            name,
            psu_snmp_fact['entPhysDescr']
        )
        assert psu_snmp_fact['entPhysContainedIn'] == CHASSIS_SUB_ID, (
            "PSU containment mismatch. Expected 'entPhysContainedIn' to be '{}', but got '{}'."
        ).format(
            CHASSIS_SUB_ID,
            psu_snmp_fact['entPhysContainedIn']
        )
        assert psu_snmp_fact['entPhysClass'] == PHYSICAL_CLASS_POWERSUPPLY, (
            "PSU class mismatch. Expected class 'PHYSICAL_CLASS_POWERSUPPLY'  '{}', but got '{}'."
        ).format(
            PHYSICAL_CLASS_POWERSUPPLY,
            psu_snmp_fact['entPhysClass']
        )
        assert psu_snmp_fact['entPhyParentRelPos'] == position, (
            "PSU relative position mismatch. Expected 'entPhyParentRelPos' to be '{}', "
            "but got '{}'."
        ).format(
            position,
            psu_snmp_fact['entPhyParentRelPos']
        )
        assert psu_snmp_fact['entPhysName'] == name, (
            "PSU name mismatch. Expected 'entPhysName' to be '{}', but got '{}'."
        ).format(
            name,
            psu_snmp_fact['entPhysName']
        )
        assert psu_snmp_fact['entPhysHwVer'] == '', (
            "PSU hardware version mismatch. Expected 'entPhysHwVer' to be empty string, "
            "but got '{}'."
        ).format(
            psu_snmp_fact['entPhysHwVer']
        )
        assert psu_snmp_fact['entPhysFwVer'] == '', (
            "PSU firmware version mismatch. Expected 'entPhysFwVer' to be empty string, "
            "but got '{}'."
        ).format(
            psu_snmp_fact['entPhysFwVer']
        )
        assert psu_snmp_fact['entPhysSwVer'] == '', (
            "PSU software version mismatch. Expected 'entPhysSwVer' to be empty string, "
            "but got '{}'."
        ).format(
            psu_snmp_fact['entPhysSwVer']
        )
        assert psu_snmp_fact['entPhysSerialNum'] == (
            '' if is_null_str(psu_info['serial']) else psu_info['serial']
        ), (
            "PSU serial number mismatch. Expected '{}' but got '{}'."
        ).format(
            psu_info['serial'],
            psu_snmp_fact['entPhysSerialNum']
        )
        assert psu_snmp_fact['entPhysMfgName'] == '', (
            "PSU manufacturer name mismatch. Expected 'entPhysMfgName' to be empty string, "
            "but got '{}'."
        ).format(
            psu_snmp_fact['entPhysMfgName']
        )
        assert psu_snmp_fact['entPhysModelName'] == '' if is_null_str(
            psu_info['model']) else psu_info['model'], (
            "PSU model name mismatch. Expected '{}' but got '{}'."
        ).format(
            psu_info['model'],
            psu_snmp_fact['entPhysModelName']
        )
        assert psu_snmp_fact['entPhysIsFRU'] == (
            REPLACEABLE if psu_info['is_replaceable'] == 'True' else NOT_REPLACEABLE
        ), (
            "PSU replaceable mismatch. Expected '{}' but got '{}'."
        ).format(
            psu_info['is_replaceable'],
            psu_snmp_fact['entPhysIsFRU']
        )

        _check_psu_sensor(duthost, name, psu_info, expect_oid,
                          snmp_physical_entity_and_sensor_info)


def _check_psu_sensor(duthost, psu_name, psu_info, psu_oid, snmp_physical_entity_and_sensor_info):
    """
    Check PSU sensor information in physical entity mib
    :param psu_name: PSU name
    :param psu_info: PSU information got from db
    :param psu_oid: PSU oid
    :param snmp_physical_entity_info: Physical entity information from snmp fact
    :return:
    """
    snmp_physical_entity_info = snmp_physical_entity_and_sensor_info["entity_mib"]
    snmp_entity_sensor_info = snmp_physical_entity_and_sensor_info["sensor_mib"]
    for field, sensor_tuple in list(PSU_SENSOR_INFO.items()):
        expect_oid = psu_oid + DEVICE_TYPE_POWER_MONITOR + sensor_tuple[2]
        if is_null_str(psu_info[field]):
            assert expect_oid not in snmp_physical_entity_info, (
                "Unexpectedly found PSU sensor OID '{}' in physical entity MIB. "
            ).format(
                expect_oid
            )
            continue

        assert expect_oid in snmp_physical_entity_info, (
            "Cannot find PSU sensor OID '{}' in physical entity MIB. "
        ).format(
            expect_oid
        )
        phy_entity_snmp_fact = snmp_physical_entity_info[expect_oid]
        sensor_name = '{sensor_name} for {psu_name}'.format(
            sensor_name=sensor_tuple[0], psu_name=psu_name)
        assert phy_entity_snmp_fact['entPhysDescr'] == sensor_name, (
            "PSU sensor description mismatch. Expected 'entPhysDescr' to be '{}', "
            "but got '{}'."
        ).format(
            sensor_name,
            phy_entity_snmp_fact['entPhysDescr']
        )
        assert phy_entity_snmp_fact['entPhysContainedIn'] == psu_oid, (
            "PSU sensor containment mismatch. Expected 'entPhysContainedIn' to be '{}', "
            "but got '{}'."
        ).format(
            psu_oid,
            phy_entity_snmp_fact['entPhysContainedIn']
        )
        assert phy_entity_snmp_fact['entPhysClass'] == PHYSICAL_CLASS_SENSOR, (
            "PSU sensor class mismatch. Expected 'entPhysClass' to be '{}', "
            "but got '{}'."
        ).format(
            PHYSICAL_CLASS_SENSOR,
            phy_entity_snmp_fact['entPhysClass']
        )
        assert phy_entity_snmp_fact['entPhyParentRelPos'] == sensor_tuple[1], (
            "PSU sensor parent relative position mismatch. Expected 'entPhyParentRelPos' to be '{}', "
            "but got '{}'."
        ).format(
            sensor_tuple[1],
            phy_entity_snmp_fact['entPhyParentRelPos']
        )
        assert phy_entity_snmp_fact['entPhysName'] == sensor_name, (
            "PSU sensor name mismatch. Expected 'entPhysName' to be '{}', "
            "but got '{}'."
        ).format(
            sensor_name,
            phy_entity_snmp_fact['entPhysName']
        )
        assert phy_entity_snmp_fact['entPhysHwVer'] == '', (
            "PSU sensor hardware version mismatch. Expected 'entPhysHwVer' to be empty string, "
            "but got '{}'."
        ).format(
            phy_entity_snmp_fact['entPhysHwVer']
        )
        assert phy_entity_snmp_fact['entPhysFwVer'] == '', (
            "PSU sensor firmware version mismatch. Expected 'entPhysFwVer' to be empty string, "
            "but got '{}'."
        ).format(
            phy_entity_snmp_fact['entPhysFwVer']
        )
        assert phy_entity_snmp_fact['entPhysSwVer'] == '', (
            "PSU sensor software version mismatch. Expected 'entPhysSwVer' to be empty string, "
            "but got '{}'."
        ).format(
            phy_entity_snmp_fact['entPhysSwVer']
        )
        assert phy_entity_snmp_fact['entPhysSerialNum'] == '', (
            "PSU sensor serial number mismatch. Expected 'entPhysSerialNum' to be empty string, "
            "but got '{}'."
        ).format(
            phy_entity_snmp_fact['entPhysSerialNum']
        )
        assert phy_entity_snmp_fact['entPhysMfgName'] == '', (
            "PSU sensor manufacturer name mismatch. Expected 'entPhysMfgName' to be empty string, "
            "but got '{}'."
        ).format(
            phy_entity_snmp_fact['entPhysMfgName']
        )
        assert phy_entity_snmp_fact['entPhysModelName'] == '', (
            "PSU sensor model name mismatch. Expected 'entPhysModelName' to be empty string, "
            "but got '{}'."
        ).format(
            phy_entity_snmp_fact['entPhysModelName']
        )
        assert phy_entity_snmp_fact['entPhysIsFRU'] == NOT_REPLACEABLE, (
            "PSU sensor is replaceable mismatch. Expected 'entPhysIsFRU' to be '{}', "
            "but got '{}'."
        ).format(
            NOT_REPLACEABLE,
            phy_entity_snmp_fact['entPhysIsFRU']
        )

        # snmp_entity_sensor_info is only supported in image newer than 202012
        if is_sensor_test_supported(duthost):
            entity_sensor_snmp_facts = snmp_entity_sensor_info[expect_oid]
            if field == "current":
                assert entity_sensor_snmp_facts['entPhySensorType'] == str(
                    int(EntitySensorDataType.AMPERES)), (
                    "PSU current sensor type mismatch. Expected 'entPhySensorType' to be '{}', "
                    "but got '{}'."
                ).format(
                    int(EntitySensorDataType.AMPERES),
                    entity_sensor_snmp_facts['entPhySensorType']
                )
            elif field == "voltage":
                assert entity_sensor_snmp_facts['entPhySensorType'] == str(
                    int(EntitySensorDataType.VOLTS_DC)), (
                    "PSU voltage sensor type mismatch. Expected 'entPhySensorType' to be '{}', "
                    "but got '{}'."
                ).format(
                    int(EntitySensorDataType.VOLTS_DC),
                    entity_sensor_snmp_facts['entPhySensorType']
                )
            elif field == "power":
                assert entity_sensor_snmp_facts['entPhySensorType'] == str(
                    int(EntitySensorDataType.WATTS)), (
                    "PSU power sensor type mismatch. Expected 'entPhySensorType' to be '{}', "
                    "but got '{}'."
                ).format(
                    int(EntitySensorDataType.WATTS),
                    entity_sensor_snmp_facts['entPhySensorType']
                )
            elif field == "temperature":
                assert entity_sensor_snmp_facts['entPhySensorType'] == str(
                    int(EntitySensorDataType.CELSIUS)), (
                    "PSU temperature sensor type mismatch. Expected 'entPhySensorType' to be '{}', "
                    "but got '{}'."
                ).format(
                    int(EntitySensorDataType.CELSIUS),
                    entity_sensor_snmp_facts['entPhySensorType']
                )
            else:
                continue
            assert entity_sensor_snmp_facts['entPhySensorPrecision'] == '3', (
                "PSU sensor precision mismatch. Expected 'entPhySensorPrecision' to be '3', "
                "but got '{}'."
            ).format(
                entity_sensor_snmp_facts['entPhySensorPrecision']
            )
            assert entity_sensor_snmp_facts['entPhySensorScale'] == EntitySensorDataScale.UNITS, (
                "PSU sensor scale mismatch. Expected 'entPhySensorScale' to be '{}', "
                "but got '{}'."
            ).format(
                EntitySensorDataScale.UNITS,
                entity_sensor_snmp_facts['entPhySensorScale']
            )
            assert entity_sensor_snmp_facts['entPhySensorOperStatus'] == str(int(EntitySensorStatus.OK)) \
                or entity_sensor_snmp_facts['entPhySensorOperStatus'] == str(int(EntitySensorStatus.NONOPERATIONAL)) \
                or entity_sensor_snmp_facts['entPhySensorOperStatus'] == str(int(EntitySensorStatus.UNAVAILABLE)), (
                "PSU sensor operational status mismatch. Expected 'entPhySensorOperStatus' to be one of '{}', "
                "'{}', '{}', but got '{}'."
            ).format(
                int(EntitySensorStatus.OK),
                int(EntitySensorStatus.NONOPERATIONAL),
                int(EntitySensorStatus.UNAVAILABLE),
                entity_sensor_snmp_facts['entPhySensorOperStatus']
            )


def test_thermal_info(duthosts, enum_rand_one_per_hwsku_hostname, snmp_physical_entity_and_sensor_info):
    """
    Verify thermal information in physical entity mib with redis database
    :param duthost: DUT host object
    :param snmp_physical_entity_info: Physical entity information from snmp fact
    :return:
    """
    snmp_physical_entity_info = snmp_physical_entity_and_sensor_info["entity_mib"]
    snmp_entity_sensor_info = snmp_physical_entity_and_sensor_info["sensor_mib"]
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    keys = redis_get_keys(duthost, STATE_DB, THERMAL_KEY_TEMPLATE.format('*'))
    assert keys, "Thermal information does not exist in DB: {}".format(keys)

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
        expect_oid = CHASSIS_MGMT_SUB_ID + DEVICE_TYPE_CHASSIS_THERMAL + position * DEVICE_INDEX_MULTIPLE + \
            SENSOR_TYPE_TEMP
        assert expect_oid in snmp_physical_entity_info, (
            "Expected OID '{}' is missing in SNMP physical entity MIB."
        ).format(expect_oid)

        thermal_snmp_fact = snmp_physical_entity_info[expect_oid]
        assert thermal_snmp_fact['entPhysDescr'] == name, (
            "Thermal description mismatch. Expected 'entPhysDescr' to be '{}', "
            "but got '{}'. "
        ).format(
            name,
            thermal_snmp_fact['entPhysDescr']
        )
        assert thermal_snmp_fact['entPhysContainedIn'] == CHASSIS_MGMT_SUB_ID, (
            "Thermal containment mismatch. Expected 'entPhysContainedIn' to be '{}', "
            "but got '{}'. "
        ).format(
            CHASSIS_MGMT_SUB_ID,
            thermal_snmp_fact['entPhysContainedIn']
        )
        assert thermal_snmp_fact['entPhysClass'] == PHYSICAL_CLASS_SENSOR, (
            "Thermal class mismatch. Expected 'entPhysClass' to be '{}', "
            "but got '{}'. "
        ).format(
            PHYSICAL_CLASS_SENSOR,
            thermal_snmp_fact['entPhysClass']
        )
        assert thermal_snmp_fact['entPhyParentRelPos'] == position, (
            "Thermal relative position mismatch. Expected 'entPhyParentRelPos' to be '{}', "
            "but got '{}'. "
        ).format(
            position,
            thermal_snmp_fact['entPhyParentRelPos']
        )
        assert thermal_snmp_fact['entPhysName'] == name, (
            "Thermal name mismatch. Expected 'entPhysName' to be '{}', "
            "but got '{}'. "
        ).format(
            name,
            thermal_snmp_fact['entPhysName']
        )
        assert thermal_snmp_fact['entPhysHwVer'] == '', (
            "Thermal hardware version mismatch. Expected 'entPhysHwVer' to be '', "
            "but got '{}'. "
        ).format(
            thermal_snmp_fact['entPhysHwVer']
        )
        assert thermal_snmp_fact['entPhysFwVer'] == '', (
            "Thermal firmware version mismatch. Expected 'entPhysFwVer' to be '', "
            "but got '{}'. "
        ).format(
            thermal_snmp_fact['entPhysFwVer']
        )
        assert thermal_snmp_fact['entPhysSwVer'] == '', (
            "Thermal software version mismatch. Expected 'entPhysSwVer' to be '', "
            "but got '{}'. "
        ).format(
            thermal_snmp_fact['entPhysSwVer']
        )
        assert thermal_snmp_fact['entPhysSerialNum'] == '', (
            "Thermal serial number mismatch. Expected 'entPhysSerialNum' to be '', "
            "but got '{}'. "
        ).format(
            thermal_snmp_fact['entPhysSerialNum']
        )
        assert thermal_snmp_fact['entPhysMfgName'] == '', (
            "Thermal manufacturer name mismatch. Expected 'entPhysMfgName' to be '', "
            "but got '{}'. "
        ).format(
            thermal_snmp_fact['entPhysMfgName']
        )
        assert thermal_snmp_fact['entPhysModelName'] == '', (
            "Thermal model name mismatch. Expected 'entPhysModelName' to be '', "
            "but got '{}'. "
        ).format(
            thermal_snmp_fact['entPhysModelName']
        )
        assert thermal_snmp_fact['entPhysIsFRU'] == NOT_REPLACEABLE, (
            "Thermal FRU mismatch. Expected 'entPhysIsFRU' to be '{}', "
            "but got '{}'. "
        ).format(
            NOT_REPLACEABLE,
            thermal_snmp_fact['entPhysIsFRU']
        )

        # snmp_entity_sensor_info is only supported in image newer than 202012
        if is_sensor_test_supported(duthost):
            thermal_sensor_snmp_fact = snmp_entity_sensor_info[expect_oid]
            assert thermal_sensor_snmp_fact['entPhySensorType'] == str(
                int(EntitySensorDataType.CELSIUS)), (
                "Thermal sensor type mismatch. Expected 'entPhySensorType' to be '{}', "
                "but got '{}'. "
            ).format(
                int(EntitySensorDataType.CELSIUS),
                thermal_sensor_snmp_fact['entPhySensorType']
            )
            assert thermal_sensor_snmp_fact['entPhySensorPrecision'] == '3', (
                "Thermal sensor precision mismatch. Expected 'entPhySensorPrecision' to be '{}', "
                "but got '{}'. "
            ).format(
                '3',
                thermal_sensor_snmp_fact['entPhySensorPrecision']
            )
            assert thermal_sensor_snmp_fact['entPhySensorScale'] == EntitySensorDataScale.UNITS, (
                "Thermal sensor scale mismatch. Expected 'entPhySensorScale' to be '{}', "
                "but got '{}'. "
            ).format(
                EntitySensorDataScale.UNITS,
                thermal_sensor_snmp_fact['entPhySensorScale']
            )
            assert thermal_sensor_snmp_fact['entPhySensorOperStatus'] == str(int(EntitySensorStatus.OK)) \
                or thermal_sensor_snmp_fact['entPhySensorOperStatus'] == str(int(EntitySensorStatus.NONOPERATIONAL)) \
                or thermal_sensor_snmp_fact['entPhySensorOperStatus'] == str(int(EntitySensorStatus.UNAVAILABLE)), (
                "Thermal sensor SNMP fact 'entPhySensorOperStatus' has unexpected value: {}. "
                "Expected one of: OK ({}), NONOPERATIONAL ({}), UNAVAILABLE ({})."
            ).format(
                thermal_sensor_snmp_fact['entPhySensorOperStatus'],
                int(EntitySensorStatus.OK),
                int(EntitySensorStatus.NONOPERATIONAL),
                int(EntitySensorStatus.UNAVAILABLE)
            )


def test_transceiver_info(duthosts, enum_rand_one_per_hwsku_hostname, snmp_physical_entity_and_sensor_info):
    """
    Verify transceiver information in physical entity mib with redis database
    :param duthost: DUT host object
    :param snmp_physical_entity_info: Physical entity information from snmp fact
    :return:
    """
    snmp_physical_entity_info = snmp_physical_entity_and_sensor_info["entity_mib"]
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    keys = redis_get_keys(duthost, STATE_DB, XCVR_KEY_TEMPLATE.format('*'))
    # Ignore the test if the platform does not have interfaces (e.g Supervisor)
    if not keys:
        pytest.skip('Transceiver information does not exist in DB, skipping this test')
    name_to_snmp_facts = {}
    for oid, values in list(snmp_physical_entity_info.items()):
        values['oid'] = oid
        name_to_snmp_facts[values['entPhysName']] = values

    transceiver_rev_key = "vendor_rev"
    release_list = ["201911", "202012", "202106", "202111"]
    if any(release in duthost.os_version for release in release_list):
        transceiver_rev_key = "hardware_rev"

    for key in keys:
        name = key.split(TABLE_NAME_SEPARATOR_VBAR)[-1]
        assert name in name_to_snmp_facts, (
            "Transceiver '{}' is missing in SNMP physical entity MIB.\n"
            "SNMP facts: {}"
        ).format(name, name_to_snmp_facts)

        transceiver_info = redis_hgetall(duthost, STATE_DB, key)
        transceiver_snmp_fact = name_to_snmp_facts[name]
        assert transceiver_snmp_fact['entPhysDescr'] is not None, (
            "Transceiver description is missing in SNMP physical entity MIB.\n"
            "entPhysDescr is None.\n"
            "SNMP reported value: '{}'"
        ).format(transceiver_snmp_fact['entPhysDescr'])

        assert transceiver_snmp_fact['entPhysContainedIn'] == CHASSIS_SUB_ID, (
            'Transceiver containment mismatch. Expected "entPhysContainedIn" to be {}, '
            'but got {}. '
        ).format(
            CHASSIS_SUB_ID,
            transceiver_snmp_fact['entPhysContainedIn']
        )
        assert transceiver_snmp_fact['entPhysClass'] == PHYSICAL_CLASS_PORT, (
            'Transceiver class mismatch. Expected "entPhysClass" to be {}, '
            'but got {}. '
        ).format(
            PHYSICAL_CLASS_PORT,
            transceiver_snmp_fact['entPhysClass']
        )
        assert transceiver_snmp_fact['entPhyParentRelPos'] == -1, (
            'Transceiver relative position mismatch. Expected "entPhyParentRelPos" to be -1, '
            'but got {}. '
        ).format(
            transceiver_snmp_fact['entPhyParentRelPos']
        )
        assert transceiver_snmp_fact['entPhysName'] == name, (
            'Transceiver name mismatch. Expected "entPhysName" to be {}, '
            'but got {}. '
        ).format(
            name,
            transceiver_snmp_fact['entPhysName']
        )
        assert transceiver_snmp_fact['entPhysHwVer'] == transceiver_info[transceiver_rev_key], (
            'Transceiver hardware revision mismatch. Expected "entPhysHwVer" to be {}, '
            'but got {}. '
        ).format(
            transceiver_info[transceiver_rev_key],
            transceiver_snmp_fact['entPhysHwVer']
        )
        assert transceiver_snmp_fact['entPhysFwVer'] == '', (
            'Transceiver firmware version mismatch. Expected "entPhysFwVer" to be empty, '
            'but got {}. '
        ).format(
            transceiver_snmp_fact['entPhysFwVer']
        )
        assert transceiver_snmp_fact['entPhysSwVer'] == '', (
            'Transceiver software version mismatch. Expected "entPhysSwVer" to be empty, '
            'but got {}. '
        ).format(
            transceiver_snmp_fact['entPhysSwVer']
        )
        assert transceiver_snmp_fact['entPhysSerialNum'] == transceiver_info['serial'], (
            'Transceiver serial number mismatch. Expected "entPhysSerialNum" to be {}, '
            'but got {}. '
        ).format(
            transceiver_info['serial'],
            transceiver_snmp_fact['entPhysSerialNum']
        )
        assert transceiver_snmp_fact['entPhysMfgName'] == transceiver_info['manufacturer'], (
            'Transceiver manufacturer name mismatch. Expected "entPhysMfgName" to be {}, '
            'but got {}. '
        ).format(
            transceiver_info['manufacturer'],
            transceiver_snmp_fact['entPhysMfgName']
        )
        assert transceiver_snmp_fact['entPhysModelName'] == transceiver_info['model'], (
            'Transceiver model name mismatch. Expected "entPhysModelName" to be {}, '
            'but got {}. '
        ).format(
            transceiver_info['model'],
            transceiver_snmp_fact['entPhysModelName']
        )
        assert transceiver_snmp_fact['entPhysIsFRU'] == (
            REPLACEABLE if transceiver_info['is_replaceable'] == 'True' else NOT_REPLACEABLE
        ), (
            'Transceiver replaceable status mismatch. Expected "entPhysIsFRU" to be {}, '
            'but got {}. '
        ).format(
            transceiver_info['is_replaceable'],
            transceiver_snmp_fact['entPhysIsFRU']
        )

        _check_transceiver_dom_sensor_info(
            duthost, name, transceiver_snmp_fact['oid'], snmp_physical_entity_info)


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
        assert expect_oid in snmp_physical_entity_info, (
            "Cannot find port sensor OID '{}' in physical entity MIB. "
            "Expected to find the sensor OID in SNMP facts but it is missing. "
        ).format(
            expect_oid
        )
        sensor_snmp_fact = snmp_physical_entity_info[expect_oid]
        assert sensor_snmp_fact['entPhysDescr'] is not None, (
            "Sensor description is empty. Expected 'entPhysDescr' to be not empty, "
            "but got '{}'. "
        ).format(
            sensor_snmp_fact['entPhysDescr']
        )
        assert sensor_snmp_fact['entPhysContainedIn'] == transceiver_oid, (
            "Sensor containment mismatch. Expected 'entPhysContainedIn' to be '{}', "
            "but got '{}'."
        ).format(
            transceiver_oid,
            sensor_snmp_fact['entPhysContainedIn']
        )
        assert sensor_snmp_fact['entPhysClass'] == PHYSICAL_CLASS_SENSOR, (
            "Sensor class mismatch. Expected 'entPhysClass' to be '{}', "
            "but got '{}'. "
        ).format(
            PHYSICAL_CLASS_SENSOR,
            sensor_snmp_fact['entPhysClass']
        )
        assert sensor_snmp_fact['entPhyParentRelPos'] == index + 1, (
            "Sensor relative position mismatch. Expected 'entPhyParentRelPos' to be {}, "
            "but got {}. "
        ).format(
            index + 1,
            sensor_snmp_fact['entPhyParentRelPos']
        )
        assert sensor_snmp_fact['entPhysName'] is not None, (
            "Sensor name is empty. Expected 'entPhysName' to be not empty, "
            "but got '{}'. "
        ).format(
            sensor_snmp_fact['entPhysName']
        )
        assert sensor_snmp_fact['entPhysHwVer'] == '', (
            "Sensor hardware version mismatch. Expected 'entPhysHwVer' to be an empty string, "
            "but got '{}'. "
        ).format(
            sensor_snmp_fact['entPhysHwVer']
        )
        assert sensor_snmp_fact['entPhysFwVer'] == '', (
            "Sensor firmware version mismatch. Expected 'entPhysFwVer' to be an empty string, "
            "but got '{}'. "
        ).format(
            sensor_snmp_fact['entPhysFwVer']
        )
        assert sensor_snmp_fact['entPhysSwVer'] == '', (
            "Sensor software version mismatch. Expected 'entPhysSwVer' to be an empty string, "
            "but got '{}'. "
        ).format(
            sensor_snmp_fact['entPhysSwVer']
        )
        assert sensor_snmp_fact['entPhysSerialNum'] == '', (
            "Sensor serial number mismatch. Expected 'entPhysSerialNum' to be an empty string, "
            "but got '{}'. "
        ).format(
            sensor_snmp_fact['entPhysSerialNum']
        )
        assert sensor_snmp_fact['entPhysMfgName'] == '', (
            "Sensor manufacture name mismatch. Expected 'entPhysMfgName' to be an empty string, "
            "but got '{}'. "
        ).format(
            sensor_snmp_fact['entPhysMfgName']
        )
        assert sensor_snmp_fact['entPhysModelName'] == '', (
            "Sensor model name mismatch. Expected 'entPhysModelName' to be an empty string, "
            "but got '{}'. "
        ).format(
            sensor_snmp_fact['entPhysModelName']
        )
        assert sensor_snmp_fact['entPhysIsFRU'] == NOT_REPLACEABLE, (
            "Sensor is FRU mismatch. Expected 'entPhysIsFRU' to be {}, "
            "but got {}. "
        ).format(
            NOT_REPLACEABLE,
            sensor_snmp_fact['entPhysIsFRU']
        )


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
    for field, value in list(sensor_info.items()):
        for pattern, data in list(XCVR_SENSOR_PATTERN.items()):
            match_result = re.match(pattern, field)
            if match_result:
                if data['extract_line_number']:
                    lane_number = int(match_result.group(1))
                    sort_factor = data['sort_factor'] + lane_number
                    oid_offset = data['oid_base'] + lane_number
                else:
                    sort_factor = data['sort_factor']
                    oid_offset = data['oid_base']
                sensor_data_list.append(SensorData(
                    field, value, sort_factor, oid_offset))
                break

    sensor_data_list = sorted(sensor_data_list, key=lambda x: x.sort_factor)
    return sensor_data_list


@pytest.mark.disable_loganalyzer
def test_turn_off_psu_and_check_psu_info(duthosts, enum_supervisor_dut_hostname,
                                         localhost, creds_all_duts,
                                         get_pdu_controller):
    """
    Turn off one PSU and check all PSU sensor entity being removed because it can no longer get any value
    :param duthost: DUT host object
    :param localhost: localhost object
    :param creds_all_duts: Credential for snmp
    :param get_pdu_controller: PDU controller
    :return:
    """
    duthost = duthosts[enum_supervisor_dut_hostname]
    pdu_controller = get_pdu_controller(duthost)
    if not pdu_controller:
        pytest.skip('psu_controller is None, skipping this test')

    outlet_status = pdu_controller.get_outlet_status()
    if len(outlet_status) < 2:
        pytest.skip(
            'At least 2 PSUs required for rest of the testing in this case')

    # Turn on all PDUs
    logging.info("Turning all outlets on before test")
    turn_on_all_outlets(pdu_controller)

    psu_to_pdus = get_grouped_pdus_by_psu(pdu_controller)
    try:
        logging.info("Turning off PDUs connected to a random PSU")
        # Get a random PSU's related PDUs to turn off
        off_psu = random.choice(list(psu_to_pdus.keys()))
        outlets = psu_to_pdus[off_psu]
        logging.info("Toggling {} PDUs connected to {}".format(len(outlets), off_psu))
        for outlet in outlets:
            pdu_controller.turn_off_outlet(outlet)
            pytest_assert(
                wait_until(30, 5, 0, check_outlet_status, pdu_controller, outlet, False),
                (
                    "Outlet {} did not turn off within the expected timeframe."
                ).format(outlet['pdu_name'])
            )

        logging.info("Checking that turning off these outlets affects PSUs")
        # wait for psud update the database
        pytest_assert(
            wait_until(900, 20, 5, _check_psu_status_after_power_off, duthost, localhost, creds_all_duts),
            "No PSUs turned off within the expected timeframe."
        )

    finally:
        turn_on_all_outlets(pdu_controller)


def _check_psu_status_after_power_off(duthost, localhost, creds_all_duts):
    """
    Check that at least one PSU is powered off and its sensor information should be removed from mib
    :param duthost: DUT host object
    :param localhost: localhost object
    :param creds_all_duts: Credential for snmp
    :return: True if sensor information is removed from mib
    """
    snmp_physical_entity_and_sensor_info = get_entity_and_sensor_mib(
        duthost, localhost, creds_all_duts)
    entity_mib_info = snmp_physical_entity_and_sensor_info["entity_mib"]
    entity_sensor_mib_info = snmp_physical_entity_and_sensor_info["sensor_mib"]

    keys = redis_get_keys(duthost, STATE_DB, PSU_KEY_TEMPLATE.format('*'))
    # Ignore the test if the platform does not have psus (e.g Line card)
    if not keys:
        pytest.skip('PSU information does not exist in DB, skipping this test {}'.format(
            duthost.hostname))
    power_off_psu_found = False
    for key in keys:
        psu_info = redis_hgetall(duthost, STATE_DB, key)
        if psu_info['presence'] == 'false' or psu_info['status'] == 'true':
            continue
        name = key.split(TABLE_NAME_SEPARATOR_VBAR)[-1]
        entity_info_key = PHYSICAL_ENTITY_KEY_TEMPLATE.format(name)
        entity_info = redis_hgetall(duthost, STATE_DB, entity_info_key)
        position = int(entity_info['position_in_parent'])
        expect_oid = MODULE_TYPE_PSU + position * MODULE_INDEX_MULTIPLE
        assert expect_oid in entity_mib_info, (
            "Expected OID '{}' not found in entity MIB. "
            "Please ensure that the PSU information is correctly populated in the SNMP facts. "
            "Entity MIB: {}"
        ).format(expect_oid, entity_mib_info)
        for field, sensor_tuple in PSU_SENSOR_INFO.items():
            sensor_oid = expect_oid + DEVICE_TYPE_POWER_MONITOR + sensor_tuple[2]
            # entity_sensor_mib_info is only supported in image newer than 202012
            if sensor_oid in entity_mib_info:
                if psu_info['current'] == '0.0' and psu_info['power'] == '0.0':
                    power_off_psu_found = True
                    break
            if is_sensor_test_supported(duthost):
                if sensor_oid not in entity_mib_info and sensor_oid not in entity_sensor_mib_info:
                    power_off_psu_found = True
                    break
            else:
                if sensor_oid not in entity_mib_info:
                    power_off_psu_found = True
                    break
    return power_off_psu_found


@pytest.mark.disable_loganalyzer
def test_remove_insert_fan_and_check_fan_info(duthosts, enum_rand_one_per_hwsku_hostname,
                                              localhost, creds_all_duts, mocker_factory):   # noqa F811
    """

    :param duthost: DUT host object
    :param localhost: localhost object
    :param creds_all_duts: Credential for snmp
    :param mocker_factory: Factory to create fan mocker
    :return:
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    logging.info('Create mocker, it may take a few seconds...')
    single_fan_mocker = mocker_factory(duthost, 'SingleFanMocker')
    if not single_fan_mocker:
        pytest.skip(
            'Fan mocker not support on this platform, skip the rest of the test')
    if not single_fan_mocker.is_fan_removable():
        pytest.skip(
            'Fan is not removable on this platform, skip the rest of the test')
    logging.info('Mock FAN absence...')
    single_fan_mocker.mock_absence()

    logging.info('Wait {} seconds for thermalctld to update the fan information to DB'.format(
        FAN_MOCK_WAIT_TIME))
    time.sleep(FAN_MOCK_WAIT_TIME)

    keys = redis_get_keys(duthost, STATE_DB, FAN_KEY_TEMPLATE.format('*'))
    # Ignore the test if the platform does not have fans (e.g Line card)
    if not keys:
        pytest.skip('Fan information does not exist in DB, skipping this test')

    snmp_physical_entity_and_sensor_info = get_entity_and_sensor_mib(
        duthost, localhost, creds_all_duts)
    entity_mib_info = snmp_physical_entity_and_sensor_info["entity_mib"]
    entity_sensor_mib_info = snmp_physical_entity_and_sensor_info["sensor_mib"]

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
            parent_entity_info = redis_hgetall(
                duthost, STATE_DB, PHYSICAL_ENTITY_KEY_TEMPLATE.format(parent_name))
            parent_position = int(parent_entity_info['position_in_parent'])
            parent_oid = MODULE_TYPE_FAN_DRAWER + parent_position * MODULE_INDEX_MULTIPLE
        expect_oid = parent_oid + DEVICE_TYPE_FAN + position * DEVICE_INDEX_MULTIPLE
        assert expect_oid not in entity_mib_info, (
            "Absent or removed hardware component OID '{}' is still present in the SNMP entity MIB.\n"
            "Expected: OID should be absent.\n"
            "Actual: OID is present.\n"
            "SNMP entity MIB: {}"
        ).format(expect_oid, entity_mib_info)

        if not is_null_str(fan_info['speed']):
            tachometers_oid = expect_oid + SENSOR_TYPE_FAN
            # entity_sensor_mib_info is only supported in image newer than 202012
            if is_sensor_test_supported(duthost):
                assert tachometers_oid not in entity_mib_info and tachometers_oid not in entity_sensor_mib_info, (
                    'Absence fan tachometers info should not be present in the mib, but it is. '
                    'Tachometers OID: {}. Entity MIB: {}. Entity Sensor MIB: {}'
                ).format(tachometers_oid, entity_mib_info, entity_sensor_mib_info)
            else:
                assert tachometers_oid not in entity_mib_info, (
                    'Absence fan tachometers info should not be present in the mib, but it is. '
                    'Tachometers OID: {}. Entity MIB: {}'
                ).format(tachometers_oid, entity_mib_info)


def redis_get_keys(duthost, db_id, pattern):
    """
    Get all keys for a given pattern in given redis database
    :param duthost: DUT host object
    :param db_id: ID of redis database
    :param pattern: Redis key pattern
    :return: A list of key name in string
    """
    totalOutput = []

    def run_cmd_store_output(cmd):
        logging.debug('Getting keys from redis by command: {}'.format(cmd))
        output = duthost.shell(cmd)['stdout'].strip()
        if output:
            totalOutput.extend(output.split('\n'))

    if duthost.is_multi_asic:
        # Search the namespaces as well on LCs
        for asic in duthost.frontend_asics:
            cmd = 'sonic-db-cli -n {} {} KEYS \"{}\"'.format(asic.namespace, db_id, pattern)
            run_cmd_store_output(cmd)

    cmd = 'sonic-db-cli {} KEYS \"{}\"'.format(db_id, pattern)
    run_cmd_store_output(cmd)
    return totalOutput if totalOutput else None


def redis_hgetall(duthost, db_id, key):
    """
    Get all field name and values for a given key in given redis dataabse
    :param duthost: DUT host object
    :param db_id: ID of redis database
    :param key: Redis Key
    :return: A dictionary, key is field name, value is field value
    """

    def run_cmd(cmd):
        output = duthost.shell(cmd)['stdout'].strip()
        if not output:
            return {}
        # fix to make literal_eval() work with nested dictionaries
        content = output.replace('\x00', '').replace("'{", '"{').replace("}'", '}"')
        return ast.literal_eval(content)

    if duthost.is_multi_asic:
        # Search the namespaces as well on LCs
        for asic in duthost.frontend_asics:
            cmd = 'sonic-db-cli -n {} {} HGETALL \"{}\"'.format(asic.namespace, db_id, key)
            output = run_cmd(cmd)
            if output:
                return output

    cmd = 'sonic-db-cli {} HGETALL \"{}\"'.format(db_id, key)
    output = run_cmd(cmd)
    if output:
        return output
    return {}


def is_null_str(value):
    """
    Indicate if a string is None or 'None' or 'N/A'
    :param value: A string value
    :return: True if a string is None or 'None' or 'N/A'
    """
    return not value or value == str(None) or value == 'N/A'
