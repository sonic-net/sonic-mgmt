import logging
import os
import sys
import time
import re
import json
from natsort import natsorted

import pytest

from tests.common import config_reload
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.utilities import check_qos_db_fv_reference_with_table

pytestmark = [
    pytest.mark.topology('any')
]

profile_format = 'pg_lossless_{}_{}_profile'
LOSSLESS_PROFILE_PATTERN = 'pg_lossless_([1-9][0-9]*000)_([1-9][0-9]*m)_profile'

DEFAULT_CABLE_LENGTH_LIST = None
DEFAULT_LOSSLESS_HEADROOM_DATA = None
DEFAULT_INGRESS_POOL_NUMBER = 0
DEFAULT_SHARED_HEADROOM_POOL_ENABLED = False
DEFAULT_OVER_SUBSCRIBE_RATIO = None
DEFAULT_SHARED_HEADROOM_POOL_SIZE = None
DEFAULT_MTU = None
PORT_TO_TEST = None
NUMBER_OF_LANES = None
PORTS_WITH_8LANES = None
ASIC_TYPE = None

TESTPARAM_HEADROOM_OVERRIDE = None
TESTPARAM_LOSSLESS_PG = None
TESTPARAM_SHARED_HEADROOM_POOL = None
TESTPARAM_LOSSY_PG = None

BUFFER_MODEL_DYNAMIC = True

def detect_buffer_model(duthost):
    """Detect the current buffer model (dynamic or traditional) and store it for further use. Called only once when the module is initialized

    Args:
        duthost: The DUT host object
    """
    global BUFFER_MODEL_DYNAMIC
    buffer_model = duthost.shell('redis-cli -n 4 hget "DEVICE_METADATA|localhost" buffer_model')['stdout']
    BUFFER_MODEL_DYNAMIC = (buffer_model == 'dynamic')


def detect_ingress_pool_number(duthost):
    """Detect the number of ingress buffer pools and store it for further use. Called only once when the module is initialized

    Args:
        duthost: The DUT host object
    """
    global DEFAULT_INGRESS_POOL_NUMBER
    pools = duthost.shell('redis-cli -n 4 keys "BUFFER_POOL|ingress*"')['stdout']
    DEFAULT_INGRESS_POOL_NUMBER = len(pools.split())


def detect_shared_headroom_pool_mode(duthost):
    """Detect whether shared headroom pool is enabled

    Args:
        duthost: The DUT host object
    """
    global DEFAULT_SHARED_HEADROOM_POOL_ENABLED
    global DEFAULT_SHARED_HEADROOM_POOL_SIZE
    global DEFAULT_OVER_SUBSCRIBE_RATIO

    over_subscribe_ratio = duthost.shell('redis-cli -n 4 hget "DEFAULT_LOSSLESS_BUFFER_PARAMETER|AZURE" over_subscribe_ratio')['stdout']
    if over_subscribe_ratio and over_subscribe_ratio != '0':
        DEFAULT_SHARED_HEADROOM_POOL_ENABLED = True
        DEFAULT_OVER_SUBSCRIBE_RATIO = int(over_subscribe_ratio)

    shared_headroom_pool_size = duthost.shell('redis-cli -n 4 hget "BUFFER_POOL|ingress_lossless_pool" xoff')['stdout']
    if shared_headroom_pool_size and shared_headroom_pool_size != '0':
        DEFAULT_SHARED_HEADROOM_POOL_ENABLED = True
        DEFAULT_SHARED_HEADROOM_POOL_SIZE = int(shared_headroom_pool_size)


def detect_default_mtu(duthost, port_to_test):
    """Detect the mtu and store it for further use. Called only once when the module is initialized

    Args:
        duthost: The DUT host object
    """
    global DEFAULT_MTU
    if not DEFAULT_MTU:
        DEFAULT_MTU = duthost.shell('redis-cli -n 4 hget "PORT|{}" mtu'.format(port_to_test))['stdout']
        logging.info("Default MTU {}".format(DEFAULT_MTU))


def load_lossless_headroom_data(duthost):
    """Load test parameters from the json file. Called only once when the module is initialized

    Args:
        duthost: the DUT host object
    """
    global DEFAULT_LOSSLESS_HEADROOM_DATA
    if not DEFAULT_LOSSLESS_HEADROOM_DATA:
        dut_hwsku = duthost.facts["hwsku"]
        dut_platform = duthost.facts["platform"]
        skudir = "/usr/share/sonic/device/{}/{}/".format(dut_platform, dut_hwsku)
        lines = duthost.shell('cat {}/pg_profile_lookup.ini'.format(skudir))["stdout"]
        DEFAULT_LOSSLESS_HEADROOM_DATA = {}
        for line in lines.split('\n'):
            if line[0] == '#':
                continue
            tokens = line.split()
            speed = tokens[0]
            cable_length = tokens[1]
            size = tokens[2]
            xon = tokens[3]
            xoff = tokens[4]
            if not DEFAULT_LOSSLESS_HEADROOM_DATA.get(speed):
                DEFAULT_LOSSLESS_HEADROOM_DATA[speed] = {}
            DEFAULT_LOSSLESS_HEADROOM_DATA[speed][cable_length] = {'size': size, 'xon': xon, 'xoff': xoff}
        DEFAULT_LOSSLESS_HEADROOM_DATA = DEFAULT_LOSSLESS_HEADROOM_DATA


def load_test_parameters(duthost):
    """Load test parameters from the json file. Called only once when the module is initialized

    Args:
        duthost: The DUT host object
    """
    global DEFAULT_CABLE_LENGTH_LIST
    global TESTPARAM_HEADROOM_OVERRIDE
    global TESTPARAM_LOSSLESS_PG
    global TESTPARAM_SHARED_HEADROOM_POOL
    global TESTPARAM_LOSSY_PG
    global ASIC_TYPE

    param_file_name = "qos/files/dynamic_buffer_param.json"
    with open(param_file_name) as file:
        params = json.load(file)
        logging.info("Loaded test parameters {} from {}".format(params, param_file_name))
        ASIC_TYPE = duthost.facts['asic_type']
        vendor_specific_param = params[ASIC_TYPE]
        DEFAULT_CABLE_LENGTH_LIST = vendor_specific_param['default_cable_length']
        TESTPARAM_HEADROOM_OVERRIDE = vendor_specific_param['headroom-override']
        TESTPARAM_LOSSLESS_PG = vendor_specific_param['lossless_pg']
        TESTPARAM_SHARED_HEADROOM_POOL = vendor_specific_param['shared-headroom-pool']
        TESTPARAM_LOSSY_PG = vendor_specific_param['lossy_pg']


def configure_shared_headroom_pool(duthost, enable):
    """Enable or disable the shared headroom pool according to the argument

    Args:
        duthost: The DUT host object
        enable: True to enable and false to disable the shared headroom pool
    """
    if enable:
        duthost.shell("config buffer shared-headroom-pool over-subscribe-ratio 2")
    else:
        duthost.shell("config buffer shared-headroom-pool over-subscribe-ratio 0")

    time.sleep(20)


@pytest.fixture(scope="module", autouse=True)
def setup_module(duthosts, rand_one_dut_hostname, request):
    """Set up module. Called only once when the module is initialized

    Args:
        duthost: The DUT host object
    """
    global DEFAULT_SHARED_HEADROOM_POOL_ENABLED
    global DEFAULT_OVER_SUBSCRIBE_RATIO

    duthost = duthosts[rand_one_dut_hostname]
    detect_buffer_model(duthost)
    enable_shared_headroom_pool = request.config.getoption("--enable_shared_headroom_pool")
    need_to_disable_shared_headroom_pool_after_test = False
    if BUFFER_MODEL_DYNAMIC:
        detect_ingress_pool_number(duthost)
        detect_shared_headroom_pool_mode(duthost)
        load_lossless_headroom_data(duthost)
        load_test_parameters(duthost)

        logging.info("Cable length: default {}".format(DEFAULT_CABLE_LENGTH_LIST))
        logging.info("Ingress pool number {}".format(DEFAULT_INGRESS_POOL_NUMBER))
        logging.info("Lossless headroom data {}".format(DEFAULT_LOSSLESS_HEADROOM_DATA))

        if enable_shared_headroom_pool and not DEFAULT_SHARED_HEADROOM_POOL_ENABLED:
            configure_shared_headroom_pool(duthost, True)
            DEFAULT_SHARED_HEADROOM_POOL_ENABLED = True
            DEFAULT_OVER_SUBSCRIBE_RATIO = 2
            logging.info("Shared headroom pool enabled according to test option")
            need_to_disable_shared_headroom_pool_after_test = True
    else:
        pytest.skip("Dynamic buffer isn't enabled, skip the test")

    yield

    if need_to_disable_shared_headroom_pool_after_test:
        configure_shared_headroom_pool(duthost, False)


def init_log_analyzer(duthost, marker, expected, ignored=None):
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=marker)
    marker = loganalyzer.init()

    loganalyzer.load_common_config()
    loganalyzer.expect_regex = []
    loganalyzer.expect_regex.extend(expected)
    if ignored:
        loganalyzer.ignore_regex.extend(ignored)

    return loganalyzer, marker


def check_log_analyzer(loganalyzer, marker):
    loganalyzer.analyze(marker)
    return loganalyzer


def check_pool_size(duthost, ingress_lossless_pool_oid, **kwargs):
    """Check whether the pool size has been updated correctly

    The expected pool size will be calculated based on the input arguments on a per-vendor basis
    After that, it will check the expected value against the buffer pool size in BUFFER_POOL_TABLE
    and in the ASIC_DB

    Args:
        ingress_lossless_pool_oid: The SAI OID of the ingress lossless pool in ASIC_DB
        kwargs: The parameters based on which the expected pool size is calculated.
                They are represented in form of kwargs because different vendor can require different parameters
                For Mellanox, it includes:
                 - Old / new pg size
                 - Old / new pg xoff (required only over subscribe ratio is defined)
                 - Old / new pg numbers
                 - Old_ratio / new_ratio / conn_graph_facts (required only over subscribe ratio is defined)
                 - Current pool size
                 - Current shared headroom pool size (required only over subscribe ratio is defined)
                 - The expected pool size is calculated as following:
                    - Shared headroom pool disabled:
                      current_pool_size + old_pg_num * old_pg_size - new_pg_num * new_pg_size
                    - Shared headroom pool enabled by over subscribe ratio:
                      current_pool_size + old_pg_num * old_pg_size - new_pg_num * new_pg_size
                          + (old_pg_num * old_pg_xoff - new_pg_num * new_pg_xoff) * over_subscribe_ratio
    """
    def _fetch_size_difference_for_8lane_ports(duthost, conn_graph_facts):
        """Calculate the difference in buffer pool size caused by 8-lane ports on Mellanox platform

        Args:
            duthost: The duthost object
            conn_graph_facts: The connection graph facts object
        """
        global PORTS_WITH_8LANES
        hostname = conn_graph_facts['device_conn'].keys()[0]
        ports_info = conn_graph_facts['device_conn'][hostname]
        if PORTS_WITH_8LANES is None:
            PORTS_WITH_8LANES = []
            for port in ports_info.keys():
                lanes = duthost.shell('redis-cli -n 4 hget "PORT|{}" lanes'.format(port))['stdout']
                if len(lanes.split(',')) == 8:
                    PORTS_WITH_8LANES.append(port)

        lossless_pgs = duthost.shell('redis-cli keys "BUFFER_PG_TABLE:Ethernet*:3-4"')['stdout'].split()
        lossless_pgs_8lane = [pg for pg in lossless_pgs if pg[16:-4] in PORTS_WITH_8LANES]
        return len(lossless_pgs_8lane) * 2 * 9216

    logging.debug("Kwargs {}".format(kwargs))

    if duthost.facts['asic_type'] == 'mellanox':
        if kwargs.get("old_ratio") and kwargs.get("new_ratio"):
            curr_pool_size = int(kwargs["pool_size"])
            curr_shp_size = int(kwargs["shp_size"])
            old_ratio = int(kwargs.get("old_ratio"))
            new_ratio = int(kwargs.get("new_ratio"))
            conn_graph_facts = kwargs.get("conn_graph_facts")
            original_memory = curr_pool_size * DEFAULT_INGRESS_POOL_NUMBER + curr_shp_size
            if new_ratio == 0:
                expected_shp_size = 0
                expected_pool_size = (original_memory - curr_shp_size * old_ratio)
                if old_ratio != 0:
                    expected_pool_size = expected_pool_size - _fetch_size_difference_for_8lane_ports(duthost, conn_graph_facts)
                expected_pool_size = expected_pool_size / DEFAULT_INGRESS_POOL_NUMBER
            else:
                expected_shp_size = curr_shp_size * old_ratio / new_ratio
                expected_pool_size = (original_memory - expected_shp_size) / DEFAULT_INGRESS_POOL_NUMBER
        elif kwargs.get("config_shp_size"):
            expected_shp_size = int(kwargs.get("config_shp_size"))
            expected_pool_size = None
        else:
            curr_pool_size = int(kwargs["pool_size"])

            if "old_pg_number" in kwargs:
                old_pg_number = int(kwargs["old_pg_number"])
            else:
                old_pg_number = 2

            if old_pg_number:
                old_size = int(kwargs["old_size"])
            else:
                old_size = 0

            if "new_pg_number" in kwargs:
                new_pg_number = int(kwargs["new_pg_number"])
            else:
                new_pg_number = old_pg_number

            if new_pg_number:
                if "new_size" in kwargs:
                    new_size = int(kwargs["new_size"])
                else:
                    new_size = old_size
                new_reserved = new_pg_number * new_size
            else:
                new_reserved = 0

            if "adjust_lossy_pg_size" in kwargs:
                adjust_lossy_pg_size = int(kwargs["adjust_lossy_pg_size"])
            else:
                adjust_lossy_pg_size = 0

            original_memory = curr_pool_size * DEFAULT_INGRESS_POOL_NUMBER + old_size * old_pg_number + adjust_lossy_pg_size

            if DEFAULT_OVER_SUBSCRIBE_RATIO:
                private_headroom_str = TESTPARAM_SHARED_HEADROOM_POOL.get("private_pg_headroom") 
                if private_headroom_str:
                    private_headroom_number = int(private_headroom_str) 
                else:
                    private_headroom_number = 0
                curr_shp_size = int(kwargs["shp_size"])
                if old_pg_number:
                    old_xoff = int(kwargs["old_xoff"])
                else:
                    old_xoff = 0
                if new_pg_number and "new_xoff" in kwargs:
                    new_xoff = int(kwargs["new_xoff"])
                else:
                    new_xoff = old_xoff
                original_memory += curr_shp_size
                shp_size_diff = new_xoff * new_pg_number - old_xoff * old_pg_number
                if old_pg_number != 0:
                    original_memory += private_headroom_number
                    shp_size_diff += private_headroom_number
                if new_pg_number != 0:
                    new_reserved += private_headroom_number
                    shp_size_diff -= private_headroom_number
                expected_shp_size = curr_shp_size + shp_size_diff / DEFAULT_OVER_SUBSCRIBE_RATIO
                new_reserved += expected_shp_size
            else:
                expected_shp_size = None
                curr_shp_size = None

            expected_pool_size = (original_memory - new_reserved) / DEFAULT_INGRESS_POOL_NUMBER

            logging.debug("Expected pool {}, expec shp {}, curr_shp {} default ovs {}".format(expected_pool_size, expected_shp_size, curr_shp_size, DEFAULT_OVER_SUBSCRIBE_RATIO))

    pytest_assert(ensure_pool_size(duthost, 20, expected_pool_size, expected_shp_size, ingress_lossless_pool_oid),
                  "Pool size isn't correct in database: expected pool {} shp {}, size in APPL_DB pool {} shp {}, size in ASIC_DB {}".format(
                      expected_pool_size,
                      expected_shp_size,
                      duthost.shell('redis-cli hget "BUFFER_POOL_TABLE:ingress_lossless_pool" size')['stdout'],
                      duthost.shell('redis-cli hget "BUFFER_POOL_TABLE:ingress_lossless_pool" xoff')['stdout'],
                      get_pool_size_from_asic_db(duthost, ingress_lossless_pool_oid))
                  if DEFAULT_OVER_SUBSCRIBE_RATIO else
                  "Pool size isn't correct in database: expected {}, size in APPL_DB pool {}, size in ASIC_DB {}".format(
                      expected_pool_size,
                      duthost.shell('redis-cli hget "BUFFER_POOL_TABLE:ingress_lossless_pool" size')['stdout'],
                      get_pool_size_from_asic_db(duthost, ingress_lossless_pool_oid))
                  )


def get_pool_size_from_asic_db(duthost, ingress_lossless_pool_oid):
    pool_sai = _compose_dict_from_cli(duthost.shell('redis-cli -n 1 hgetall ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_POOL:{}'.format(ingress_lossless_pool_oid))['stdout'].split('\n'))
    return pool_sai.get('SAI_BUFFER_POOL_ATTR_SIZE'), pool_sai.get('SAI_BUFFER_POOL_ATTR_XOFF_SIZE')


def ensure_pool_size(duthost, timeout, expected_pool_size, expected_shp_size, ingress_lossless_pool_oid=None):
    """Make sure the size of the buffer pool and shared headroom pool is as expected within a given time in APPL_DB and ASIC_DB (optional)

    Args:
        timeout: The time out value
        expected_pool_size: The expected shared buffer pool size
        expected_shp_size: The expected shared headroom pool size
        ingress_lossless_pool_oid: The SAI OID of ingress lossless buffer pool. If it is omitted, the ASIC DB won't be checked
    """
    def _ensure_pool_size(duthost, expected_pool_size, expected_shp_size, ingress_lossless_pool_oid=None):
        pool_app =_compose_dict_from_cli(duthost.shell('redis-cli hgetall "BUFFER_POOL_TABLE:ingress_lossless_pool"')['stdout'].split('\n'))

        if expected_pool_size and int(pool_app['size']) != expected_pool_size:
            return False

        if DEFAULT_OVER_SUBSCRIBE_RATIO and int(pool_app['xoff']) != expected_shp_size:
            return False

        if ingress_lossless_pool_oid:
            pool_size, shp_size = get_pool_size_from_asic_db(duthost, ingress_lossless_pool_oid)
            if expected_pool_size and int(pool_size) != expected_pool_size:
                return False

            if expected_shp_size and expected_shp_size != int(shp_size):
                return False

        return True

    if timeout >= 5:
        delay = timeout / 5
    else:
        delay = 1

    return wait_until(timeout, delay, _ensure_pool_size, duthost, expected_pool_size, expected_shp_size, ingress_lossless_pool_oid)


def check_pg_profile(duthost, pg, expected_profile, fail_test=True):
    """Check whether the profile in BUFFER_PG match the expected value in a wait_until loop with maximum timeout as 10 seconds

    Args:
        pg: The key of buffer pg in BUFFER_PG table. Format: BUFFER_PG|<port>|<pg>
        expected_profile: The name of the expected profile
        fail_test: Fail the test by pytest_assert in case expected_profile not found within given time

    Returns:
        Whether the expected profile has been found within given time
    """
    def _check_pg_profile(duthost, pg, expected_profile):
        if check_qos_db_fv_reference_with_table(duthost) == True:
            profile = duthost.shell('redis-cli hget {} profile'.format(pg))['stdout'][1:-1]
            return (profile == 'BUFFER_PROFILE_TABLE:' + expected_profile)
        else:
            profile = duthost.shell('redis-cli hget {} profile'.format(pg))['stdout']
            return (profile == expected_profile)

    if wait_until(10, 2, _check_pg_profile, duthost, pg, expected_profile):
        return True
    else:
        if fail_test:
            pytest_assert(False, "Profile in PG {} isn't {}".format(pg, expected_profile))
        else:
            return False


def check_pfc_enable(duthost, port, expected_pfc_enable_map):
    """Check whether the pfc_enable map in port table is correct in a wait_until loop with maximum timeout as 10 seconds

    Args:
        port: The port to be checked
        expected_pfc_enable_map: The expected pfc_enable map
    """
    def _check_pfc_enable(duthost, port, expected_pfc_enable_map):
        pfc_enable = duthost.shell('redis-cli -n 4 hget "PORT_QOS_MAP|{}" pfc_enable'.format(port))['stdout']
        return (expected_pfc_enable_map == pfc_enable)

    pytest_assert(wait_until(10, 2, _check_pfc_enable, duthost, port, expected_pfc_enable_map),
                  "Port {} pfc enable check failed expected: {} got: {}".format(
                      port,
                      expected_pfc_enable_map,
                      duthost.shell('redis-cli -n 4 hget "PORT_QOS_MAP|{}" pfc_enable'.format(port))['stdout']))


def check_lossless_profile_removed(duthost, profile, sai_oid=None):
    """Check whether the lossless profile has been removed from APPL_DB, STATE_DB and ASIC_DB (if sai_oid provided)

    Args:
        profile: The name of the buffer profile to be checked
        sai_oid: The SAI OID in ASIC_DB of the buffer profile
                 If it is None the ASIC_DB won't be checked
    """
    profile_info = duthost.shell('redis-cli -n 6 hgetall "BUFFER_PROFILE_TABLE|{}"'.format(profile))['stdout']
    pytest_assert(not profile_info, "Profile {} isn't removed from STATE_DB".format(profile))
    profile_info = duthost.shell('redis-cli hgetall "BUFFER_PROFILE_TABLE:{}"'.format(profile))['stdout']
    pytest_assert(not profile_info, "Profile {} isn't removed from APPL_DB".format(profile))
    logging.debug('Profile {} has been removed from STATE_DB and APPL_DB'.format(profile))
    if sai_oid:
        profile_info = duthost.shell('redis-cli -n 1 hgetall {}'.format(sai_oid))['stdout']
        pytest_assert(not profile_info, "Profile {} hasn't been removed from ASIC_DB".format(sai_oid))


def fetch_initial_asic_db(duthost):
    profiles_in_asicdb = duthost.shell('redis-cli -n 1 keys "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_PROFILE*"')['stdout']
    return set(profiles_in_asicdb.split('\n'))


def _compose_dict_from_cli(fields_list):
    """Convert the out put of hgetall command to a dict object containing the field, key pairs of the database table content

    Args:
        fields_list: A list of lines, the output of redis-cli hgetall command
    """
    return dict(zip(fields_list[0::2], fields_list[1::2]))


def check_buffer_profile_details(duthost, initial_profiles, profile_name, profile_oid, pool_oid):
    """Check buffer profile details.

    The following items are tested:
     - Whether the headroom information, like xoff, is correct.
       This is tested by comparing with standard profile in pg_profile_lookup table
     - Whether the profile information in APPL_DB matches that in ASIC_DB

    Args:
        initial_profiles: The keys of buffer profiles in ASIC_DB at the beginning of the test
        profile_name: Name of the profile
        profile_oid: SAI OID of the profile
        pool_oid: SAI OID of ingress lossless pool
    """
    profile_appldb = _compose_dict_from_cli(duthost.shell('redis-cli hgetall BUFFER_PROFILE_TABLE:{}'.format(profile_name))['stdout'].split('\n'))
    logging.debug("APPL_DB buffer profile {}: {} ".format(profile_name, profile_appldb))

    # Check the profile against the standard value
    m = re.search(LOSSLESS_PROFILE_PATTERN, profile_name)
    if m:
        # This means it's a dynamic profile
        speed = m.group(1)
        cable_length = m.group(2)
        std_profiles_for_speed = DEFAULT_LOSSLESS_HEADROOM_DATA.get(speed)
        if std_profiles_for_speed:
            std_profile = std_profiles_for_speed.get(cable_length)
            if std_profile:
                # This means it's a profile with std speed and cable length. We can check whether the headroom data is correct
                pytest_assert(profile_appldb['xon'] == std_profile['xon'] and profile_appldb['xoff'] == std_profile['xoff']
                              and (profile_appldb['size'] == std_profile['size'] or DEFAULT_SHARED_HEADROOM_POOL_ENABLED),
                              "Generated profile {} doesn't match the std profile {}".format(profile_appldb, std_profile))
            else:
                for std_cable_len, std_profile in std_profiles_for_speed.items():
                    if int(std_cable_len[:-1]) > int(cable_length[:-1]):
                        pytest_assert(int(std_profile['xoff']) >= int(profile_appldb['xoff']),
                                      "XOFF of generated profile {} is greater than standard profile {} while its cable length is less".format(profile_appldb, std_profile))
                    else:
                        pytest_assert(int(std_profile['xoff']) <= int(profile_appldb['xoff']),
                                      "XOFF of generated profile {} is less than standard profile {} while its cable length is greater".format(profile_appldb, std_profile))
        else:
            logging.info("Skip headroom checking because headroom information is not provided for speed {}".format(speed))

    profiles_in_asicdb = set(duthost.shell('redis-cli -n 1 keys "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_PROFILE*"')['stdout'].split('\n'))
    diff = profiles_in_asicdb - initial_profiles
    if len(diff) == 1:
        profile_oid = diff.pop()
    pytest_assert(profile_oid, "Unable to fetch SAI OID for profile {}, initial SAI OID set {} current set {}".format(
        profile_name, initial_profiles, profiles_in_asicdb))

    logging.debug("Initial profiles {} and current profiles {} have the following difference(s) {}".format(initial_profiles, profiles_in_asicdb, diff))

    profile_sai = _compose_dict_from_cli(duthost.shell('redis-cli -n 1 hgetall {}'.format(profile_oid))['stdout'].split('\n'))

    logging.debug("SAI object for new profile {}: oid {} content {}".format(profile_name, profile_oid, profile_sai))

    if pool_oid == None:
        pool_oid = profile_sai['SAI_BUFFER_PROFILE_ATTR_POOL_ID']
    if profile_appldb.get('dynamic_th'):
        sai_threshold_value = profile_appldb['dynamic_th']
        sai_threshold_mode = 'SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC'
    else:
        sai_threshold_value = profile_appldb['static_th']
        sai_threshold_mode = 'SAI_BUFFER_PROFILE_THRESHOLD_MODE_STATIC'
    assert profile_sai == {'SAI_BUFFER_PROFILE_ATTR_XON_TH': profile_appldb['xon'],
                           'SAI_BUFFER_PROFILE_ATTR_XOFF_TH': profile_appldb['xoff'],
                           'SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE': profile_appldb['size'],
                           'SAI_BUFFER_PROFILE_ATTR_POOL_ID': pool_oid,
                           'SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE': sai_threshold_mode,
                           'SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH': sai_threshold_value}

    return profile_oid, pool_oid


def make_expected_profile_name(speed, cable_length, other_factors=None):
    """Make the name of an expected profile according to parameters

    Args:
        speed: The speed of the port (on which the profile is applied)
        cable_length: The cable length of the port
        other_factors: Other factors that affects profile name, like mtu, threshold, etc
                       It can be omitted.

    Return:
        The name of the profile
    """
    expected_profile = 'pg_lossless_{}_{}_'.format(speed, cable_length)
    if other_factors:
        expected_profile += '_'.join(other_factors) + '_'
    if ASIC_TYPE == 'mellanox':
        if NUMBER_OF_LANES == 8 and speed != '400000':
            expected_profile += '8lane_'
    expected_profile += 'profile'
    return expected_profile


@pytest.fixture(params=['50000', '10000'])
def speed_to_test(request):
    """Used to parametrized test cases for speeds

    Args:
        param request: The pytest request object

    Return:
        speed_to_test
    """
    return request.param


@pytest.fixture(params=['15m', '40m'])
def cable_len_to_test(request):
    """Used to parametrized test cases for cable length

    Args:
        request: The pytest request object

    Return:
        cable_len_to_test
    """
    return request.param


@pytest.fixture(params=['1500', '9100'])
def mtu_to_test(request):
    """Used to parametrized test cases for mtu

    Args:
        request: The pytest request object

    Return:
        cable_len_to_test
    """
    return request.param


@pytest.fixture(scope="module", autouse=True)
def port_to_test(request, duthost):
    """Used to parametrized test cases for port

    Args:
        request: The pytest request object

    Return:
        port_to_test
    """
    global PORT_TO_TEST
    global NUMBER_OF_LANES
    if PORT_TO_TEST:
        return PORT_TO_TEST

    dutLagInterfaces = []
    mgFacts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    ports = mgFacts['minigraph_ports'].keys()

    for _, lag in mgFacts["minigraph_portchannels"].items():
        dutLagInterfaces += lag["members"]

    testPort = set(mgFacts["minigraph_ports"].keys())
    testPort -= set(dutLagInterfaces)
    pytest_require(len(testPort) > 0, "No port to run test")

    PORT_TO_TEST = list(testPort)[0]
    lanes = duthost.shell('redis-cli -n 4 hget "PORT|{}" lanes'.format(PORT_TO_TEST))['stdout']
    NUMBER_OF_LANES = len(lanes.split(','))

    logging.info("Port to test {}, number of lanes {}".format(PORT_TO_TEST, NUMBER_OF_LANES))

    return PORT_TO_TEST


@pytest.fixture(params=['3-4', '6'])
def pg_to_test(request):
    """Used to parametrized test cases for PGs under test

    Args:
        request: The pytest request object

    Return:
        pg_to_test
    """
    return request.param


def test_change_speed_cable(duthosts, rand_one_dut_hostname, conn_graph_facts, port_to_test, speed_to_test, mtu_to_test, cable_len_to_test):
    """The testcase for changing the speed and cable length of a port

    Change the variables of the port, including speed, mtu and cable length, in different ways and observe whether the DUT behaves correctly
    For any of the variable, if it matches the current port configuration, we will skip configuring it.
    If all of the speed_to_test, mtu_to_test and cable_len_to_test match the current value, the test will be skipped

    The flow of the test case:
        1. Update the port configuration according to input parameters
        2. Determine whether the profile removing behavior can be verified:
           If neither mtu nor cable length is default value, they will be applied on the port_to_test only,
           and the generated profile will be removed after the configuration change because the profile is referenced by this port only.
           For example:
               The mtu_to_test 1500 only applied on the port_to_test, thus the *_mtu1500_* profile is referenced by the port only
               The *_mtu1500_* mtu will be removed after the mtu of the port is updated to default value.
               In this case, we are able to verify whether the buffer profile is removed after mtu reverted or all PGs are removed.
               Other the other hand, if the mtu is 9100, the buffer profile can be referenced by many other ports and it's less possible for us to verify the removing behavior.
           We will remove and readd an extra PG 6 to verify the removing behavior as well.
        3. Each time the port configuration updated, the following items will be checked as much as possible:
            - Whether the new profile is generated in APPL_DB, STATE_DB and ASIC_DB.
            - Whether the pool size is updated in APPL_DB and ASIC_DB.
        4. Each time the PG on a port is added or removed, the following items will be checked:
            - Whether the profile referenced by PGs is as expected according to the port configuration.
            - Whether the profile is removed if all PGs are removed and we are able to check removing behavior (result of step 2).
            - Whether the pfc_enable filed of the port has been updated accordingly.

    Args:
        port_to_test: On which port will the test be performed
        speed_to_test: To what speed will the port's be changed
        mtu_to_test: To what mtu will the port's be changed
        cable_len_to_test: To what cable length will the port's be changed
    """
    duthost = duthosts[rand_one_dut_hostname]
    supported_speeds = duthost.shell('redis-cli -n 6 hget "PORT_TABLE|{}" supported_speeds'.format(port_to_test))['stdout']
    if supported_speeds and speed_to_test not in supported_speeds:
        pytest.skip('Speed is not supported by the port, skip')
    original_speed = duthost.shell('redis-cli -n 4 hget "PORT|{}" speed'.format(port_to_test))['stdout']
    original_cable_len = duthost.shell('redis-cli -n 4 hget "CABLE_LENGTH|AZURE" {}'.format(port_to_test))['stdout']

    if check_qos_db_fv_reference_with_table(duthost) == True:
        profile = duthost.shell('redis-cli hget "BUFFER_PG_TABLE:{}:3-4" profile'.format(port_to_test))['stdout'][1:-1]
    else:
        profile = "BUFFER_PROFILE_TABLE:" + duthost.shell('redis-cli hget "BUFFER_PG_TABLE:{}:3-4" profile'.format(port_to_test))['stdout']
    detect_default_mtu(duthost, port_to_test)

    original_pg_size = int(duthost.shell('redis-cli hget "{}" size'.format(profile))['stdout'])
    original_pool_size = int(duthost.shell('redis-cli hget BUFFER_POOL_TABLE:ingress_lossless_pool size')['stdout'])
    if DEFAULT_OVER_SUBSCRIBE_RATIO:
        original_pg_xoff = int(duthost.shell('redis-cli hget "{}" xoff'.format(profile))['stdout'])
        original_shp_size = int(duthost.shell('redis-cli hget BUFFER_POOL_TABLE:ingress_lossless_pool xoff')['stdout'])
    else:
        original_pg_xoff = None
        original_shp_size = None

    initial_asic_db_profiles = fetch_initial_asic_db(duthost)

    if mtu_to_test == DEFAULT_MTU:
        if speed_to_test == original_speed and cable_len_to_test == original_cable_len:
            pytest.skip('Speed, MTU and cable length matches the default value, nothing to test, skip')
        expected_profile = make_expected_profile_name(speed_to_test, cable_len_to_test)
        if duthost.shell('redis-cli hget BUFFER_PROFILE_TABLE:{}'.format(expected_profile))['stdout']:
            pytest.skip('The buffer profile has existed, most of the checks can not be performed, skip')

    try:
        if not speed_to_test == original_speed:
            logging.info("Changing port's speed to {}".format(speed_to_test))
            duthost.shell('config interface speed {} {}'.format(port_to_test, speed_to_test))
        if not mtu_to_test == DEFAULT_MTU:
            logging.info("Changing port's mtu to {}".format(mtu_to_test))
            duthost.shell('config interface mtu {} {}'.format(port_to_test, mtu_to_test))
        if not cable_len_to_test == original_cable_len:
            logging.info("Changing port's cable length to {}".format(cable_len_to_test))
            duthost.shell('config interface cable-length {} {}'.format(port_to_test, cable_len_to_test))

        check_profile_removed = cable_len_to_test not in DEFAULT_CABLE_LENGTH_LIST

        # Check whether profile is correct in PG table
        if mtu_to_test != DEFAULT_MTU:
            expected_profile = make_expected_profile_name(speed_to_test, cable_len_to_test, ['mtu{}'.format(mtu_to_test)])
            check_profile_removed = True
        else:
            expected_profile = make_expected_profile_name(speed_to_test, cable_len_to_test)

        logging.info('[Speed and/or cable-len and/or MTU updated] Checking whether new profile {} has been created and pfc_enable has been updated'.format(expected_profile))
        check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), expected_profile)
        check_pfc_enable(duthost, port_to_test, '3,4')
        profile_oid, pool_oid = check_buffer_profile_details(duthost, initial_asic_db_profiles, expected_profile, None, None)
        logging.info('SAI OID for newly created profile {} ingress lossless pool {}'.format(profile_oid, pool_oid))

        # Check whether profile exist
        pg_size = int(duthost.shell('redis-cli hget "BUFFER_PROFILE_TABLE:{}" size'.format(expected_profile))['stdout'])
        pg_xoff = int(duthost.shell('redis-cli hget "BUFFER_PROFILE_TABLE:{}" xoff'.format(expected_profile))['stdout']) if DEFAULT_OVER_SUBSCRIBE_RATIO else None
        check_pool_size(duthost,
                        pool_oid,
                        pool_size = original_pool_size,
                        shp_size = original_shp_size,
                        old_xoff = original_pg_xoff,
                        new_xoff = pg_xoff,
                        old_size = original_pg_size,
                        new_size = pg_size)

        # Remove all the lossless profile on the port
        logging.info('[Remove all lossless PGs] Checking pool size and pfc_enable')
        duthost.shell('config interface buffer priority-group lossless remove {} 3-4'.format(port_to_test))

        check_pool_size(duthost,
                        pool_oid,
                        pool_size = original_pool_size,
                        shp_size = original_shp_size,
                        old_xoff = original_pg_xoff,
                        old_size = original_pg_size,
                        new_pg_number = 0)

        check_pfc_enable(duthost, port_to_test, '')

        if check_profile_removed:
            logging.info('[Remove dynamic profile on PG removed] Checking whether the profile {} is removed on receiving all lossless PG removed'.format(expected_profile))
            check_lossless_profile_removed(duthost, expected_profile, profile_oid)

            # Re-add another lossless priority
            logging.info('Re-add a lossless_pg and check pool size and pfc_enable')
            duthost.shell('config interface buffer priority-group lossless add {} 6'.format(port_to_test))

            check_pool_size(duthost,
                            pool_oid,
                            pool_size = original_pool_size,
                            shp_size = original_shp_size,
                            old_xoff = original_pg_xoff,
                            new_xoff = pg_xoff,
                            old_size = original_pg_size,
                            new_size = pg_size,
                            new_pg_number = 1)

            check_pfc_enable(duthost, port_to_test, '6')
            profile_oid, _ = check_buffer_profile_details(duthost, initial_asic_db_profiles, expected_profile, None, pool_oid)

            if cable_len_to_test != original_cable_len:
                logging.info('[Revert the cable length to the default value] Checking whether the profile is updated')
                duthost.shell('config interface cable-length {} {}'.format(port_to_test, original_cable_len))

            if mtu_to_test != DEFAULT_MTU:
                logging.info('[Revert the mtu to the default value] Checking whether the profile is updated')
                duthost.shell('config interface mtu {} {}'.format(port_to_test, DEFAULT_MTU))

            # Remove old profile on cable length change
            logging.info('[Remove dynamic profile on cable length and/or MTU updated] Checking whether the old profile is removed')
            check_lossless_profile_removed(duthost, expected_profile, profile_oid)
            expected_profile = make_expected_profile_name(speed_to_test, original_cable_len)
            check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:6'.format(port_to_test), expected_profile)

            pg_size = int(duthost.shell('redis-cli hget "BUFFER_PROFILE_TABLE:{}" size'.format(expected_profile))['stdout'])
            pg_xoff = int(duthost.shell('redis-cli hget "BUFFER_PROFILE_TABLE:{}" xoff'.format(expected_profile))['stdout']) if DEFAULT_OVER_SUBSCRIBE_RATIO else None
            check_pool_size(duthost,
                            pool_oid,
                            pool_size = original_pool_size,
                            shp_size = original_shp_size,
                            old_xoff = original_pg_xoff,
                            new_xoff = pg_xoff,
                            old_size = original_pg_size,
                            new_size = pg_size,
                            new_pg_number = 1)

            duthost.shell('config interface buffer priority-group lossless remove {} 6'.format(port_to_test))

            check_pool_size(duthost,
                            pool_oid,
                            pool_size = original_pool_size,
                            shp_size = original_shp_size,
                            old_xoff = original_pg_xoff,
                            new_xoff = pg_xoff,
                            old_size = original_pg_size,
                            new_pg_number = 0)
            check_pfc_enable(duthost, port_to_test, '')
        else:
            if cable_len_to_test != original_cable_len:
                logging.info('[Update cable length without any lossless pg configured]')
                duthost.shell('config interface cable-length {} {}'.format(port_to_test, original_cable_len))
            if mtu_to_test != DEFAULT_MTU:
                logging.info('[Update mtu without any lossless pg configured]')
                duthost.shell('config interface mtu {} {}'.format(port_to_test, DEFAULT_MTU))

        if speed_to_test != original_speed:
            logging.info('[Update speed without any lossless pg configured]')
            duthost.shell('config interface speed {} {}'.format(port_to_test, original_speed))

        logging.info('[Add lossless pg with speed and cable length ready]')
        duthost.shell('config interface buffer priority-group lossless add {} 3-4'.format(port_to_test))

        expected_profile = make_expected_profile_name(original_speed, original_cable_len)
        check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), expected_profile)
        check_pfc_enable(duthost, port_to_test, '3,4')

        check_pool_size(duthost,
                        pool_oid,
                        pool_size = original_pool_size,
                        shp_size = original_shp_size,
                        old_xoff = original_pg_xoff,
                        old_size = original_pg_size)

        logging.info('[Extra lossless PG]')
        duthost.shell('config interface buffer priority-group lossless add {} 6'.format(port_to_test))

        check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:6'.format(port_to_test), expected_profile)
        check_pfc_enable(duthost, port_to_test, '3,4,6')

        check_pool_size(duthost,
                        pool_oid,
                        pool_size = original_pool_size,
                        shp_size = original_shp_size,
                        old_xoff = original_pg_xoff,
                        old_size = original_pg_size,
                        new_pg_number = 3)

        logging.info('[Restore config]')
        duthost.shell('config interface buffer priority-group lossless remove {} 6'.format(port_to_test))

        check_pfc_enable(duthost, port_to_test, '3,4')

        check_pool_size(duthost,
                        pool_oid,
                        pool_size = original_pool_size,
                        shp_size = original_shp_size,
                        old_xoff = original_pg_xoff,
                        old_size = original_pg_size)
    finally:
        duthost.shell('config interface buffer priority-group lossless remove {}'.format(port_to_test), module_ignore_errors = True)
        duthost.shell('config interface speed {} {}'.format(port_to_test, original_speed), module_ignore_errors = True)
        duthost.shell('config interface mtu {} {}'.format(port_to_test, DEFAULT_MTU), module_ignore_errors = True)
        duthost.shell('config interface cable-length {} {}'.format(port_to_test, original_cable_len), module_ignore_errors = True)
        duthost.shell('config interface buffer priority-group lossless add {} 3-4'.format(port_to_test), module_ignore_errors = True)
        ensure_pool_size(duthost, 60, original_pool_size, original_shp_size, None)


def _parse_buffer_profile_params(param, cmd, name):
    """A helper for test_headroom_override, parsing the parameters from the pre-provided json file

    Args:
        param: The dict containing test parameters parsed from dynamic_buffer_param.json
        return: A tuple consisting of new headroom size and cli string

    Return:
        A tuple consists of:
            - The CLI string by which a headroom-override profile can be configured
            - The size of new profile
    """
    cli_str = "config buffer profile {} {}".format(cmd, name)
    xon = None
    if 'xon' in param:
        xon = param['xon']
        cli_str += " --xon " + xon

    xoff = ""
    if 'xoff' in param:
        xoff = param['xoff']
        cli_str += " --xoff " + xoff

    size = ""
    if DEFAULT_SHARED_HEADROOM_POOL_ENABLED and xon:
        new_size = int(xon)
    elif 'size' in param:
        size = param['size']
        cli_str += " --size " + size
        new_size = int(size)
    elif xoff and xon:
        new_size = int(xon) + int(xoff)
    else:
        new_size = None

    if 'dynamic_th' in param:
        cli_str += " --dynamic_th " + param['dynamic_th']
    return cli_str, new_size, xoff


def test_headroom_override(duthosts, rand_one_dut_hostname, conn_graph_facts, port_to_test):
    """Test case for headroom override

    Verify the headroom override behavior.
    All arguments required for testing are fetched from a predefined json file on a per-vendor basis.
    The test will be skipped in case the arguments are not provided.

    The flow of the test case:
        1. Fetch the parameters
        2. Add the headroom override profile and apply it to PG 3-4 on port_to_test
        3. Verify:
            - Whether the profile referenced by PG is correct
            - Whether the pfc_enable matches the PG
            - Whether the buffer profile is correct deployed in APPL_DB, STATE_DB and ASIC_DB
            - Whether the pool size has been updated correctly
        4. Add PG 6, verify the related info
        5. Update the headroom override profile and verify the related info
        6. Negative test: try to remove the headroom override profile.
           Verify it is not removed because it is still being referenced.
        7. Revert the PG configurations, verify the related info

    Args:
        port_to_test: On which port will the test be performed
    """
    duthost = duthosts[rand_one_dut_hostname]
    if not TESTPARAM_HEADROOM_OVERRIDE:
        pytest.skip("Headroom override test skipped due to no parameters provided")

    original_speed = duthost.shell('redis-cli -n 4 hget "PORT|{}" speed'.format(port_to_test))['stdout']
    original_cable_len = duthost.shell('redis-cli -n 4 hget "CABLE_LENGTH|AZURE" {}'.format(port_to_test))['stdout']
    if check_qos_db_fv_reference_with_table(duthost) == True:
        original_profile = duthost.shell('redis-cli hget "BUFFER_PG_TABLE:{}:3-4" profile'.format(port_to_test))['stdout'][1:-1]
    else:
        original_profile = duthost.shell('redis-cli hget "BUFFER_PG_TABLE:{}:3-4" profile'.format(port_to_test))['stdout']
        original_profile = "BUFFER_PROFILE_TABLE:" + original_profile

    original_pg_size = duthost.shell('redis-cli hget "{}" size'.format(original_profile))['stdout']
    original_pool_size = duthost.shell('redis-cli hget BUFFER_POOL_TABLE:ingress_lossless_pool size')['stdout']
    if DEFAULT_OVER_SUBSCRIBE_RATIO:
        original_shp_size = duthost.shell('redis-cli hget BUFFER_POOL_TABLE:ingress_lossless_pool xoff')['stdout']
        original_pg_xoff = duthost.shell('redis-cli hget "{}" xoff'.format(original_profile))['stdout']
    else:
        original_shp_size = None
        original_pg_xoff = None

    initial_asic_db_profiles = fetch_initial_asic_db(duthost)

    try:
        # Configure a static profile
        param = TESTPARAM_HEADROOM_OVERRIDE.get("add")
        if not param:
            pytest.skip('Headroom override test skipped due to no parameters for "add" command provided')
        else:
            cli_str, new_size, new_xoff = _parse_buffer_profile_params(param, "add", "headroom-override")

        logging.info("[Prepare configuration] {}".format(cli_str))
        duthost.shell(cli_str)

        logging.info("[Test: headroom override on lossless PG 3-4] Apply the profile on the PG and check pool size")
        duthost.shell('config interface buffer priority-group lossless set {} 3-4 headroom-override'.format(port_to_test))

        check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), 'headroom-override')
        check_pfc_enable(duthost, port_to_test, '3,4')
        profile_oid, pool_oid = check_buffer_profile_details(duthost, initial_asic_db_profiles, "headroom-override", None, None)

        check_pool_size(duthost,
                        pool_oid,
                        pool_size = original_pool_size,
                        shp_size = original_shp_size,
                        old_xoff = original_pg_xoff,
                        new_xoff = new_xoff,
                        old_size = original_pg_size,
                        new_size = new_size)

        # Add another headroom override
        logging.info("[Test: headroom override on more lossless PGs 6] Apply the profile on the PG and check pool size")
        duthost.shell('config interface buffer priority-group lossless add {} 6 headroom-override'.format(port_to_test))

        check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:6'.format(port_to_test), 'headroom-override')
        check_pfc_enable(duthost, port_to_test, '3,4,6')
        profile_oid, _ = check_buffer_profile_details(duthost, initial_asic_db_profiles, "headroom-override", profile_oid, pool_oid)

        check_pool_size(duthost,
                        pool_oid,
                        pool_size = original_pool_size,
                        shp_size = original_shp_size,
                        old_xoff = original_pg_xoff,
                        new_xoff = new_xoff,
                        old_size = original_pg_size,
                        new_size = new_size,
                        new_pg_number = 3)

        param = TESTPARAM_HEADROOM_OVERRIDE.get("set")
        if not param:
            pytest.skip('Headroom override test skipped due to no parameters for "set" command provided')
        else:
            cli_str, new_size, new_xoff = _parse_buffer_profile_params(param, "set", "headroom-override")

        logging.info("[Test: update headroom-override profile] Update the profile and check pool size: {}".format(cli_str))
        duthost.shell(cli_str)

        check_pool_size(duthost,
                        pool_oid,
                        pool_size = original_pool_size,
                        shp_size = original_shp_size,
                        old_xoff = original_pg_xoff,
                        new_xoff = new_xoff,
                        old_size = original_pg_size,
                        new_size = new_size,
                        new_pg_number = 3)

        # Restore configuration
        logging.info("[Test: static headroom being referenced can not be removed]")
        duthost.shell('config buffer profile remove headroom-override', module_ignore_errors = True)

        profile = duthost.shell('redis-cli hgetall "BUFFER_PROFILE_TABLE:headroom-override"')['stdout']
        pytest_assert(profile, 'Headroom override profile has been removed when being referenced')
        logging.info("[Restore configuration]")
        duthost.shell('config interface buffer priority-group lossless remove {}'.format(port_to_test))
        duthost.shell('config interface buffer priority-group lossless add {} 3-4'.format(port_to_test))

        check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), original_profile.split(':')[1])
        check_pfc_enable(duthost, port_to_test, '3,4')
        check_pool_size(duthost,
                        pool_oid,
                        pool_size = original_pool_size,
                        shp_size = original_shp_size,
                        old_xoff = original_pg_xoff,
                        old_size = original_pg_size,
                        new_pg_number = 2)
    finally:
        duthost.shell('config interface buffer priority-group lossless remove {}'.format(port_to_test), module_ignore_errors = True)
        duthost.shell('config interface buffer priority-group lossless add {} 3-4'.format(port_to_test), module_ignore_errors = True)
        duthost.shell('config buffer profile remove headroom-override', module_ignore_errors = True)
        ensure_pool_size(duthost, 60, original_pool_size, original_shp_size, None)

def check_buffer_profiles_for_shp(duthost, shp_enabled=True):
    def _check_buffer_profiles_for_shp(duthost, shp_enabled):
        buffer_profiles = duthost.shell('redis-cli keys "BUFFER_PROFILE_TABLE:*"')['stdout'].split('\n')
        for profile_name in buffer_profiles:
            m = re.search(LOSSLESS_PROFILE_PATTERN, profile_name)
            if m:
                profile_obj = _compose_dict_from_cli(duthost.shell('redis-cli hgetall {}'.format(profile_name))['stdout'].split('\n'))
                if shp_enabled:
                    if not profile_obj['xon'] == profile_obj['size']:
                        return False
                else:
                    if int(profile_obj['size']) < int(profile_obj['xon']) + int(profile_obj['xoff']):
                        return False
        # Return True only if all lossless profiles pass the check
        return True

    pytest_assert(wait_until(20, 2, _check_buffer_profiles_for_shp, duthost, shp_enabled))


def test_shared_headroom_pool_configure(duthosts, rand_one_dut_hostname, conn_graph_facts, port_to_test):
    """Test case for shared headroom pool configuration

    Test case to verify the variant commands of shared headroom pool configuration and how they affect the other buffer configurations

    The flow of the test case:
        1. If the over subscribe ratio isn't 2, configure it to 2
           If the size of shared headroom pool is configured: remove it
        2. Get shared headroom pool size, check it against the ASIC DB
           Check the buffer profiles,
            - For Mellanox platform, for all the buffer profiles, size should be equal to xon
        3. Testcase: over subscribe ratio updated
            - Config over subscribe ratio to 4, check whether the shared headroom pool size is divided by 2
        4. Testcase: configure size
            - Config shared headroom pool size to a certain number which is predefined on a per-vendor basis,
              Check whether the shared headroom pool size is equal to the configured number
        5. Testcase: remove the over subscribe ratio configuration while size is configured
            - Check the buffer profiles and shared headroom pool size
        6. Testcase: remove the shared headroom pool size with over subscribe ratio configured
            - Config over subscribe ratio to 2, check whether the shared headroom pool size matches the previous value
            - Remove the size configuration, check whether shared headroom pool is still enabled
        7. Testcase: remove both over subscribe ratio and shared headroom pool size
        8. Restore configuration
    """
    duthost = duthosts[rand_one_dut_hostname]

    pool_size_before_shp = duthost.shell('redis-cli hget BUFFER_POOL_TABLE:ingress_lossless_pool size')['stdout']
    shp_size_before_shp = duthost.shell('redis-cli hget BUFFER_POOL_TABLE:ingress_lossless_pool xoff')['stdout']

    original_over_subscribe_ratio = duthost.shell('redis-cli -n 4 hget "DEFAULT_LOSSLESS_BUFFER_PARAMETER|AZURE" over_subscribe_ratio')['stdout']
    original_configured_shp_size = duthost.shell('redis-cli -n 4 hget "BUFFER_POOL|ingress_lossless_pool" xoff')['stdout']
    original_speed = duthost.shell('redis-cli -n 4 hget "PORT|{}" speed'.format(port_to_test))['stdout']
    original_cable_len = duthost.shell('redis-cli -n 4 hget "CABLE_LENGTH|AZURE" {}'.format(port_to_test))['stdout']

    if not TESTPARAM_SHARED_HEADROOM_POOL:
        pytest.skip('Shared headroom pool test skipped due to no parameters defined')
    shp_size_to_test = TESTPARAM_SHARED_HEADROOM_POOL.get("size")
    if not shp_size_to_test:
        pytest.skip('Shared headroom pool test skipped due to size not defined')

    try:
        # First, we need to fetch the SAI OID of ingress lossless pool.
        # The only way to achieve that is to trigger a new buffer profile creation and then fetch the SAI OID from it
        initial_asic_db_profiles = fetch_initial_asic_db(duthost)
        duthost.shell('config interface cable-length {} 10m'.format(port_to_test))
        expected_profile = make_expected_profile_name(original_speed, '10m')
        time.sleep(20)
        profile_oid, pool_oid = check_buffer_profile_details(duthost, initial_asic_db_profiles, expected_profile, None, None)
        logging.info('Got SAI OID of ingress lossless pool: {}'.format(pool_oid))
        # Restore the cable length
        duthost.shell('config interface cable-length {} {}'.format(port_to_test, original_cable_len))
        time.sleep(20)

        if original_over_subscribe_ratio != '2':
            duthost.shell('config buffer shared-headroom-pool over-subscribe-ratio 2')
        if original_configured_shp_size and original_configured_shp_size != '0':
            duthost.shell('config buffer shared-headroom-pool size 0')

        # Make sure the shared headroom pool configuration has been deployed
        time.sleep(30)

        # Check whether the buffer profile for lossless PGs are correct
        check_buffer_profiles_for_shp(duthost)

        # Fetch initial buffer pool size and shared headroom pool size
        original_pool_size = duthost.shell('redis-cli hget BUFFER_POOL_TABLE:ingress_lossless_pool size')['stdout']
        original_shp_size = duthost.shell('redis-cli hget BUFFER_POOL_TABLE:ingress_lossless_pool xoff')['stdout']

        logging.info('[Test: check shared headroom pool size consistency between APPL_DB and ASIC_DB]')
        check_pool_size(duthost,
                        pool_oid,
                        pool_size = original_pool_size,
                        shp_size = original_shp_size,
                        old_pg_number = 0,
                        new_pg_number = 0)

        logging.info('[Test: update over-subscribe-ratio to 4 and check sizes of buffer pool and shared headroom pool]')
        duthost.shell('config buffer shared-headroom-pool over-subscribe-ratio 4')
        check_pool_size(duthost,
                        pool_oid,
                        pool_size = original_pool_size,
                        shp_size = original_shp_size,
                        old_ratio = '2',
                        new_ratio = '4',
                        old_pg_number = 0,
                        new_pg_number = 0)

        logging.info('[Test: configure shared headroom pool size and check APPL_DB and ASIC_DB]')
        duthost.shell('config buffer shared-headroom-pool size {}'.format(shp_size_to_test))
        check_pool_size(duthost,
                        pool_oid,
                        config_shp_size = shp_size_to_test)
        check_buffer_profiles_for_shp(duthost)

        logging.info('[Test: remove the over subscribe ratio configuration while size is configured]')
        duthost.shell('config buffer shared-headroom-pool over-subscribe-ratio 0')
        check_pool_size(duthost,
                        pool_oid,
                        config_shp_size = shp_size_to_test)
        check_buffer_profiles_for_shp(duthost)

        logging.info('[Test: remove the size configuration while over subscribe ratio is configured]')
        duthost.shell('config buffer shared-headroom-pool over-subscribe-ratio 1')
        duthost.shell('config buffer shared-headroom-pool size 0')
        check_pool_size(duthost,
                        pool_oid,
                        pool_size = original_pool_size,
                        shp_size = original_shp_size,
                        old_ratio = '2',
                        new_ratio = '1',
                        old_pg_number = 0,
                        new_pg_number = 0)
        check_buffer_profiles_for_shp(duthost)

        logging.info('[Test: remove over subscribe ratio]')
        duthost.shell('config buffer shared-headroom-pool over-subscribe-ratio 0')
        check_pool_size(duthost,
                        pool_oid,
                        pool_size = original_pool_size,
                        shp_size = original_shp_size,
                        old_ratio = '2',
                        new_ratio = '0',
                        conn_graph_facts = conn_graph_facts,
                        old_pg_number = 0,
                        new_pg_number = 0)

        logging.info('[Test: remove over subscribe ratio and then the size]')
        # Configure over subscribe ratio and shared headroom pool size
        duthost.shell('config buffer shared-headroom-pool over-subscribe-ratio 2')
        duthost.shell('config buffer shared-headroom-pool size {}'.format(shp_size_to_test))
        check_pool_size(duthost,
                        pool_oid,
                        config_shp_size = shp_size_to_test)
        # Remove the over subscribe ratio and then the size
        duthost.shell('config buffer shared-headroom-pool over-subscribe-ratio 0')
        duthost.shell('config buffer shared-headroom-pool size 0')
        check_buffer_profiles_for_shp(duthost, shp_enabled = False)
    finally:
        duthost.shell('config buffer shared-headroom-pool over-subscribe-ratio {}'.format(original_over_subscribe_ratio), module_ignore_errors = True)
        duthost.shell('config buffer shared-headroom-pool size {}'.format(original_configured_shp_size), module_ignore_errors = True)
        duthost.shell('config interface cable-length {} {}'.format(port_to_test, original_cable_len), module_ignore_errors = True)
        ensure_pool_size(duthost, 60, pool_size_before_shp, shp_size_before_shp, None)


def test_lossless_pg(duthosts, rand_one_dut_hostname, conn_graph_facts, port_to_test, pg_to_test):
    """Test case for non default dynamic th

    Test case to verify the static profile with non default dynamic th
    The buffer profile will be generated automatically after the profile has been applied to the port
    The arguments required for the test are fetched from a predefined json file on a per vendor basis.
    Not providing any of the arguments results in the test case skipped.

    The flow of the test case:
        1. Configure a headroom override profile and check it in the APPL_DB, STATE_DB and ASIC_DB
        2. Configure a non default dynamic th profile
        3. Apply the nondefault dynamic th profile to PG 3-4 and update cable length
        4. Check whether a new buffer profile is created accordingly in the APPL_DB, STATE_DB and ASIC_DB
        5. Update the PG 3-4 to the default mode: dynamic profile
           Verify whether the profile created in step 4 is removed
        6. Reconfigure it as non default dynamic th profile and check related info
        7. Update it to a headroom override profile and check related info
        8. Restore the configuration

    Args:
        port_to_test: On which port will the test be performed
        pg_to_test: To what PG will the profiles be applied
    """
    duthost = duthosts[rand_one_dut_hostname]
    original_speed = duthost.shell('redis-cli -n 4 hget "PORT|{}" speed'.format(port_to_test))['stdout']
    original_cable_len = duthost.shell('redis-cli -n 4 hget "CABLE_LENGTH|AZURE" {}'.format(port_to_test))['stdout']
    original_pool_size = duthost.shell('redis-cli hget BUFFER_POOL_TABLE:ingress_lossless_pool size')['stdout']
    original_shp_size = duthost.shell('redis-cli hget BUFFER_POOL_TABLE:ingress_lossless_pool xoff')['stdout']

    initial_asic_db_profiles = fetch_initial_asic_db(duthost)

    set_command = 'config interface buffer priority-group lossless set {} {} '.format(port_to_test, pg_to_test)
    add_command = 'config interface buffer priority-group lossless add {} {} '.format(port_to_test, pg_to_test)
    if pg_to_test == '3-4':
        first_command = set_command
    else:
        first_command = add_command

    buffer_pg = 'BUFFER_PG_TABLE:{}:{}'.format(port_to_test, pg_to_test)

    try:
        param = TESTPARAM_LOSSLESS_PG.get("headroom-override")
        if not param:
            pytest.skip('Lossless pg test skipped due to no parameters for "headroom-override" command provided')
        else:
            cli_str, new_size, new_xoff = _parse_buffer_profile_params(param, "add", "headroom-override")

        # Create profiles
        logging.info('[Preparing]: Create static buffer profile for headroom override')
        duthost.shell(cli_str)
        headroom_override_profile_oid, pool_oid = check_buffer_profile_details(duthost, initial_asic_db_profiles, "headroom-override", None, None)

        initial_asic_db_profiles = fetch_initial_asic_db(duthost)

        # This is a dynamic profile with non default dynamic-th.
        # Profile won't be created until configured on some pg
        param = TESTPARAM_LOSSLESS_PG.get("non-default-dynamic_th")
        if not param:
            pytest.skip('Lossless pg test skipped due to no parameters for "non-default-dynamic_th" command provided')
        else:
            cli_str, new_size, new_xoff = _parse_buffer_profile_params(param, "add", "non-default-dynamic_th")

        logging.info('[Preparing]: Create static buffer profile for non default dynamic_th')
        duthost.shell(cli_str)

        # Update cable length to 15m
        logging.info('[Preparing]: Update cable length')
        duthost.shell('config interface cable-length {} 15m'.format(port_to_test))
        expected_profile = make_expected_profile_name(original_speed, '15m')
        check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), expected_profile)
        profile_oid, _ = check_buffer_profile_details(duthost, initial_asic_db_profiles, expected_profile, None, pool_oid)

        # Originally, it should be a dynamic PG, update it to override
        logging.info('[Testcase: dynamic headroom => headroom override]')
        duthost.shell(first_command + 'headroom-override')
        # Check whether lossless dynamic profile is removed
        check_pg_profile(duthost, buffer_pg, 'headroom-override')
        if pg_to_test == '3-4':
            check_lossless_profile_removed(duthost, expected_profile, profile_oid)
        else:
            initial_asic_db_profiles = fetch_initial_asic_db(duthost)

        # Update it to non-default dynamic_th
        logging.info('[Testcase: headroom override => dynamically calculated headroom with non-default dynamic_th]')
        duthost.shell(set_command + 'non-default-dynamic_th')
        expected_nondef_profile = make_expected_profile_name(original_speed, '15m', ['th2'])
        check_pg_profile(duthost, buffer_pg, expected_nondef_profile)
        # A new profile should be created in ASIC DB
        profile_oid, _ = check_buffer_profile_details(duthost, initial_asic_db_profiles, expected_nondef_profile, None, pool_oid)

        # Update it to dynamic PG
        logging.info('[Testcase: dynamically calculated headroom with non-default dynamic_th => dynamic headroom]')
        duthost.shell(set_command)
        check_pg_profile(duthost, buffer_pg, expected_profile)
        check_lossless_profile_removed(duthost, expected_nondef_profile, profile_oid)

        # Update it to non-default dynamic_th
        logging.info('[Testcase: dynamic headroom => dynamically calculated headroom with non-default dynamic_th]')
        duthost.shell(set_command + 'non-default-dynamic_th')
        check_pg_profile(duthost, buffer_pg, expected_nondef_profile)
        # A new profile should be created in ASIC DB
        profile_oid, _ = check_buffer_profile_details(duthost, initial_asic_db_profiles, expected_nondef_profile, None, pool_oid)
        if pg_to_test == '3-4':
            # The oid can be reused by SAI. So we don't check whether profile_oid is removed.
            check_lossless_profile_removed(duthost, expected_profile)

        # Update it to headroom override
        logging.info('[Testcase: dynamically calculated headroom with non-default dynamic_th => headroom override]')
        duthost.shell(set_command + 'headroom-override')
        check_pg_profile(duthost, buffer_pg, 'headroom-override')
        check_lossless_profile_removed(duthost, expected_nondef_profile, profile_oid)

        # Update it to dynamic PG, restore the configuration
        logging.info('[Testcase: headroom override => dynamic headroom]')
        duthost.shell(set_command)
        check_pg_profile(duthost, buffer_pg, expected_profile)

        # Remove all static profiles
        logging.info('[Restoring configuration]')
        duthost.shell('config buffer profile remove headroom-override')
        duthost.shell('config buffer profile remove non-default-dynamic_th')
        check_lossless_profile_removed(duthost, 'headroom-override', headroom_override_profile_oid)
        # No need to check non-default-dynamic_th because it won't propagated to APPL_DB

        # Restore the cable length
        duthost.shell(set_command)

        duthost.shell('config interface cable-length {} {}'.format(port_to_test, original_cable_len))
        old_profile = expected_profile
        expected_profile = make_expected_profile_name(original_speed, original_cable_len)
        check_pg_profile(duthost, buffer_pg, expected_profile)
        check_lossless_profile_removed(duthost, old_profile, profile_oid)
    finally:
        if pg_to_test == '3-4':
            duthost.shell(set_command, module_ignore_errors = True)
        else:
            duthost.shell('config interface buffer priority-group lossless remove {} {} '.format(port_to_test, pg_to_test), module_ignore_errors = True)
        duthost.shell('config interface cable-length {} {}'.format(port_to_test, original_cable_len), module_ignore_errors = True)
        duthost.shell('config buffer profile remove headroom-override', module_ignore_errors = True)
        duthost.shell('config buffer profile remove non-default-dynamic_th', module_ignore_errors = True)
        ensure_pool_size(duthost, 60, original_pool_size, original_shp_size, None)

def test_port_admin_down(duthosts, rand_one_dut_hostname, conn_graph_facts, port_to_test):
    """The test case for admin down ports

    For administratively down ports, all PGs should be removed from the ASIC

    Args:
        port_to_test: Port to run the test

    The flow of the test case:
        1. Shut down the port
        2. Check:
           - whether all the PGs on the port has been removed
           - whether the lossless profile is removed if it's referenced by the port_to_test only
        3. Perform the following operations
           - add/remove a general dynamic PG (profile = NULL)
           - add/remove a headroom override PG
           - add/remove a dynamic PG with non default dynamic th
           - change the cable length
        4. Check whether the PGs are correctly applied after port being started up
    """
    param = TESTPARAM_HEADROOM_OVERRIDE.get("add")
    if not param:
        pytest.skip('Shutdown port test skipped due to no headroom override parameters defined')

    duthost = duthosts[rand_one_dut_hostname]
    original_speed = duthost.shell('redis-cli -n 4 hget "PORT|{}" speed'.format(port_to_test))['stdout']
    original_cable_len = duthost.shell('redis-cli -n 4 hget "CABLE_LENGTH|AZURE" {}'.format(port_to_test))['stdout']
    if check_qos_db_fv_reference_with_table(duthost) == True:
        original_profile = duthost.shell('redis-cli hget "BUFFER_PG_TABLE:{}:3-4" profile'.format(port_to_test))['stdout'][1:-1]
    else:
        original_profile = duthost.shell('redis-cli hget "BUFFER_PG_TABLE:{}:3-4" profile'.format(port_to_test))['stdout']
        original_profile = "BUFFER_PROFILE_TABLE:" + original_profile
    original_pg_size = duthost.shell('redis-cli hget "{}" size'.format(original_profile))['stdout']
    original_pool_size = duthost.shell('redis-cli hget BUFFER_POOL_TABLE:ingress_lossless_pool size')['stdout']

    new_cable_len = '15m'

    lossy_pg_size = TESTPARAM_LOSSY_PG.get(original_speed)
    if not lossy_pg_size:
        lossy_pg_size = TESTPARAM_LOSSY_PG.get('default')
        if not lossy_pg_size:
            pytest.skip('Shutdown port test skipped due to no lossy pg size defined')

    if DEFAULT_OVER_SUBSCRIBE_RATIO:
        original_pg_xoff = int(duthost.shell('redis-cli hget "{}" xoff'.format(original_profile))['stdout'])
        original_shp_size = int(duthost.shell('redis-cli hget BUFFER_POOL_TABLE:ingress_lossless_pool xoff')['stdout'])
    else:
        original_pg_xoff = None
        original_shp_size = None

    initial_asic_db_profiles = fetch_initial_asic_db(duthost)

    # Create a non default dynamic-th profile
    non_default_dynamic_th_profile = 'test-profile-non-default-dynamic_th'
    dynamic_th_value = '2'
    duthost.shell('config buffer profile add {} --dynamic_th {}'.format(non_default_dynamic_th_profile, dynamic_th_value))

    # Create a headroom override profile
    headroom_override_profile = 'test-profile-headroom-override'
    duthost.shell('config buffer profile add {} --xon {} --xoff {}'.format(headroom_override_profile, param['xon'], param['xoff']))

    _, pool_oid = check_buffer_profile_details(duthost, initial_asic_db_profiles, headroom_override_profile, None, None)

    """
        Each item is a tuple consisting of:
         - Hint message to user
         - Command to be executed
         - The expected profile after the command is executed and the port is administratively up
         - Whether we need to check whether the previous expected_profile has been removed after port is administratively down
    """
    scenarios = [
        ('Remove the generic PG when port is administratively down',
         'config interface buffer priority-group lossless remove {} 3-4'.format(port_to_test),
         None,
         False),
        ('Add a PG with non default dynamic_th when port is administratively down',
         'config interface buffer priority-group lossless add {} 3-4 {}'.format(port_to_test, non_default_dynamic_th_profile),
         make_expected_profile_name(original_speed, original_cable_len, ['th{}'.format(dynamic_th_value)]),
         False),
        ('Remove the PG with non default dynamic_th when port is administratively down',
         'config interface buffer priority-group lossless remove {} 3-4'.format(port_to_test),
         None,
         True),
        ('Add a PG with headroom override profile when port is administratively down',
         'config interface buffer priority-group lossless add {} 3-4 {}'.format(port_to_test, headroom_override_profile),
         headroom_override_profile,
         False),
        ('Remove the PG with headroom override when port is administratively down',
         'config interface buffer priority-group lossless remove {} 3-4'.format(port_to_test),
         None,
         False),
        ('Readd the generic PG when port is administratively down',
         'config interface buffer priority-group lossless add {} 3-4'.format(port_to_test),
         make_expected_profile_name(original_speed, original_cable_len),
         False),
        ('Change the cable length when port is administratively down',
         'config interface cable-length {} {}'.format(port_to_test, new_cable_len),
         make_expected_profile_name(original_speed, new_cable_len),
         False),
        ('Restore the cable length when port is administratively down',
         'config interface cable-length {} {}'.format(port_to_test, original_cable_len),
         make_expected_profile_name(original_speed, original_cable_len),
         True)
    ]

    expected_profile_in_appldb = None
    try:
        for scenario in scenarios:
            # Shutdown port
            logging.info('Shut down port {}'.format(port_to_test))
            duthost.shell('config interface shutdown {}'.format(port_to_test))
            # Make sure there isn't any PG on the port
            logging.info('Check whether all PGs are removed from port {}'.format(port_to_test))
            time.sleep(10)
            pgs_in_appl_db = duthost.shell('redis-cli keys "BUFFER_PG_TABLE:{}:*"'.format(port_to_test))['stdout']
            pytest_assert(not pgs_in_appl_db, "There shouldn't be any PGs on an administratively down port but we got {}".format(pgs_in_appl_db))

            # Check the pool size after the port is admin down
            check_pool_size(duthost,
                            pool_oid,
                            pool_size = original_pool_size,
                            shp_size = original_shp_size,
                            old_xoff = original_pg_xoff,
                            old_size = original_pg_size,
                            new_pg_number = 0,
                            adjust_lossy_pg_size = lossy_pg_size)

            previous_profile = expected_profile_in_appldb
            hint, command, expected_profile_in_appldb, need_remove_previous_profile = scenario

            # Check whether the profile that is expected to be removed is removed
            if need_remove_previous_profile:
                logging.info('Check whether profile {} has been removed after port being administratively down'.format(previous_profile))
                check_lossless_profile_removed(duthost, previous_profile)
            logging.info(hint)
            duthost.shell(command)

            logging.info('Start up port {}'.format(port_to_test))
            duthost.shell('config interface startup {}'.format(port_to_test))
            if expected_profile_in_appldb:
                logging.info('Check whether profile in PG is as expected({})'.format(expected_profile_in_appldb))
                check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), expected_profile_in_appldb)
            else:
                logging.info('Check whether profile in PG has been removed')
                time.sleep(10)
                pgs_in_appl_db = duthost.shell('redis-cli keys "BUFFER_PG_TABLE:{}:3-4"'.format(port_to_test))['stdout']
                pytest_assert(not pgs_in_appl_db, "There shouldn't be PGs 3-4 but we got {}".format(pgs_in_appl_db))

        # Check the pool size at the end of test.
        # We don't check the pool size each time the port is admin down because
        # 1. It's difficult to pass parameters for all of the scenarios
        # 2. We have done this kind of test for many times in other testcases
        check_pool_size(duthost,
                        pool_oid,
                        pool_size = original_pool_size,
                        shp_size = original_shp_size,
                        old_xoff = original_pg_xoff,
                        old_size = original_pg_size,
                        new_pg_number = 2)

    finally:
        duthost.shell('config interface cable-length {} {}'.format(port_to_test, original_cable_len), module_ignore_errors=True)
        duthost.shell('config interface startup {}'.format(port_to_test), module_ignore_errors=True)
        duthost.shell('config interface buffer priority-group lossless set {} 3-4'.format(port_to_test), module_ignore_errors=True)
        duthost.shell('config interface buffer priority-group lossless add {} 3-4'.format(port_to_test), module_ignore_errors=True)
        duthost.shell('config buffer profile remove {}'.format(non_default_dynamic_th_profile), module_ignore_errors=True)
        duthost.shell('config buffer profile remove {}'.format(headroom_override_profile), module_ignore_errors=True)
        ensure_pool_size(duthost, 60, original_pool_size, original_shp_size, None)


def test_port_auto_neg(duthosts, rand_one_dut_hostname, conn_graph_facts, port_to_test):
    """The test case for auto negotiation enabled ports

    For those ports, the speed which is taken into account for buffer calculating is no longer the configure speed but
        - The maximum supported speed if advertised-speeds is not configured
        - The maximum advertised speed otherwise

    Args:
        port_to_test: Port to run the test

    The flow of the test case:
        1. Fetch the supported_speeds from STATE_DB. It's exposed by port auto negotiation feature when system starts.
           Skip the test if it is not exposed.
        2. Preparing:
           - Configure the speed to the minimum supported one and the cable length to 15m
           - This is to enforce there is a new buffer profile created
        3. Enable the port auto negotiation and then configure the advertised speed list and then disable it
           - The maximum supported speed should be taken into account for buffer calculation after port auto negotiation enabled
           - The maximum advertised speed should be taken after it is configured
           - The configured speed should be taken after the port auto negotiation is disabled
        4. Enable the port auto negotiation with the advertised speed list configured
           - The maximum advertised speed should be taken after it is configured
        5. Add a new PG.
           - The maximum advertised speed should be taken in this case
        6. Configure advertised speed as all
           - The maximum supported speed should be taken into account for buffer calculation

    Note:
        The buffer pool size is not verified in this test because:
        - Only the logic to generate effective speed is updated in port auto-negotiation,
          which will affect only the buffer priority-groups and profiles on the port, which is verified in the test.
        - The buffer pool size depends on the buffer priority-groups and profiles but not directly on the effective speed.
          As buffer pool size has been verified in other test cases and checking it will consume more time, we don't repeat it here.
    """
    def _get_max_speed_from_list(speed_list_str):
        speed_list = natsorted(speed_list_str.split(','))
        return speed_list[-1]

    duthost = duthosts[rand_one_dut_hostname]
    supported_speeds = duthost.shell('redis-cli -n 6 hget "PORT_TABLE|{}" supported_speeds'.format(port_to_test))['stdout']
    if not supported_speeds:
        pytest.skip('No supported_speeds found for port {}, skip the test'.format(port_to_test))['stdout']
    original_speed = duthost.shell('redis-cli -n 4 hget "PORT|{}" speed'.format(port_to_test))['stdout']
    original_cable_length = duthost.shell('redis-cli -n 4 hget "CABLE_LENGTH|AZURE" {}'.format(port_to_test))['stdout']
    original_pool_size = duthost.shell('redis-cli hget BUFFER_POOL_TABLE:ingress_lossless_pool size')['stdout']
    if DEFAULT_OVER_SUBSCRIBE_RATIO:
        original_shp_size = int(duthost.shell('redis-cli hget BUFFER_POOL_TABLE:ingress_lossless_pool xoff')['stdout'])
    else:
        original_shp_size = None

    max_supported_speed = _get_max_speed_from_list(supported_speeds)
    supported_speeds_list = natsorted(supported_speeds.split(','))
    speed_before_test = supported_speeds_list[0]
    cable_length_to_test = '15m'
    advertised_speeds_to_test = ','.join(supported_speeds_list[:-1])
    max_advertised_speed = _get_max_speed_from_list(advertised_speeds_to_test)

    initial_asic_db_profiles = fetch_initial_asic_db(duthost)
    expected_profile = make_expected_profile_name(speed_before_test, cable_length_to_test)
    try:
        # Preparing: configure the speed to one which is not the maximum speed and the cable length to 15m
        # This is to enforce there is a new buffer profile created
        duthost.shell('config interface speed {} {}'.format(port_to_test, speed_before_test))
        duthost.shell('config interface cable-length {} {}'.format(port_to_test, cable_length_to_test))
        check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), expected_profile)
        new_profile_id, pool_id = check_buffer_profile_details(duthost, initial_asic_db_profiles, expected_profile, None, None)

        # As comments at the beginning of the method, we don't check buffer pool size in this test case.
        # The same for all the following steps.

        # Enable port auto negotiation first and then configure the advertised speed list
        logging.info('Enable port auto negotiation')
        duthost.shell('config interface autoneg {} enabled'.format(port_to_test))
        # Check whether the maximum supported speed is used for creating lossless profile
        expected_profile = make_expected_profile_name(max_supported_speed, cable_length_to_test)
        check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), expected_profile)
        check_buffer_profile_details(duthost, initial_asic_db_profiles, expected_profile, new_profile_id, pool_id)

        # Configure advertised speeds
        logging.info('Update advertised speeds to {}'.format(advertised_speeds_to_test))
        duthost.shell('config interface advertised-speeds {} {}'.format(port_to_test, advertised_speeds_to_test))
        # Check whether the maximum advertised speed is used for creating lossless profile
        expected_profile = make_expected_profile_name(max_advertised_speed, cable_length_to_test)
        check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), expected_profile)
        check_buffer_profile_details(duthost, initial_asic_db_profiles, expected_profile, new_profile_id, pool_id)

        # Disable port auto negotiation
        logging.info('Disable port auto negotiation')
        duthost.shell('config interface autoneg {} disabled'.format(port_to_test))
        expected_profile = make_expected_profile_name(speed_before_test, cable_length_to_test)
        check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), expected_profile)
        check_buffer_profile_details(duthost, initial_asic_db_profiles, expected_profile, new_profile_id, pool_id)

        # Enable port auto negotiation with advertised speed configured
        logging.info('Reenable port auto negotiation with advertised speeds configured')
        duthost.shell('config interface autoneg {} enabled'.format(port_to_test))
        # Check whether the maximum advertised speed is used for creating lossless profile
        expected_profile = make_expected_profile_name(max_advertised_speed, cable_length_to_test)
        check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), expected_profile)
        check_buffer_profile_details(duthost, initial_asic_db_profiles, expected_profile, new_profile_id, pool_id)

        # Add new PGs. The maximum advertised speed should be used
        logging.info('Add new PG 6')
        duthost.shell('config interface buffer priority-group lossless add {} 6'.format(port_to_test))
        check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:6'.format(port_to_test), expected_profile)

        # Update the advertised speed to all
        logging.info('Update advertised speeds to all')
        duthost.shell('config interface advertised-speeds {} all'.format(port_to_test))
        expected_profile = make_expected_profile_name(max_supported_speed, cable_length_to_test)
        check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), expected_profile)
        check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:6'.format(port_to_test), expected_profile)
        check_buffer_profile_details(duthost, initial_asic_db_profiles, expected_profile, new_profile_id, pool_id)
    finally:
        # Clean up
        duthost.shell('config interface buffer priority-group lossless remove {} 6'.format(port_to_test), module_ignore_errors=True)
        duthost.shell('config interface cable-length {} {}'.format(port_to_test, original_cable_length), module_ignore_errors=True)
        duthost.shell('config interface speed {} {}'.format(port_to_test, original_speed), module_ignore_errors=True)
        duthost.shell('config interface advertised-speeds {} all'.format(port_to_test), module_ignore_errors=True)
        duthost.shell('config interface autoneg {} disabled'.format(port_to_test), module_ignore_errors=True)
        ensure_pool_size(duthost, 60, original_pool_size, original_shp_size, None)


@pytest.mark.disable_loganalyzer
def test_exceeding_headroom(duthosts, rand_one_dut_hostname, conn_graph_facts, port_to_test):
    """The test case for maximum headroom

    If the accumulative headroom of a port exceeds the maximum value,
    the new configuation causing the violation should not be applied to prevent orchagent from exiting

    Args:
        port_to_test: Port to run the test

    The flow of the test case:
        1. Find the longest possible cable length the port can support.
           It will also verify whether a super long cable will be applied
           The test will be skipped if such limit isn't found after the cable length has been increased to 2km.
        2. Add extra PGs to a port, which causes the accumulative headroom exceed the limit
        3. Configure a headroom-override on a port and then enlarge the size of the profile.
           Verify whether the large size is applied.
        4. Configure a long cable length with shared headroom pool enabled.
           Verify the size in the profile is updated when shared headroom pool is disabled.

        In each step, it also checks whether the expected error message is found.
    """
    duthost = duthosts[rand_one_dut_hostname]
    max_headroom_size = duthost.shell('redis-cli -n 6 hget "BUFFER_MAX_PARAM_TABLE|{}" max_headroom_size'.format(port_to_test))['stdout']
    if not max_headroom_size:
        pytest.skip('No max headroom found on port {}, skip'.format(port_to_test))

    original_cable_len = duthost.shell('redis-cli -n 4 hget "CABLE_LENGTH|AZURE" {}'.format(port_to_test))['stdout']
    original_speed = duthost.shell('redis-cli -n 4 hget "PORT|{}" speed'.format(port_to_test))['stdout']
    original_over_subscribe_ratio = duthost.shell('redis-cli -n 4 hget "DEFAULT_LOSSLESS_BUFFER_PARAMETER|AZURE" over_subscribe_ratio')['stdout']
    original_configured_shp_size = duthost.shell('redis-cli -n 4 hget "BUFFER_POOL|ingress_lossless_pool" xoff')['stdout']
    original_pool_size = duthost.shell('redis-cli hget BUFFER_POOL_TABLE:ingress_lossless_pool size')['stdout']
    original_shp_size = duthost.shell('redis-cli hget BUFFER_POOL_TABLE:ingress_lossless_pool xoff')['stdout']

    try:
        # Test case runs with shared headroom pool disabled
        # because the headroom size is very small with shared headroom pool enabled
        if original_over_subscribe_ratio and original_over_subscribe_ratio != '0':
            duthost.shell('config buffer shared-headroom-pool over-subscribe-ratio 0')
        if original_configured_shp_size and original_configured_shp_size != '0':
            duthost.shell('config buffer shared-headroom-pool size 0')

        # 1. Find the longest possible cable length the port can support.
        loganalyzer, marker = init_log_analyzer(duthost,
                                                'Fetch the longest possible cable length',
                                                ['Update speed .* and cable length .* for port .* failed, accumulative headroom size exceeds the limit',
                                                 'Unable to update profile for port .*. Accumulative headroom size exceeds limit'],
                                                ['Failed to process table update',
                                                 'oid is set to null object id on SAI_OBJECT_TYPE_BUFFER_PROFILE',
                                                 'Failed to remove buffer profile .* with type BUFFER_PROFILE_TABLE',
                                                 'doTask: Failed to process buffer task, drop it'])
        logging.info('[Find out the longest cable length the port can support]')
        cable_length = 300
        while True:
            duthost.shell('config interface cable-length {} {}m'.format(port_to_test, cable_length))
            expected_profile = make_expected_profile_name(original_speed, '{}m'.format(cable_length))
            profile_applied = check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), expected_profile, False)
            if not profile_applied:
                break
            logging.debug('Cable length {} has been applied successfully'.format(cable_length))
            cable_length += 100
            if cable_length > 2000:
                pytest.skip("Not able to find the maximum headroom of port {} after cable length has been increased to 2km, skip the test".format(port_to_test))

        # We've got the maximum cable length that can be applied on the port
        violating_cable_length = cable_length
        maximum_cable_length = cable_length - 100
        logging.info('Got maximum cable length {}'.format(maximum_cable_length))

        # Check whether there is the expected error message in the log
        logging.info('Check whether the expected error message is found')
        check_log_analyzer(loganalyzer, marker)

        loganalyzer, marker = init_log_analyzer(duthost,
                                                'Add addtional PGs',
                                                ['Update speed .* and cable length .* for port .* failed, accumulative headroom size exceeds the limit',
                                                 'Unable to update profile for port .*. Accumulative headroom size exceeds limit'])

        maximum_profile_name = make_expected_profile_name(original_speed, '{}m'.format(maximum_cable_length))
        maximum_profile = _compose_dict_from_cli(duthost.shell('redis-cli hgetall BUFFER_PROFILE_TABLE:{}'.format(maximum_profile_name))['stdout'].split())

        # Config the cable length to the longest acceptable value and check the profile
        logging.info('[Config the cable length to the longest acceptable value on the port]')
        duthost.shell('config interface cable-length {} {}m'.format(port_to_test, maximum_cable_length))
        check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), maximum_profile_name)

        # 2. Add extra PGs to a port, which causes the accumulative headroom exceed the limit
        logging.info('Add another PG and make sure the system isn\'t broken')
        duthost.shell('config interface buffer priority-group lossless add {} {}'.format(port_to_test, '5-7'))
        profile_applied = check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:5-7'.format(port_to_test), maximum_profile_name, False)
        pytest_assert(not profile_applied, "Profile {} applied on {}:5-7, which makes the accumulative headroom exceed the limit".format(maximum_profile_name, port_to_test))

        # Check whether there is the expected error message in the log
        check_log_analyzer(loganalyzer, marker)

        # Restore the configuration
        duthost.shell('config interface buffer priority-group lossless remove {} {}'.format(port_to_test, '5-7'))
        duthost.shell('config interface cable-length {} {}'.format(port_to_test, original_cable_len))

        # 3. Configure a headroom-override on a port and then enlarge the size of the profile.
        loganalyzer, marker = init_log_analyzer(duthost,
                                                'Static profile',
                                                ['Update speed .* and cable length .* for port .* failed, accumulative headroom size exceeds the limit',
                                                 'Unable to update profile for port .*. Accumulative headroom size exceeds limit'])

        logging.info('[Config headroom override to PG 3-4]')
        duthost.shell('config buffer profile add test-headroom --xon {} --xoff {} --size {}'.format(
            maximum_profile['xon'], maximum_profile['xoff'], maximum_profile['size']))
        duthost.shell('config interface buffer priority-group lossless set {} {} {}'.format(port_to_test, '3-4', 'test-headroom'))

        logging.info('Verify the profile is applied')
        check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), 'test-headroom')

        # Apply the profile on other PGs, which make the accumulative headroom exceed the limit
        duthost.shell('config interface buffer priority-group lossless add {} {} {}'.format(port_to_test, '5-7', 'test-headroom'))
        # Make sure the profile hasn't been applied
        profile_applied = check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:5-7'.format(port_to_test), 'test-headroom', False)
        pytest_assert(not profile_applied, "Profile {} applied on {}:5-7, which makes the accumulative headroom exceed the limit".format(maximum_profile_name, port_to_test))

        # Check log
        check_log_analyzer(loganalyzer, marker)

        # Restore configuration
        duthost.shell('config interface buffer priority-group lossless remove {} {}'.format(port_to_test, '5-7'))

        # Update static profile to a larger size, which makes it exceeds the port headroom limit
        # Setup the log analyzer
        loganalyzer, marker = init_log_analyzer(duthost,
                                                'Configure a larger size to a static profile',
                                                ['BUFFER_PROFILE .* cannot be updated because .* referencing it violates the resource limitation',
                                                 'Unable to update profile for port .*. Accumulative headroom size exceeds limit'])

        logging.info('[Update headroom override to a larger size]')
        duthost.shell('config buffer profile set test-headroom --size {}'.format(int(maximum_profile['size']) * 2))

        # This should make it exceed the limit, so the profile should not applied to the APPL_DB
        time.sleep(20)
        size_in_appldb = duthost.shell('redis-cli hget "BUFFER_PROFILE_TABLE:test-headroom" size')['stdout']
        pytest_assert(size_in_appldb == maximum_profile['size'], 'The profile with a large size was applied to APPL_DB, which can make headroom exceeding')

        # Check log
        check_log_analyzer(loganalyzer, marker)

        # Restore config
        duthost.shell('config interface buffer priority-group lossless set {} {}'.format(port_to_test, '3-4'))
        duthost.shell('config buffer profile remove test-headroom')

        # 4. Configure a long cable length with shared headroom pool enabled.
        loganalyzer, marker = init_log_analyzer(duthost,
                                                'Toggle shared headroom pool',
                                                ['BUFFER_PROFILE .* cannot be updated because .* referencing it violates the resource limitation',
                                                 'Unable to update profile for port .*. Accumulative headroom size exceeds limit',
                                                 'refreshSharedHeadroomPool: Failed to update buffer profile .* when toggle shared headroom pool'])

        # Enable shared headroom pool
        duthost.shell('config buffer shared-headroom-pool over-subscribe-ratio 2')
        time.sleep(20)
        # And then configure the cable length which causes the accumulative headroom exceed the limit
        duthost.shell('config interface cable-length {} {}m'.format(port_to_test, violating_cable_length))
        expected_profile = make_expected_profile_name(original_speed, '{}m'.format(violating_cable_length))
        check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), expected_profile)

        # Disable shared headroom pool
        duthost.shell('config buffer shared-headroom-pool over-subscribe-ratio 0')
        time.sleep(20)
        # Make sure the size isn't updated
        profile_appldb = _compose_dict_from_cli(duthost.shell('redis-cli hgetall BUFFER_PROFILE_TABLE:{}'.format(expected_profile))['stdout'].split('\n'))
        assert profile_appldb['xon'] == profile_appldb['size']

        # Check log
        check_log_analyzer(loganalyzer, marker)
    finally:
        logging.info('[Clean up]')
        duthost.shell('config interface cable-length {} {}'.format(port_to_test, original_cable_len), module_ignore_errors = True)
        duthost.shell('config interface buffer priority-group lossless remove {} 5-7'.format(port_to_test), module_ignore_errors = True)
        duthost.shell('config interface buffer priority-group lossless set {} 3-4'.format(port_to_test), module_ignore_errors = True)
        duthost.shell('config buffer profile remove test-headroom', module_ignore_errors = True)
        duthost.shell('config buffer shared-headroom-pool over-subscribe-ratio {}'.format(original_over_subscribe_ratio), module_ignore_errors = True)
        duthost.shell('config buffer shared-headroom-pool size {}'.format(original_configured_shp_size), module_ignore_errors = True)
        ensure_pool_size(duthost, 60, original_pool_size, original_shp_size, None)


def _recovery_to_dynamic_buffer_model(duthost):
    duthost.shell('kill $(pgrep buffermgrd)')
    duthost.shell('config qos reload')
    duthost.shell('config save -y')
    config_reload(duthost, config_source='config_db')


def test_buffer_model_test(duthosts, rand_one_dut_hostname, conn_graph_facts):
    """Verify whether the buffer model is expected after configuration operations:
    The following items are verified
     - Whether the buffer model is traditional after executing config load_minigraph
     - Whether the buffer model is dynamic after recovering the buffer model to dynamic
    """
    duthost = duthosts[rand_one_dut_hostname]
    try:
        logging.info('[Config load_minigraph]')
        config_reload(duthost, config_source='minigraph')
        buffer_model = duthost.shell('redis-cli -n 4 hget "DEVICE_METADATA|localhost" buffer_model')['stdout']
        pytest_assert(buffer_model == 'traditional', 'Got buffer model {} after executing config load_minigraph, traditional expected')

        logging.info('[Recover the DUT to default buffer model]')
        _recovery_to_dynamic_buffer_model(duthost)
        buffer_model = duthost.shell('redis-cli -n 4 hget "DEVICE_METADATA|localhost" buffer_model')['stdout']
        pytest_assert(buffer_model == 'dynamic', 'Got buffer model {} after executing recovering the buffer model to dynamic')
    finally:
        _recovery_to_dynamic_buffer_model(duthost)
