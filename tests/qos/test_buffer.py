import logging
import os
import sys
import time
import re
import json
import math
from natsort import natsorted

import pytest

from tests.common import config_reload
from tests.common.broadcom_data import is_broadcom_device
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts
from tests.common.mellanox_data import is_mellanox_device
from tests.common.innovium_data import is_innovium_device
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.utilities import check_qos_db_fv_reference_with_table
from tests.common.utilities import skip_release
from tests.common.dualtor.dual_tor_utils import is_tunnel_qos_remap_enabled, dualtor_ports # lgtm[py/unused-import]

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
TESTPARAM_EXTRA_OVERHEAD = None
TESTPARAM_ADMIN_DOWN = None

BUFFER_MODEL_DYNAMIC = True

ASIC_TABLE_KEYS_LOADED = False
CELL_SIZE = None
PIPELINE_LATENCY = None
MAC_PHY_DELAY = None

LOSSLESS_TRAFFIC_PATTERN_KEYS_LOADED = False
LOSSLESS_MTU = None
SMALL_PACKET_PERCENTAGE = None

KEY_2_LOSSLESS_QUEUE = "2_lossless_queues"
KEY_4_LOSSLESS_QUEUE = "4_lossless_queues"

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


def get_asic_table_data_from_db(duthost):
    """
    Load CELL_SIZE, PIPELINE_LATENCY and MAC_PHY_DELAY from ASIC_TABLE
    """
    # Get cell size from state DB
    # Command: redis-cli -n 6 hget "ASIC_TABLE|MELLANOX-SPECTRUM-2" 'cell_size'
    asic_keys = duthost.shell('redis-cli -n 6 keys *ASIC_TABLE*')['stdout']
    cell_size = float(duthost.shell('redis-cli -n 6 hget "{}" "cell_size"'.format(asic_keys))['stdout'])

    # Get PIPELINE_LATENCY from state DB
    # Command: redis-cli -n 6 hget "ASIC_TABLE|MELLANOX-SPECTRUM-2" 'pipeline_latency'
    pipeline_latency = float(
        duthost.shell('redis-cli -n 6 hget "{}" "pipeline_latency"'.format(asic_keys))['stdout']) * 1024

    # Get MAC_PHY_DELAY from state DB
    # Command: redis-cli -n 6 hget "ASIC_TABLE|MELLANOX-SPECTRUM-2" 'mac_phy_delay'
    mac_phy_delay = float(duthost.shell('redis-cli -n 6 hget "{}" "mac_phy_delay"'.format(asic_keys))['stdout']) * 1024

    return cell_size, pipeline_latency, mac_phy_delay

def detect_asic_table_keys(duthost):
    """
    Get CELL_SIZE, PIPELINE_LATENCY and MAC_PHY_DELAY by function get_asic_table_data_from_db
    """
    global CELL_SIZE
    global PIPELINE_LATENCY
    global MAC_PHY_DELAY
    global ASIC_TABLE_KEYS_LOADED

    CELL_SIZE, PIPELINE_LATENCY, MAC_PHY_DELAY = get_asic_table_data_from_db(duthost)

    ASIC_TABLE_KEYS_LOADED = True


def get_lossless_traffic_pattern_data_from_db(duthost):
    """
    Load LOSSLESS_MTU, SMALL_PACKET_PERCENTAGE from LOSSLESS_TRAFFIC_PATTERN table
    """
    # Get LOSSLESS_MTU from config DB
    # Command: redis-cli -n 4 hget 'LOSSLESS_TRAFFIC_PATTERN|AZURE' 'mtu'
    lossless_traffic_keys = duthost.shell('redis-cli -n 4 keys LOSSLESS_TRAFFIC_PATTERN*')['stdout']
    lossless_mtu = float(duthost.shell('redis-cli -n 4 hget "{}" "mtu"'.format(lossless_traffic_keys))['stdout'])

    # Get SMALL_PACKET_PERCENTAGE from config DB
    # Command: redis-cli -n 4 hget 'LOSSLESS_TRAFFIC_PATTERN|AZURE' 'small_packet_percentage'
    small_packet_percentage = float(
        duthost.shell('redis-cli -n 4 hget "{}" "small_packet_percentage"'.format(lossless_traffic_keys))['stdout'])

    return lossless_mtu, small_packet_percentage


def detect_lossless_traffic_pattern_keys(duthost):
    """
    Get LOSSLESS_MTU, SMALL_PACKET_PERCENTAGE by calling function get_lossless_traffic_pattern_data_from_db
    """
    global LOSSLESS_MTU
    global SMALL_PACKET_PERCENTAGE
    global LOSSLESS_TRAFFIC_PATTERN_KEYS_LOADED
    LOSSLESS_MTU, SMALL_PACKET_PERCENTAGE = get_lossless_traffic_pattern_data_from_db(duthost)

    LOSSLESS_TRAFFIC_PATTERN_KEYS_LOADED = True


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
    global TESTPARAM_EXTRA_OVERHEAD
    global TESTPARAM_ADMIN_DOWN
    global ASIC_TYPE
    global MAX_SPEED_8LANE_PORT

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
        TESTPARAM_EXTRA_OVERHEAD = vendor_specific_param['extra_overhead']
        TESTPARAM_ADMIN_DOWN = vendor_specific_param['admin-down']
        MAX_SPEED_8LANE_PORT = vendor_specific_param['max_speed_8lane_platform'].get(duthost.facts['platform'])

        # For ingress profile list, we need to check whether the ingress lossy profile exists
        ingress_lossy_pool = duthost.shell('redis-cli -n 4 keys "BUFFER_POOL|ingress_lossy_pool"')['stdout']
        if ingress_lossy_pool:
            ingress_profile_list = TESTPARAM_ADMIN_DOWN.get('BUFFER_PORT_INGRESS_PROFILE_LIST_TABLE')
            ingress_profile_list.append('[BUFFER_PROFILE_TABLE:ingress_lossy_zero_profile]')

        # 'admin-down' section contains references to buffer profiles
        # We need to convert the format of the references according to whether table name should be in the reference
        if not check_qos_db_fv_reference_with_table(duthost):
            expected_pgs = TESTPARAM_ADMIN_DOWN.get('BUFFER_PG_TABLE')
            if expected_pgs:
                new_pgs = {}
                for pg, profile in expected_pgs.items():
                    new_pgs[pg] = profile.replace('[BUFFER_PROFILE_TABLE:', '').replace(']', '')
                TESTPARAM_ADMIN_DOWN['BUFFER_PG_TABLE'] = new_pgs

            expected_queues = TESTPARAM_ADMIN_DOWN.get('BUFFER_QUEUE_TABLE')
            if expected_queues:
                new_queues = {}
                for queue, profile in expected_queues.items():
                    new_queues[queue] = profile.replace('[BUFFER_PROFILE_TABLE:', '').replace(']', '')
                TESTPARAM_ADMIN_DOWN['BUFFER_QUEUE_TABLE'] = new_queues

            expected_ingress_profile_list = TESTPARAM_ADMIN_DOWN.get('BUFFER_PORT_INGRESS_PROFILE_LIST_TABLE')
            if expected_ingress_profile_list:
                new_list = []
                for profile in expected_ingress_profile_list:
                    new_list.append(profile.replace('[BUFFER_PROFILE_TABLE:', '').replace(']', ''))
                TESTPARAM_ADMIN_DOWN['BUFFER_PORT_INGRESS_PROFILE_LIST_TABLE'] = new_list

            expected_egress_profile_list = TESTPARAM_ADMIN_DOWN.get('BUFFER_PORT_EGRESS_PROFILE_LIST_TABLE')
            if expected_egress_profile_list:
                new_list = []
                for profile in expected_egress_profile_list:
                    new_list.append(profile.replace('[BUFFER_PROFILE_TABLE:', '').replace(']', ''))
                TESTPARAM_ADMIN_DOWN['BUFFER_PORT_EGRESS_PROFILE_LIST_TABLE'] = new_list


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
    if not is_mellanox_device(duthost) and not is_innovium_device(duthost):
        load_lossless_headroom_data(duthost)
        yield
        return

    # Disable BGP neighbors
    # There are a lot of routing entries learnt with BGP neighbors enabled.
    # There are a lot of speed changing operations during the buffer test,
    # which causes port operational down and routing entries withdrawn.
    # Since orchagent works in a single thread model, this can causes buffer related notifications
    # pended in the queue and can not be drained until routing entries handled,
    # which in turn significantly slows down the process in orchagent and makes many checks timeout.
    # As the buffer test has already taken ~30 minutes, we don't want to extend the wait time.
    # So disabling BGP neighbors is a reasonal way to tolerance this situation.
    bgp_neighbors = duthost.shell('redis-cli -n 4 keys BGP_NEIGHBOR*')['stdout']
    if bgp_neighbors:
        duthost.shell('config bgp shutdown all')
        logging.info("Shutting down BGP neighbors and waiting for all routing entries withdrawn")
        time.sleep(60)

    enable_shared_headroom_pool = request.config.getoption("--enable_shared_headroom_pool")
    need_to_disable_shared_headroom_pool_after_test = False
    if BUFFER_MODEL_DYNAMIC:
        detect_ingress_pool_number(duthost)
        detect_shared_headroom_pool_mode(duthost)
        detect_asic_table_keys(duthost)
        detect_lossless_traffic_pattern_keys(duthost)
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
        load_lossless_headroom_data(duthost)
        logging.info("Lossless headroom data {}".format(DEFAULT_LOSSLESS_HEADROOM_DATA))

    yield

    if need_to_disable_shared_headroom_pool_after_test:
        configure_shared_headroom_pool(duthost, False)

    if bgp_neighbors:
        duthost.shell("config bgp startup all")
        time.sleep(60)


def skip_traditional_model():
    if not BUFFER_MODEL_DYNAMIC:
        pytest.skip("Skip test in traditional model")


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
        if not ports_info:
            ports = [port.split('|')[1] for port in duthost.shell('redis-cli -n 4 keys "PORT|*"')['stdout'].split('\n')]
        else:
            ports = ports_info.keys()
        if PORTS_WITH_8LANES is None:
            PORTS_WITH_8LANES = []
            for port in ports:
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

            if "adjust_extra_overhead" in kwargs:
                adjust_extra_overhead = int(kwargs["adjust_extra_overhead"])
            else:
                adjust_extra_overhead = 0

            original_memory = curr_pool_size * DEFAULT_INGRESS_POOL_NUMBER + old_size * old_pg_number + adjust_extra_overhead

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

    return wait_until(timeout, delay, 0, _ensure_pool_size, duthost, expected_pool_size, expected_shp_size, ingress_lossless_pool_oid)


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

    if wait_until(10, 2, 0, _check_pg_profile, duthost, pg, expected_profile):
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

    pytest_assert(wait_until(10, 2, 0, _check_pfc_enable, duthost, port, expected_pfc_enable_map),
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


def check_buffer_profile_details(duthost, initial_profiles, profile_name, profile_oid, pool_oid, port_to_test):
    """Check buffer profile details.

    The following items are tested:
     - Whether the headroom information, like xoff, is correct.
       For version 202106 and before, this is tested by comparing with standard profile in pg_profile_lookup table
       For version after 202106, this is tested by comparing with the returned value from function calculate_headroom_data
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
        if check_qos_db_fv_reference_with_table(duthost) == True:
            # SONiC version is 202106 and before, compare with standard profile in pg_profile_lookup table
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
        else:
            # SONiC version is after 202106, compare with the returned value from function calculate_headroom_data
            ret, head_room_data = calculate_headroom_data(duthost, port_to_test)
            if ret:
                # This means it's a profile with std speed and cable length. We can check whether the headroom data is correct
                pytest_assert(int(profile_appldb['xon']) == head_room_data['xon'] and int(profile_appldb['xoff']) == head_room_data['xoff']
                              and (int(profile_appldb['size']) == head_room_data['size'] or DEFAULT_SHARED_HEADROOM_POOL_ENABLED),
                              "Generated profile {} doesn't match the std profile {}".format(profile_appldb, head_room_data))
            else:
                logging.info("Skip headroom checking because headroom information is not able to be calculated for speed {}".format(speed))

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


def make_expected_profile_name(speed, cable_length, **kwargs):
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
    other_factors = kwargs.get('other_factors')
    if other_factors:
        expected_profile += '_'.join(other_factors) + '_'
    if ASIC_TYPE == 'mellanox':
        number_of_lanes = kwargs.get('number_of_lanes')
        if number_of_lanes is not None:
            if number_of_lanes == 8 and speed != MAX_SPEED_8LANE_PORT:
                expected_profile += '8lane_'
        elif NUMBER_OF_LANES == 8 and speed != MAX_SPEED_8LANE_PORT:
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
    lagMembers = set(dutLagInterfaces)
    testPort -= lagMembers
    pytest_require(len(testPort) > 0, "No port to run test")

    PORT_TO_TEST = request.config.getoption("--port_to_test")
    if PORT_TO_TEST in lagMembers:
        logging.info("LAG member port {} can not be used for dynamic buffer test".format(PORT_TO_TEST))
        PORT_TO_TEST = None
    if not PORT_TO_TEST:
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
    skip_traditional_model()

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
            expected_profile = make_expected_profile_name(speed_to_test, cable_len_to_test, other_factors=['mtu{}'.format(mtu_to_test)])
            check_profile_removed = True
        else:
            expected_profile = make_expected_profile_name(speed_to_test, cable_len_to_test)

        logging.info('[Speed and/or cable-len and/or MTU updated] Checking whether new profile {} has been created and pfc_enable has been updated'.format(expected_profile))
        check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), expected_profile)
        check_pfc_enable(duthost, port_to_test, '3,4')
        profile_oid, pool_oid = check_buffer_profile_details(duthost, initial_asic_db_profiles, expected_profile, None, None, port_to_test)
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
            profile_oid, _ = check_buffer_profile_details(duthost, initial_asic_db_profiles, expected_profile, None, pool_oid, port_to_test)

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
    skip_traditional_model()

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
        profile_oid, pool_oid = check_buffer_profile_details(duthost, initial_asic_db_profiles, "headroom-override", None, None, port_to_test)

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
        profile_oid, _ = check_buffer_profile_details(duthost, initial_asic_db_profiles, "headroom-override", profile_oid, pool_oid, port_to_test)

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

    pytest_assert(wait_until(20, 2, 0, _check_buffer_profiles_for_shp, duthost, shp_enabled))


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
    skip_traditional_model()

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
        profile_oid, pool_oid = check_buffer_profile_details(duthost, initial_asic_db_profiles, expected_profile, None, None, port_to_test)
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
    skip_traditional_model()

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
        headroom_override_profile_oid, pool_oid = check_buffer_profile_details(duthost, initial_asic_db_profiles, "headroom-override", None, None, port_to_test)

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
        profile_oid, _ = check_buffer_profile_details(duthost, initial_asic_db_profiles, expected_profile, None, pool_oid, port_to_test)

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
        expected_nondef_profile = make_expected_profile_name(original_speed, '15m', other_factors=['th2'])
        check_pg_profile(duthost, buffer_pg, expected_nondef_profile)
        # A new profile should be created in ASIC DB
        profile_oid, _ = check_buffer_profile_details(duthost, initial_asic_db_profiles, expected_nondef_profile, None, pool_oid, port_to_test)

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
        profile_oid, _ = check_buffer_profile_details(duthost, initial_asic_db_profiles, expected_nondef_profile, None, pool_oid, port_to_test)
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
    def _convert_ref_from_configdb_to_appldb(references):
        """Convert reference format from CONFIG_DB to APPL_DB

        Args:
            references: The reference or reference list to CONFIG_DB entry

        Return:
            The reference or reference list to APPL_DB entry

        Example 1 profile list:
            Input: '[BUFFER_PROFILE|ingress_lossless_profile],[BUFFER_PROFILE|ingress_lossy_profile]'
            Output: '[BUFFER_PROFILE_TABLE:ingress_lossless_profile],[BUFFER_PROFILE_TABLE:ingress_lossy_profile]'

        Example 2 single item:
            Input: '[BUFFER_PROFILE|ingress_lossless_profile]
            Output: '[BUFFER_PROFILE_TABLE:ingress_lossless_profile]
        """
        if not references:
            return ''

        references_in_appldb = ''
        for reference in references.split(','):
            fields = reference.split('|')
            fields[0] += '_TABLE'
            references_in_appldb += ':'.join(fields) + ','

        return references_in_appldb[:-1]

    def _check_buffer_object_aligns_between_appldb_configdb(port_to_test, key, profile_field_name):
        """Check whether buffer objects (queues and priority groups) align between APPL_DB and CONFIG_DB

        This is to verify whether the entries in BUFFER_QUEUE, BUFFER_PORT_INGRESS/EGRESS_PROFILE_LIST
        tables have been popagated to APPL_DB correctly after the port has been started up.

        Args:
            port_to_test: The port under test
            key: The key in buffer tables in CONFIG_DB format, like BUFFER_PG|Ethernet0|3-4
            profile_field_name: profile for BUFFER_QUEUE table and profile_list for buffer profile list tables
        """
        objects_in_configdb = duthost.shell('redis-cli -n 4 keys "{}"'.format(key))['stdout'].split()
        if objects_in_configdb:
            for object_in_configdb in objects_in_configdb:
                profile_in_configdb = duthost.shell('redis-cli -n 4 hget "{}" {}'.format(object_in_configdb, profile_field_name))['stdout']
                # Convert config db reference to appl db reference
                if is_qos_db_reference_with_table:
                    expected_profile_in_appldb = _convert_ref_from_configdb_to_appldb(profile_in_configdb)
                else:
                    expected_profile_in_appldb = profile_in_configdb
                # Convert queue id
                object_in_app_db = _convert_ref_from_configdb_to_appldb(object_in_configdb)
                profile_in_appl_db = duthost.shell('redis-cli hget "{}" {}'.format(object_in_app_db, profile_field_name))['stdout']
                pytest_assert(profile_in_appl_db == expected_profile_in_appldb,
                              "Buffer object {} contains {} which isn't expected ({})".format(key, profile_in_appl_db, expected_profile_in_appldb))

    def _check_buffer_object_aligns_with_expected_ones(port_to_test, table, expected_objects):
        """Check whether the content in BUFFER_PG or BUFFER_QUEUE tables is exactly the same as the expected objects

        Args:
            port_to_test: The port under test
            table: BUFFER_PG or BUFFER_QUEUE
            expected_objects: The expected buffer items of BUFFER_PG or BUFFER_QUEUE when the port is admin down.
                              They are predefined parameters and loaded at the beginning of the test.
                              Typically, they are zero profiles.
        """
        objects_in_appl_db = duthost.shell('redis-cli keys "{}:{}:*"'.format(table, port_to_test))['stdout'].split()
        if expected_objects:
            expected_object_keys = ['{}:{}:{}'.format(table, port_to_test, objectid) for objectid in expected_objects.keys()]
            pytest_assert(set(expected_object_keys) == set(objects_in_appl_db),
                          "Objects in {} on admin-down port is {} but should be {}".format(table, objects_in_appl_db, expected_object_keys))
            for objectid, expected_profile in expected_objects.items():
                profile = duthost.shell('redis-cli hget {}:{}:{} profile'.format(table, port_to_test, objectid))['stdout']
                pytest_assert(profile == expected_profile,
                              "Profile in {}:{}:{} should be {} but got {}".format(table, port_to_test, objectid, expected_objects[objectid], profile))
        else:
            pytest_assert(not objects_in_appl_db, "There shouldn't be any object in {} on an administratively down port but we got {}".format(table, objects_in_appl_db))

    def _check_buffer_object_list_aligns_with_expected_ones(port_to_test, table, expected_objects):
        """Check whether the content in BUFFER_PG or BUFFER_QUEUE tables is exactly the same as the expected objects

        Args:
            port_to_test: The port under test
            table: BUFFER_PG or BUFFER_QUEUE
            expected_objects: The expected buffer items of BUFFER_PG or BUFFER_QUEUE when the port is admin down.
                              They are predefined parameters and loaded at the beginning of the test.
        """
        object_list_in_appl_db = duthost.shell('redis-cli hget "{}:{}" profile_list'.format(table, port_to_test))['stdout'].split(',')
        if expected_objects:
            pytest_assert(set(expected_objects) == set(object_list_in_appl_db),
                          "Profile in {}:{} should be {} but got {}".format(table, port_to_test, expected_objects, object_list_in_appl_db))
        else:
            pytest_assert(not object_list_in_appl_db, "There shouldn't be any object in {} on an administratively down port but we got {}".format(table, object_list_in_appl_db))

    skip_traditional_model()

    param = TESTPARAM_HEADROOM_OVERRIDE.get("add")
    if not param:
        pytest.skip('Shutdown port test skipped due to no headroom override parameters defined')

    duthost = duthosts[rand_one_dut_hostname]
    is_qos_db_reference_with_table = check_qos_db_fv_reference_with_table(duthost)
    original_speed = duthost.shell('redis-cli -n 4 hget "PORT|{}" speed'.format(port_to_test))['stdout']
    raw_lanes_str =  duthost.shell('redis-cli -n 4 hget "PORT|{}" lanes'.format(port_to_test))['stdout']
    list_of_lanes = raw_lanes_str.split(',')
    original_cable_len = duthost.shell('redis-cli -n 4 hget "CABLE_LENGTH|AZURE" {}'.format(port_to_test))['stdout']
    if check_qos_db_fv_reference_with_table(duthost) == True:
        original_profile = duthost.shell('redis-cli hget "BUFFER_PG_TABLE:{}:3-4" profile'.format(port_to_test))['stdout'][1:-1]
    else:
        original_profile = duthost.shell('redis-cli hget "BUFFER_PG_TABLE:{}:3-4" profile'.format(port_to_test))['stdout']
        original_profile = "BUFFER_PROFILE_TABLE:" + original_profile
    original_pg_size = duthost.shell('redis-cli hget "{}" size'.format(original_profile))['stdout']
    original_pool_size = duthost.shell('redis-cli hget BUFFER_POOL_TABLE:ingress_lossless_pool size')['stdout']

    new_cable_len = '15m'

    extra_overhead = TESTPARAM_EXTRA_OVERHEAD.get(str(len(list_of_lanes)))
    if not extra_overhead:
        extra_overhead = TESTPARAM_EXTRA_OVERHEAD.get('default')
        if not extra_overhead:
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

    _, pool_oid = check_buffer_profile_details(duthost, initial_asic_db_profiles, headroom_override_profile, None, None, port_to_test)

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
         make_expected_profile_name(original_speed, original_cable_len, other_factors=['th{}'.format(dynamic_th_value)]),
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
            # Make sure there isn't any PG on the port or zero profile configured for PGs
            time.sleep(10)
            logging.info('Check whether all PGs are removed from port {}'.format(port_to_test))
            expected_pgs = TESTPARAM_ADMIN_DOWN.get('BUFFER_PG_TABLE')
            _check_buffer_object_aligns_with_expected_ones(port_to_test, 'BUFFER_PG_TABLE', expected_pgs)

            # Make sure the zero profiles have been applied on queues on the port
            logging.info('Check whether all queues are configured as zero profile or removed from port {}'.format(port_to_test))
            expected_queues = TESTPARAM_ADMIN_DOWN.get('BUFFER_QUEUE_TABLE')
            _check_buffer_object_aligns_with_expected_ones(port_to_test, 'BUFFER_QUEUE_TABLE', expected_queues)

            # Make sure the zero profiles have been applied on ingress buffer profile list on the port
            logging.info('Check whether ingress profile list is configured as zero profile or removed from port {}'.format(port_to_test))
            expected_ingress_profile_list = TESTPARAM_ADMIN_DOWN.get('BUFFER_PORT_INGRESS_PROFILE_LIST_TABLE')
            _check_buffer_object_list_aligns_with_expected_ones(port_to_test, 'BUFFER_PORT_INGRESS_PROFILE_LIST_TABLE', expected_ingress_profile_list)

            # Make sure the zero profiles have been applied on egress buffer profile list on the port
            logging.info('Check whether egress profile list is configured as zero profile or removed from port {}'.format(port_to_test))
            expected_egress_profile_list = TESTPARAM_ADMIN_DOWN.get('BUFFER_PORT_EGRESS_PROFILE_LIST_TABLE')
            _check_buffer_object_list_aligns_with_expected_ones(port_to_test, 'BUFFER_PORT_EGRESS_PROFILE_LIST_TABLE', expected_egress_profile_list)

            # Check the pool size after the port is admin down
            check_pool_size(duthost,
                            pool_oid,
                            pool_size = original_pool_size,
                            shp_size = original_shp_size,
                            old_xoff = original_pg_xoff,
                            old_size = original_pg_size,
                            new_pg_number = 0,
                            adjust_extra_overhead = extra_overhead)

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

            # Check whether the queues have been applied correctly
            logging.info('Check whether queues are readded to port {}'.format(port_to_test))
            _check_buffer_object_aligns_between_appldb_configdb(port_to_test, "BUFFER_QUEUE|{}|*".format(port_to_test), 'profile')

            # Check whether the ingress profile list have been applied correctly
            logging.info('Check whether ingress profile list are readded to port {}'.format(port_to_test))
            _check_buffer_object_aligns_between_appldb_configdb(port_to_test, "BUFFER_PORT_INGRESS_PROFILE_LIST|{}".format(port_to_test), 'profile_list')

            # Check whether the egress profile list have been applied correctly
            logging.info('Check whether egress profile list are readded to port {}'.format(port_to_test))
            _check_buffer_object_aligns_between_appldb_configdb(port_to_test, "BUFFER_PORT_EGRESS_PROFILE_LIST|{}".format(port_to_test), 'profile_list')

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

    skip_traditional_model()

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
        new_profile_id, pool_id = check_buffer_profile_details(duthost, initial_asic_db_profiles, expected_profile, None, None, port_to_test)

        # As comments at the beginning of the method, we don't check buffer pool size in this test case.
        # The same for all the following steps.

        # Enable port auto negotiation first and then configure the advertised speed list
        logging.info('Enable port auto negotiation')
        duthost.shell('config interface autoneg {} enabled'.format(port_to_test))
        # Check whether the maximum supported speed is used for creating lossless profile
        expected_profile = make_expected_profile_name(max_supported_speed, cable_length_to_test)
        check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), expected_profile)
        check_buffer_profile_details(duthost, initial_asic_db_profiles, expected_profile, new_profile_id, pool_id, port_to_test)

        # Configure advertised speeds
        logging.info('Update advertised speeds to {}'.format(advertised_speeds_to_test))
        duthost.shell('config interface advertised-speeds {} {}'.format(port_to_test, advertised_speeds_to_test))
        # Check whether the maximum advertised speed is used for creating lossless profile
        expected_profile = make_expected_profile_name(max_advertised_speed, cable_length_to_test)
        check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), expected_profile)
        check_buffer_profile_details(duthost, initial_asic_db_profiles, expected_profile, new_profile_id, pool_id, port_to_test)

        # Disable port auto negotiation
        logging.info('Disable port auto negotiation')
        duthost.shell('config interface autoneg {} disabled'.format(port_to_test))
        expected_profile = make_expected_profile_name(speed_before_test, cable_length_to_test)
        check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), expected_profile)
        check_buffer_profile_details(duthost, initial_asic_db_profiles, expected_profile, new_profile_id, pool_id, port_to_test)

        # Enable port auto negotiation with advertised speed configured
        logging.info('Reenable port auto negotiation with advertised speeds configured')
        duthost.shell('config interface autoneg {} enabled'.format(port_to_test))
        # Check whether the maximum advertised speed is used for creating lossless profile
        expected_profile = make_expected_profile_name(max_advertised_speed, cable_length_to_test)
        check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), expected_profile)
        check_buffer_profile_details(duthost, initial_asic_db_profiles, expected_profile, new_profile_id, pool_id, port_to_test)

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
        check_buffer_profile_details(duthost, initial_asic_db_profiles, expected_profile, new_profile_id, pool_id, port_to_test)
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
    skip_traditional_model()

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
        cable_length = int(original_cable_len[:-1])
        cable_length_step = 128
        while True:
            duthost.shell('config interface cable-length {} {}m'.format(port_to_test, cable_length))
            expected_profile = make_expected_profile_name(original_speed, '{}m'.format(cable_length))
            profile_applied = check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), expected_profile, False)
            if not profile_applied:
                break
            logging.info('Cable length {} has been applied successfully'.format(cable_length))
            if cable_length > 10000:
                pytest.skip("Not able to find the maximum headroom of port {} after cable length has been increased to 10km, skip the test".format(port_to_test))
            cable_length += cable_length_step
            cable_length_step *= 2

        # Find the exact point from which the accumulative headroom starts to exceed the limit via using binary seach
        cable_length_upper = cable_length
        cable_length_step /= 2
        cable_length -= cable_length_step
        cable_length_lower = cable_length
        logging.info("Cable length {} can be applied but {} can't. Finding the exact maximum cable length".format(cable_length_lower, cable_length_upper))
        while True:
            cable_length = (cable_length_upper + cable_length_lower) / 2
            duthost.shell('config interface cable-length {} {}m'.format(port_to_test, cable_length))
            expected_profile = make_expected_profile_name(original_speed, '{}m'.format(cable_length))
            profile_applied = check_pg_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), expected_profile, False)
            if profile_applied:
                cable_length_lower = cable_length
                logging.info('Cable length {} has been applied successfully, moving forward. Range now is [{}, {})'.format(cable_length, cable_length_lower, cable_length_upper))
            else:
                cable_length_upper = cable_length
                logging.info('Cable length {} has not been applied, moving backward. Range now is [{}, {})'.format(cable_length, cable_length_lower, cable_length_upper))
            if cable_length_lower + 1 >= cable_length_upper:
                cable_length = cable_length_lower
                break

        # We've got the maximum cable length that can be applied on the port
        violating_cable_length = cable_length_upper
        maximum_cable_length = cable_length_lower
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
    skip_traditional_model()

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


def test_buffer_deployment(duthosts, rand_one_dut_hostname, conn_graph_facts, tbinfo, dualtor_ports):
    """The testcase to verify whether buffer template has been correctly rendered and applied

    1. For all ports in the config_db,
       - Check whether there is no lossless buffer PG configured on an admin-down port
       - Check whether the lossless PG and queues aligns with the port's speed and cable length
       - If name to oid maps exist for port and PG, check whether the information in ASIC_DB aligns with that in CONFIG_DB
       - If a lossless profile hasn't been checked, check whether lossless profile in CONFIG_DB aligns with
         - pg_profile_lookup.ini according to speed and cable length
         - information in ASIC_DB
    2. Shutdown a port and check whether the lossless buffer PG has been remvoed
    3. Startup the port and check whether the lossless PG has been readded.
    """
    def _check_condition(condition, message, use_assert):
        """Check whether the condition is satisfied

        Args:
            condition: The condition to check
            message: The message to log or in pytest_assert
            use_assert: Whether to use assert or not. If this is called from wait_until(), it should be False.

        Return:
            The condition
        """
        if use_assert:
            pytest_assert(condition, message)
        elif not condition:
            logging.info("Port buffer check: {}".format(message))
            return False

        return True

    def _check_buffer_item_in_asic_db(duthost, port, buffer_item, name_map, buffer_profile_oid, asic_key_name, should_have_profile, use_assert):
        """Check whether the buffer queues or priority groups align between APPL_DB and ASIC_DB

        Args:
            buffer_item: ID of buffer queues or priority groups in APPL_DB, like "Ethernet0:3-4".
            name_map: The map from buffer item's name to its SAI OID.
                      The map is fetched from CONFIG_DB at the beginning of the test.
            buffer_profile_oid: The OID of the expected buffer profile.
                                Not None: It will check whether the OID of profile in ASIC_DB is the same.
            asic_key_name: The field name buffer profiles of queues or priority groups in ASIC_DB
            should_have_profile: Whether there should be a profile configured for the buffer object
            use_assert: In case the test failed, to assert or just return false.
                        It should return false if it is called in a wait_until loop
        """
        buffer_item_asic_oid = name_map['{}:{}'.format(port, buffer_item)]
        buffer_item_asic_key = duthost.shell('redis-cli -n 1 keys *{}*'.format(buffer_item_asic_oid))['stdout']
        buffer_profile_oid_in_pg = duthost.shell('redis-cli -n 1 hget {} {}'.format(buffer_item_asic_key, asic_key_name))['stdout']
        if should_have_profile:
            if buffer_profile_oid:
                if not _check_condition(buffer_profile_oid == buffer_profile_oid_in_pg,
                                        "Different OIDs in buffer items ({}) and ({}) in port {}".format(buffer_profile_oid, buffer_profile_oid_in_pg, port),
                                        use_assert):
                    return None, False
            else:
                buffer_profile_oid = buffer_profile_oid_in_pg
        else:
            if not _check_condition(not buffer_profile_oid_in_pg or buffer_profile_oid_in_pg == 'oid:0x0',
                                    "Buffer PG configured on admin down port in ASIC_DB {}".format(port),
                                    use_assert):
                return None, False

        return buffer_profile_oid, True

    def _ids_to_id_list(ids):
        """Convert ID map to list of IDs

        Example: "0-2" => ["0", "1", "2"]
        """
        pattern = "^([0-9])+(-[0-9]+)*$"
        m = re.match(pattern, ids)
        lower = m.group(1)
        upper = m.group(2)
        if not upper:
            upper = lower
        else:
            upper = upper[1:]
        return [str(x) for x in range(int(lower), int(upper) + 1)]

    def _check_port_buffer_info_and_get_profile_oid(duthost, table, ids, port, expected_profile, use_assert=True):
        """Check port's buffer information against APPL_DB and ASIC_DB

        Args:
            duthost: The duthost object
            table: BUFFER_QUEUE or BUFFER_PG
            ids: The ID map, like "3-4" or "0-2"
            port: The port to test in string
            expected_profile: The expected profile in string
            use_assert: Whether or not to use pytest_assert in case any conditional check isn't satisfied

        Return:
            A tuple consisting of the OID of buffer profile and whether there is any check failed
        """
        profile_in_db = duthost.shell('redis-cli hget "{}:{}:{}" profile'.format(table, port, ids))['stdout']
        buffer_profile_oid = None
        if table == 'BUFFER_PG_TABLE':
            sai_field = 'SAI_INGRESS_PRIORITY_GROUP_ATTR_BUFFER_PROFILE'
            buffer_name_map = pg_name_map
        elif table == 'BUFFER_QUEUE_TABLE':
            sai_field = 'SAI_QUEUE_ATTR_BUFFER_PROFILE_ID'
            buffer_name_map = queue_name_map

        id_list = _ids_to_id_list(ids)

        if expected_profile:
            if not _check_condition(profile_in_db == expected_profile, "The profile of {}:{}:{} isn't the expected ({})".format(table, port, ids, expected_profile), use_assert):
                return None, False

            if buffer_name_map:
                buffer_profile_oid = None
                for item in id_list:
                    logging.info("Checking {}:{}:{} in ASIC_DB".format(table, port, item))
                    buffer_profile_oid, success = _check_buffer_item_in_asic_db(duthost, port, item, buffer_name_map, buffer_profile_oid, sai_field, True, use_assert)
                    if not success:
                        return None, False
        else:
            if not _check_condition(not profile_in_db, "{}:{}:{} configured on admin down port".format(table, port, ids), use_assert):
                return None, False
            if buffer_name_map:
                for item in id_list:
                    logging.info("Checking {}:{}:{} in ASIC_DB".format(table, port, item))
                    buffer_profile_oid, success = _check_buffer_item_in_asic_db(duthost, port, item, buffer_name_map, None, sai_field, False, use_assert)

        return buffer_profile_oid, True

    def _check_port_buffer_info_and_return(duthost, table, ids, port, expected_profile):
        """Check port's buffer information against CONFIG_DB and ASIC_DB and return the result

        This is called from wait_until

        Args:
            duthost: The duthost object
            port: The port to test in string
            expected_profile: The expected profile in string

        Return:
            Whether all the checks passed
        """
        _, result = _check_port_buffer_info_and_get_profile_oid(duthost, table, ids, port, expected_profile, False)
        return result

    duthost = duthosts[rand_one_dut_hostname]
    asic_type = duthost.get_asic_name()

    # Skip the legacy branches
    skip_release(duthost, ["201811", "201911"])

    # Check whether the COUNTERS_PG_NAME_MAP and COUNTERS_QUEUE_NAME_MAP exists. Skip ASIC_DB checking if it isn't
    pg_name_map = _compose_dict_from_cli(duthost.shell('redis-cli -n 2 hgetall COUNTERS_PG_NAME_MAP')['stdout'].split())
    queue_name_map = _compose_dict_from_cli(duthost.shell('redis-cli -n 2 hgetall COUNTERS_QUEUE_NAME_MAP')['stdout'].split())
    cable_length_map = _compose_dict_from_cli(duthost.shell('redis-cli -n 4 hgetall "CABLE_LENGTH|AZURE"')['stdout'].split())
    buffer_table_up = {
        KEY_2_LOSSLESS_QUEUE: [('BUFFER_PG_TABLE', '0', '[BUFFER_PROFILE_TABLE:ingress_lossy_profile]'),
                                         ('BUFFER_QUEUE_TABLE', '0-2', '[BUFFER_PROFILE_TABLE:q_lossy_profile]'),
                                         ('BUFFER_QUEUE_TABLE', '3-4', '[BUFFER_PROFILE_TABLE:egress_lossless_profile]'),
                                         ('BUFFER_QUEUE_TABLE', '5-6', '[BUFFER_PROFILE_TABLE:q_lossy_profile]'),
                                         (None, None, None)
                             ],
        KEY_4_LOSSLESS_QUEUE: [('BUFFER_PG_TABLE', '0', '[BUFFER_PROFILE_TABLE:ingress_lossy_profile]'),
                                         ('BUFFER_QUEUE_TABLE', '0-1', '[BUFFER_PROFILE_TABLE:q_lossy_profile]'),
                                         ('BUFFER_QUEUE_TABLE', '2-4', '[BUFFER_PROFILE_TABLE:egress_lossless_profile]'),
                                         ('BUFFER_QUEUE_TABLE', '5', '[BUFFER_PROFILE_TABLE:q_lossy_profile]'),
                                         ('BUFFER_QUEUE_TABLE', '6', '[BUFFER_PROFILE_TABLE:egress_lossless_profile]'),
                                         ('BUFFER_QUEUE_TABLE', '7', '[BUFFER_PROFILE_TABLE:q_lossy_profile]'),
                                         (None, None, None)
                             ]
    }
    if is_tunnel_qos_remap_enabled(duthost):
        buffer_table_up[KEY_2_LOSSLESS_QUEUE][3] = ('BUFFER_QUEUE_TABLE', '5-7', '[BUFFER_PROFILE_TABLE:q_lossy_profile]')
    
    if not is_mellanox_device(duthost):
        buffer_table_up[KEY_2_LOSSLESS_QUEUE][1] = ('BUFFER_QUEUE_TABLE', '0-2', '[BUFFER_PROFILE_TABLE:egress_lossy_profile]')
        if is_tunnel_qos_remap_enabled(duthost):
            buffer_table_up[KEY_2_LOSSLESS_QUEUE][3] = ('BUFFER_QUEUE_TABLE', '5-7', '[BUFFER_PROFILE_TABLE:egress_lossy_profile]')
        else:
            buffer_table_up[KEY_2_LOSSLESS_QUEUE][3] = ('BUFFER_QUEUE_TABLE', '5-6', '[BUFFER_PROFILE_TABLE:egress_lossy_profile]')

        buffer_table_up[KEY_4_LOSSLESS_QUEUE][1] = ('BUFFER_QUEUE_TABLE', '0-1', '[BUFFER_PROFILE_TABLE:egress_lossy_profile]')
        buffer_table_up[KEY_4_LOSSLESS_QUEUE][3] = ('BUFFER_QUEUE_TABLE', '5', '[BUFFER_PROFILE_TABLE:egress_lossy_profile]')
        buffer_table_up[KEY_4_LOSSLESS_QUEUE][5] = ('BUFFER_QUEUE_TABLE', '7', '[BUFFER_PROFILE_TABLE:egress_lossy_profile]')
    
    buffer_table_down = {
        KEY_2_LOSSLESS_QUEUE: [('BUFFER_PG_TABLE', '0', '[BUFFER_PROFILE_TABLE:ingress_lossy_pg_zero_profile]'),
                                           ('BUFFER_QUEUE_TABLE', '0-2', '[BUFFER_PROFILE_TABLE:egress_lossy_zero_profile]'),
                                           ('BUFFER_QUEUE_TABLE', '3-4', '[BUFFER_PROFILE_TABLE:egress_lossless_zero_profile]'),
                                           ('BUFFER_QUEUE_TABLE', '5-6', '[BUFFER_PROFILE_TABLE:egress_lossy_zero_profile]'),
                                           (None, None, None)
                             ],
        KEY_4_LOSSLESS_QUEUE: [(None, None, None)] # The admin_down ports can not be dualtor_ports. Hence there is no 4_lossless_queue profile
    }

    if is_tunnel_qos_remap_enabled(duthost):
        buffer_table_down[KEY_2_LOSSLESS_QUEUE][3] = ('BUFFER_QUEUE_TABLE', '5-7', '[BUFFER_PROFILE_TABLE:egress_lossy_zero_profile]')
    
    buffer_items_to_check_dict = {"up": buffer_table_up, "down": buffer_table_down}


    if is_innovium_device(duthost):
        buffer_items_to_check_dict["up"][3] = ('BUFFER_QUEUE_TABLE', '5-7', '[BUFFER_PROFILE_TABLE:egress_lossy_profile]')
        buffer_items_to_check_dict["down"][3] = ('BUFFER_QUEUE_TABLE', '5-7', '[BUFFER_PROFILE_TABLE:egress_lossy_zero_profile]')

    if check_qos_db_fv_reference_with_table(duthost):
        profile_wrapper = '[BUFFER_PROFILE_TABLE:{}]'
        is_qos_db_reference_with_table = True
    else:
        for status, buffer_items_to_check_4_6 in buffer_items_to_check_dict.items():
            for queue_4_6, buffer_items_to_check in buffer_items_to_check_4_6.items():
                new_buffer_items_to_check = []
                for item in buffer_items_to_check:
                    table, ids, profiles = item
                    if profiles:
                        profiles = profiles.replace('[BUFFER_PROFILE_TABLE:', '').replace(']', '')
                    new_buffer_items_to_check.append((table, ids, profiles))
                buffer_items_to_check_dict[status][queue_4_6] = new_buffer_items_to_check
        profile_wrapper = '{}'
        is_qos_db_reference_with_table = False

    configdb_ports = [x.split('|')[1] for x in duthost.shell('redis-cli -n 4 keys "PORT|*"')['stdout'].split()]
    profiles_checked = {}
    lossless_pool_oid = None
    admin_up_ports = set()
    for port in configdb_ports:
        logging.info("Checking port buffer information: {}".format(port))
        port_config = _compose_dict_from_cli(duthost.shell('redis-cli -n 4 hgetall "PORT|{}"'.format(port))['stdout'].split())
        cable_length = cable_length_map[port]
        speed = port_config['speed']
        expected_profile = make_expected_profile_name(speed, cable_length, number_of_lanes=len(port_config['lanes'].split(',')))

        if port in dualtor_ports:
            key_name = KEY_4_LOSSLESS_QUEUE
        else:
            key_name = KEY_2_LOSSLESS_QUEUE
        # The last item in the check list various according to port's admin state.
        # We need to append it according to the port each time. Pop the last item first
        if port_config.get('admin_status') == 'up':
            admin_up_ports.add(port)
            buffer_items_to_check = buffer_items_to_check_dict["up"][key_name][:]
            if key_name == KEY_4_LOSSLESS_QUEUE:
                buffer_items_to_check.extend(
                    [('BUFFER_PG_TABLE', '2-4', profile_wrapper.format(expected_profile)),
                    ('BUFFER_PG_TABLE', '6', profile_wrapper.format(expected_profile))])
            else:
                buffer_items_to_check.append(('BUFFER_PG_TABLE', '3-4', profile_wrapper.format(expected_profile)))
        else:
            if is_mellanox_device(duthost):
                buffer_items_to_check = buffer_items_to_check_dict["down"][key_name]
            elif is_broadcom_device(duthost) and (asic_type in ['td2', 'td3'] or speed <= '10000'):
                buffer_items_to_check = [(None, None, None)]
            else:
                if key_name == KEY_2_LOSSLESS_QUEUE:
                    buffer_items_to_check = [('BUFFER_PG_TABLE', '3-4', profile_wrapper.format(expected_profile))]
                else:
                    buffer_items_to_check.extend(
                        [('BUFFER_PG_TABLE', '2-4', profile_wrapper.format(expected_profile)),
                        ('BUFFER_PG_TABLE', '6', profile_wrapper.format(expected_profile))])

        for table, ids, expected_profile in buffer_items_to_check:
            logging.info("Checking buffer item {}:{}:{}".format(table, port, ids))

            if not expected_profile:
                continue

            buffer_profile_oid, _ = _check_port_buffer_info_and_get_profile_oid(duthost, table, ids, port, expected_profile)

            if is_qos_db_reference_with_table:
                expected_profile_key = expected_profile[1:-1]
            else:
                expected_profile_key = "BUFFER_PROFILE_TABLE:{}".format(expected_profile)

            if expected_profile not in profiles_checked:
                profile_info = _compose_dict_from_cli(duthost.shell('redis-cli hgetall "{}"'.format(expected_profile_key))['stdout'].split())
                is_ingress_lossless = expected_profile[:12] == 'pg_lossless_'
                if is_ingress_lossless and not BUFFER_MODEL_DYNAMIC:
                    std_profiles_for_speed = DEFAULT_LOSSLESS_HEADROOM_DATA.get(speed)
                    if std_profiles_for_speed:
                        std_profile = std_profiles_for_speed.get(cable_length)
                        if std_profile:
                            # This means it's a profile with std speed and cable length. We can check whether the headroom data is correct
                            pytest_assert(profile_info['xon'] == std_profile['xon'] and profile_info['xoff'] == std_profile['xoff']
                                          and (profile_info['size'] == std_profile['size'] or DEFAULT_SHARED_HEADROOM_POOL_ENABLED),
                                          "Buffer profile {} {} doesn't match default {}".format(expected_profile, profile_info, std_profile))

                if buffer_profile_oid:
                    # Further check the buffer profile in ASIC_DB
                    logging.info("Checking profile {} oid {}".format(expected_profile, buffer_profile_oid))
                    buffer_profile_key = duthost.shell('redis-cli -n 1 keys *{}*'.format(buffer_profile_oid))['stdout']
                    buffer_profile_asic_info = _compose_dict_from_cli(duthost.shell('redis-cli -n 1 hgetall {}'.format(buffer_profile_key))['stdout'].split())
                    pytest_assert(buffer_profile_asic_info.get('SAI_BUFFER_PROFILE_ATTR_XON_TH') == profile_info.get('xon') and
                                  buffer_profile_asic_info.get('SAI_BUFFER_PROFILE_ATTR_XOFF_TH') == profile_info.get('xoff') and
                                  buffer_profile_asic_info['SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE'] == profile_info['size'] and
                                  (buffer_profile_asic_info['SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE'] == 'SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC' and
                                   buffer_profile_asic_info['SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH'] == profile_info['dynamic_th'] or
                                   buffer_profile_asic_info['SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE'] == 'SAI_BUFFER_PROFILE_THRESHOLD_MODE_STATIC' and
                                   buffer_profile_asic_info['SAI_BUFFER_PROFILE_ATTR_SHARED_STATIC_TH'] == profile_info['static_th']),
                                  "Buffer profile {} {} doesn't align with ASIC_TABLE {}".format(expected_profile, profile_info, buffer_profile_asic_info))

                profiles_checked[expected_profile] = buffer_profile_oid
                if is_ingress_lossless:
                    if not lossless_pool_oid:
                        lossless_pool_oid = buffer_profile_asic_info['SAI_BUFFER_PROFILE_ATTR_POOL_ID']
                    else:
                        pytest_assert(lossless_pool_oid == buffer_profile_asic_info['SAI_BUFFER_PROFILE_ATTR_POOL_ID'],
                                      "Buffer profile {} has different buffer pool id {} from others {}".format(expected_profile, buffer_profile_asic_info['SAI_BUFFER_PROFILE_ATTR_POOL_ID'], lossless_pool_oid))
            else:
                pytest_assert(profiles_checked[expected_profile] == buffer_profile_oid,
                              "PG {}:{} has different OID of profile from other PGs sharing the same profile {}".format(port, ids, expected_profile))

    if not BUFFER_MODEL_DYNAMIC:

        def _profile_name(duthost, port, pg_id_name):
            if is_mellanox_device(duthost):
                profile_name = None
            else:
                profile_name = duthost.shell('redis-cli hget "BUFFER_PG_TABLE:{}:{}" profile'.format(port, pg_id_name))['stdout']
            
            return profile_name

        port_to_shutdown = admin_up_ports.pop()
        if port_to_shutdown in dualtor_ports:
            pg_id_names = ["2-4", "6"]
        else:
            pg_id_names = ["3-4"]
        try:
            # Shutdown the port and check whether the lossless PG has been remvoed
            logging.info("Shut down an admin-up port {} and check its buffer information".format(port_to_shutdown))
            duthost.shell('config interface shutdown {}'.format(port_to_shutdown))
            for pg_id_name in pg_id_names:
                wait_until(60, 5, 0, _check_port_buffer_info_and_return, duthost, 'BUFFER_PG_TABLE', pg_id_name, port_to_shutdown, _profile_name(duthost, port, pg_id_name))
            # Startup the port and check whether the lossless PG has been reconfigured
            logging.info("Re-startup the port {} and check its buffer information".format(port_to_shutdown))
            duthost.shell('config interface startup {}'.format(port_to_shutdown))
            for pg_id_name in pg_id_names:
                wait_until(60, 5, 0, _check_port_buffer_info_and_return, duthost, 'BUFFER_PG_TABLE', pg_id_name, port_to_shutdown, _profile_name(duthost, port, pg_id_name))
        finally:
            duthost.shell('config interface startup {}'.format(port_to_shutdown), module_ignore_errors=True)

def calculate_headroom_data(duthost, port_to_test):
    """
    This function is intend to calculate the headroom size based on the input port attributes
    Each vendor should have it's own implementation for the algorithm
    """
    if ASIC_TYPE == 'mellanox':
        return mellanox_calculate_headroom_data(duthost, port_to_test)
    else:
        return False, None


def mellanox_calculate_headroom_data(duthost, port_to_test):
    """
    This function is Mellanox platform specific.
    It intends to calculate the headroom size based on the input port attributes(speed, cable_length, number of lanes..., etc)
    This algorithm is the same as the implementation in https://github.com/Azure/sonic-swss/blob/master/cfgmgr/buffer_headroom_mellanox.lua
    """
    global ASIC_TABLE_KEYS_LOADED
    global CELL_SIZE
    global PIPELINE_LATENCY
    global MAC_PHY_DELAY

    global LOSSLESS_TRAFFIC_PATTERN_KEYS_LOADED
    global LOSSLESS_MTU
    global SMALL_PACKET_PERCENTAGE

    over_subscribe_ratio = 0
    peer_response_time = 0
    port_mtu = 0
    gearbox_delay = 0
    is_8lane = False
    shp_enabled = False
    use_default_peer_response_time = False

    head_room_data = {}

    # Init pause_quanta_per_speed_dict
    pause_quanta_per_speed_dict = {400000: 905, 200000: 453, 100000: 394, 50000: 147, 40000: 118, 25000: 80, 10000: 67,
                                   1000: 2, 100: 1}

    # Get effective speed
    # If auto neg is off, effective speed is configured speed
    # elif advertised speeds is configured or supported speeds is fetched
    # effective speed is the maximum speed in the speeds list
    # else the effective speed can not be conducted and the test fail
    port_info = _compose_dict_from_cli(duthost.shell('redis-cli -n 4 hgetall "PORT|{}"'.format(port_to_test))['stdout'].split('\n'))
    if port_info.get('autoneg') == 'on':
        adv_speeds = port_info.get('adv_speeds')
        if adv_speeds and adv_speeds != 'all':
            available_speeds = adv_speeds
        else:
            available_speeds = duthost.shell('redis-cli -n 6 hget "PORT_TABLE|{}" "supported_speeds"'.format(port_to_test))['stdout']
        port_speed_raw = natsorted(available_speeds.split(','))[-1]
    else:
        port_speed_raw = port_info.get('speed')
    if port_speed_raw:
        port_speed = int(port_speed_raw)
    else:
        logging.error("failed to get speed from config db for port {}".format(port_to_test))
        return False, None

    # Get pause_quanta with port speed from pause_quanta_per_speed_dict
    if port_speed in pause_quanta_per_speed_dict.keys():
        pause_quanta = pause_quanta_per_speed_dict[port_speed]
    else:
        # Get default peer response time from State DB
        # Command: redis-cli -n 6 hget "ASIC_TABLE|MELLANOX-SPECTRUM-3" "peer_response_time"
        peer_response_time_keys = duthost.shell('redis-cli -n 6 keys ASIC_TABLE*')['stdout']
        peer_response_time = float(duthost.shell('redis-cli -n 6 hget "{}" "peer_response_time"'.format(peer_response_time_keys))['stdout'])
        use_default_peer_response_time = True

    # Get port mtu from config DB
    # Command: redis-cli -n 4 hget "PORT|Ethernet0" 'mtu'
    port_mtu_raw = duthost.shell('redis-cli -n 4 hget "PORT|{}" "mtu"'.format(port_to_test))['stdout']
    if port_mtu_raw:
        port_mtu = int(port_mtu_raw)
    else:
        logging.error("failed to get MTU from config db for port {}".format(port_to_test))
        return False, None

    # Determine gearbox_delay with platform name, so far only MSN3800 has gear_box installed
    if duthost.facts["platform"] not in ["x86_64-mlnx_msn3800-r0"]:
        gearbox_delay = 0
    else:
        gearbox_delay_keys = duthost.shell('redis-cli -n 6 keys PERIPHERAL_TABLE*')['stdout']
        gearbox_delay = float(duthost.shell('redis-cli -n 6 hget "{}" "gearbox_delay"'.format(gearbox_delay_keys))['stdout'])

    # Get cable length from config DB
    # Command: redis-cli -n 4 hget "CABLE_LENGTH|AZURE"  'Ethernet0'
    cable_length_keys = duthost.shell('redis-cli -n 4 keys *CABLE_LENGTH*')['stdout']
    cable_length_raw = duthost.shell('redis-cli -n 4 hget "{}" "{}"'.format(cable_length_keys, port_to_test))['stdout']
    if cable_length_raw and cable_length_raw.endswith('m'):
        cable_length = float(cable_length_raw[:-1])
    else:
        logging.error("failed to get a valid cable length from config db for port {}".format(port_to_test))
        return False, None

    logging.info('port_speed = {}, port_mtu = {}, cable_length = {}'.format(port_speed, port_mtu, cable_length))

    # Get port lanes number from config DB
    # Command: redis-cli -n 4 hget "PORT|Ethernet0" 'lanes'
    port_lanes = duthost.shell('redis-cli -n 4 hget "PORT|{}" "lanes"'.format(port_to_test))['stdout']
    is_8lane = port_lanes and len(port_lanes.split(',')) == 8

    if not ASIC_TABLE_KEYS_LOADED:
        CELL_SIZE, PIPELINE_LATENCY, MAC_PHY_DELAY = get_asic_table_data_from_db(duthost)

    if not LOSSLESS_TRAFFIC_PATTERN_KEYS_LOADED:
        LOSSLESS_MTU, SMALL_PACKET_PERCENTAGE = get_lossless_traffic_pattern_data_from_db(duthost)

    # Get over_subscribe_ratio from config DB
    # Command: redis-cli -n 4 hget "DEFAULT_LOSSLESS_BUFFER_PARAMETER|AZURE" 'over_subscribe_ratio'
    default_lossless_param_keys = duthost.shell('redis-cli -n 4 keys DEFAULT_LOSSLESS_BUFFER_PARAMETER*')['stdout'][0]
    over_subscribe_ratio_raw = duthost.shell(
        'redis-cli -n 4 hget "{}" "over_subscribe_ratio"'.format(default_lossless_param_keys))['stdout']
    if over_subscribe_ratio_raw:
        over_subscribe_ratio = float(over_subscribe_ratio_raw)
    else:
        over_subscribe_ratio = None

    shp_size_raw = duthost.shell('redis-cli -n 4 hget "BUFFER_POOL|ingress_lossless_pool", "xoff"')['stdout']
    if shp_size_raw:
        shp_size = float(shp_size_raw)
    else:
        shp_size = None

    if (shp_size and shp_size != 0) or (over_subscribe_ratio and over_subscribe_ratio != 0):
        shp_enabled = True

    speed_of_light = 198000000
    minimal_packet_size = 64
    cell_occupancy = 0
    worst_case_factor = 0
    propagation_delay = 0
    bytes_on_cable = 0
    bytes_on_gearbox = 0
    xoff_value = 0
    xon_value = 0
    headroom_size = 0
    speed_overhead = 0
    pipeline_latency = PIPELINE_LATENCY

    if is_8lane:
        pipeline_latency = PIPELINE_LATENCY * 2 - 1024
        speed_overhead = port_mtu
    else:
        speed_overhead = 0

    if CELL_SIZE > 2 * minimal_packet_size:
        worst_case_factor = CELL_SIZE / minimal_packet_size
    else:
        worst_case_factor = (2 * CELL_SIZE) / (1 + CELL_SIZE)

    cell_occupancy = (100 - SMALL_PACKET_PERCENTAGE + SMALL_PACKET_PERCENTAGE * worst_case_factor) / 100

    if gearbox_delay == 0:
        bytes_on_gearbox = 0
    else:
        bytes_on_gearbox = port_speed * gearbox_delay / (8 * 1024)
    logging.debug('gearbox_delay = {}, bytes_on_gearbox = {}'.format(gearbox_delay, bytes_on_gearbox))

    if not use_default_peer_response_time:
        peer_response_time = (float(pause_quanta)) * 512 / (1024 * 8)
    bytes_on_cable = 2 * (float(cable_length)) * port_speed * 1000000000 / speed_of_light / (8 * 1024)
    propagation_delay = port_mtu + bytes_on_cable + 2 * bytes_on_gearbox + MAC_PHY_DELAY + peer_response_time * 1024

    # Calculate the xoff and xon and then round up at 1024 bytes
    xoff_value = LOSSLESS_MTU + propagation_delay * cell_occupancy
    xoff_value = math.ceil(xoff_value / 1024) * 1024
    xon_value = pipeline_latency
    xon_value = math.ceil(xon_value / 1024) * 1024

    if shp_enabled:
        headroom_size = xon_value
    else:
        headroom_size = xoff_value + xon_value + speed_overhead

    headroom_size = math.ceil(headroom_size / 1024) * 1024

    head_room_data['size'] = int(headroom_size)
    head_room_data['xon'] = int(xon_value)
    head_room_data['xoff'] = int(xoff_value)
    return True, head_room_data
