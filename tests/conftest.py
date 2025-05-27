import concurrent.futures
from functools import lru_cache
import os
import json
import logging
import getpass
import random
from concurrent.futures import as_completed
import re
import sys

import pytest
import yaml
import copy
import time
import subprocess
import threading
import pathlib
import importlib

from datetime import datetime
from ipaddress import ip_interface, IPv4Interface
from tests.common.multi_servers_utils import MultiServersUtils
from tests.common.fixtures.conn_graph_facts import conn_graph_facts     # noqa: F401
from tests.common.devices.local import Localhost
from tests.common.devices.ptf import PTFHost
from tests.common.devices.eos import EosHost
from tests.common.devices.sonic import SonicHost
from tests.common.devices.fanout import FanoutHost
from tests.common.devices.k8s import K8sMasterHost
from tests.common.devices.k8s import K8sMasterCluster
from tests.common.devices.duthosts import DutHosts
from tests.common.devices.vmhost import VMHost
from tests.common.devices.base import NeighborDevice
from tests.common.devices.cisco import CiscoHost
from tests.common.fixtures.duthost_utils import backup_and_restore_config_db_session        # noqa: F401
from tests.common.fixtures.ptfhost_utils import ptf_portmap_file                            # noqa: F401
from tests.common.fixtures.ptfhost_utils import ptf_test_port_map_active_active             # noqa: F401
from tests.common.fixtures.ptfhost_utils import run_icmp_responder_session                  # noqa: F401
from tests.common.dualtor.dual_tor_utils import disable_timed_oscillation_active_standby    # noqa: F401

from tests.common.helpers.constants import (
    ASIC_PARAM_TYPE_ALL, ASIC_PARAM_TYPE_FRONTEND, DEFAULT_ASIC_ID, NAMESPACE_PREFIX,
    ASICS_PRESENT, DUT_CHECK_NAMESPACE
)
from tests.common.helpers.custom_msg_utils import add_custom_msg
from tests.common.helpers.dut_ports import encode_dut_port_name
from tests.common.helpers.dut_utils import encode_dut_and_container_name
from tests.common.helpers.parallel_utils import InitialCheckState, InitialCheckStatus
from tests.common.helpers.pfcwd_helper import TrafficPorts, select_test_ports, set_pfc_timers
from tests.common.system_utils import docker
from tests.common.testbed import TestbedInfo
from tests.common.utilities import get_inventory_files, wait_until
from tests.common.utilities import get_host_vars
from tests.common.utilities import get_host_visible_vars
from tests.common.utilities import get_test_server_host
from tests.common.utilities import str2bool
from tests.common.utilities import safe_filename
from tests.common.utilities import get_duts_from_host_pattern
from tests.common.helpers.dut_utils import is_supervisor_node, is_frontend_node, create_duthost_console, creds_on_dut, \
    is_enabled_nat_for_dpu, get_dpu_names_and_ssh_ports, enable_nat_for_dpus, is_macsec_capable_node
from tests.common.cache import FactsCache
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert as pt_assert
from tests.common.helpers.inventory_utils import trim_inventory
from tests.common.utilities import InterruptableThread
from tests.common.plugins.ptfadapter.dummy_testutils import DummyTestUtils
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor

import tests.common.gnmi_setup as gnmi_setup

try:
    from tests.common.macsec import MacsecPluginT2, MacsecPluginT0
except ImportError as e:
    logging.error(e)

from tests.common.platform.args.advanced_reboot_args import add_advanced_reboot_args
from tests.common.platform.args.cont_warm_reboot_args import add_cont_warm_reboot_args
from tests.common.platform.args.normal_reboot_args import add_normal_reboot_args
from ptf import testutils
from ptf.mask import Mask


logger = logging.getLogger(__name__)
cache = FactsCache()

DUTHOSTS_FIXTURE_FAILED_RC = 15
CUSTOM_MSG_PREFIX = "sonic_custom_msg"

pytest_plugins = ('tests.common.plugins.ptfadapter',
                  'tests.common.plugins.ansible_fixtures',
                  'tests.common.plugins.dut_monitor',
                  'tests.common.plugins.loganalyzer',
                  'tests.common.plugins.pdu_controller',
                  'tests.common.plugins.sanity_check',
                  'tests.common.plugins.custom_markers',
                  'tests.common.plugins.test_completeness',
                  'tests.common.plugins.log_section_start',
                  'tests.common.plugins.custom_fixtures',
                  'tests.common.dualtor',
                  'tests.decap',
                  'tests.platform_tests.api',
                  'tests.common.plugins.allure_server',
                  'tests.common.plugins.conditional_mark',
                  'tests.common.plugins.random_seed',
                  'tests.common.plugins.memory_utilization',
                  'tests.common.fixtures.duthost_utils')


def pytest_addoption(parser):
    parser.addoption("--testbed", action="store", default=None, help="testbed name")
    parser.addoption("--testbed_file", action="store", default=None, help="testbed file name")

    # test_vrf options
    parser.addoption("--vrf_capacity", action="store", default=None, type=int, help="vrf capacity of dut (4-1000)")
    parser.addoption("--vrf_test_count", action="store", default=None, type=int,
                     help="number of vrf to be tested (1-997)")

    # qos_sai options
    parser.addoption("--ptf_portmap", action="store", default=None, type=str,
                     help="PTF port index to DUT port alias map")
    parser.addoption("--qos_swap_syncd", action="store", type=str2bool, default=True,
                     help="Swap syncd container with syncd-rpc container")

    # Kubernetes master options
    parser.addoption("--kube_master", action="store", default=None, type=str,
                     help="Name of k8s master group used in k8s inventory, format: k8s_vms{msetnumber}_{servernumber}")

    # neighbor device type
    parser.addoption("--neighbor_type", action="store", default="eos", type=str, choices=["eos", "sonic", "cisco"],
                     help="Neighbor devices type")

    # ceos neighbor lacp multiplier
    parser.addoption("--ceos_neighbor_lacp_multiplier", action="store", default=3, type=int,
                     help="LACP multiplier for ceos neighbors")

    # FWUtil options
    parser.addoption('--fw-pkg', action='store', help='Firmware package file')

    ############################
    # pfc_asym options         #
    ############################
    parser.addoption("--server_ports_num", action="store", default=20, type=int, help="Number of server ports to use")
    parser.addoption("--fanout_inventory", action="store", default="lab", help="Inventory with defined fanout hosts")

    ############################
    # test_techsupport options #
    ############################
    parser.addoption("--loop_num", action="store", default=2, type=int,
                     help="Change default loop range for show techsupport command")
    parser.addoption("--loop_delay", action="store", default=2, type=int,
                     help="Change default loops delay")
    parser.addoption("--logs_since", action="store", type=int,
                     help="number of minutes for show techsupport command")
    parser.addoption("--collect_techsupport", action="store", default=True, type=str2bool,
                     help="Enable/Disable tech support collection. Default is enabled (True)")

    ############################
    #   sanity_check options   #
    ############################
    parser.addoption("--skip_sanity", action="store_true", default=False,
                     help="Skip sanity check")
    parser.addoption("--allow_recover", action="store_true", default=False,
                     help="Allow recovery attempt in sanity check in case of failure")
    parser.addoption("--check_items", action="store", default=False,
                     help="Change (add|remove) check items in the check list")
    parser.addoption("--post_check", action="store_true", default=False,
                     help="Perform post test sanity check if sanity check is enabled")
    parser.addoption("--post_check_items", action="store", default=False,
                     help="Change (add|remove) post test check items based on pre test check items")
    parser.addoption("--recover_method", action="store", default="adaptive",
                     help="Set method to use for recover if sanity failed")

    ########################
    #   pre-test options   #
    ########################
    parser.addoption("--deep_clean", action="store_true", default=False,
                     help="Deep clean DUT before tests (remove old logs, cores, dumps)")
    parser.addoption("--py_saithrift_url", action="store", default=None, type=str,
                     help="Specify the url of the saithrift package to be installed on the ptf "
                          "(should be http://<serverip>/path/python-saithrift_0.9.4_amd64.deb")

    #########################
    #   post-test options   #
    #########################
    parser.addoption("--posttest_show_tech_since", action="store", default="yesterday",
                     help="collect show techsupport since <date>. <date> should be a string which can "
                          "be parsed by bash command 'date --d <date>'. Default value is yesterday. "
                          "To collect all time spans, please use '@0' as the value.")

    ############################
    #  keysight ixanvl options #
    ############################
    parser.addoption("--testnum", action="store", default=None, type=str)
    parser.addoption("--enable-snappi-dynamic-ports", action="store_true", default=False,
                     help="Force to use dynamic port allocation for snappi port selections")

    ##################################
    # advance-reboot,upgrade options #
    ##################################
    add_advanced_reboot_args(parser)
    add_cont_warm_reboot_args(parser)
    add_normal_reboot_args(parser)

    ############################
    #   loop_times options     #
    ############################
    parser.addoption("--loop_times", metavar="LOOP_TIMES", action="store", default=1, type=int,
                     help="Define the loop times of the test")
    ############################
    #   collect logs option    #
    ############################
    parser.addoption("--collect_db_data", action="store_true", default=False, help="Collect db info if test failed")

    ############################
    #   macsec options         #
    ############################
    parser.addoption("--enable_macsec", action="store_true", default=False,
                     help="Enable macsec on some links of testbed")
    parser.addoption("--macsec_profile", action="store", default="all",
                     type=str, help="profile name list in macsec/profile.json")

    ############################
    #   QoS options         #
    ############################
    parser.addoption("--public_docker_registry", action="store_true", default=False,
                     help="To use public docker registry for syncd swap, by default is disabled (False)")

    ##############################
    #   ansible inventory option #
    ##############################
    parser.addoption("--trim_inv", action="store_true", default=False, help="Trim inventory files")

    ##############################
    # gnmi connection options      #
    ##############################
    # The gNMI target port number to connect to the DUT gNMI server.
    parser.addoption("--gnmi_port", action="store", default="8080", type=str,
                     help="gNMI target port number")
    parser.addoption("--gnmi_insecure", action="store_true", default=True,
                     help="Use insecure connection to gNMI target")
    parser.addoption("--disable_sai_validation", action="store_true", default=False,
                     help="Disable SAI validation")
    ############################
    #   Parallel run options   #
    ############################
    parser.addoption("--target_hostname", action="store", default=None, type=str,
                     help="Target hostname to run the test in parallel")
    parser.addoption("--parallel_state_file", action="store", default=None, type=str,
                     help="File to store the state of the parallel run")
    parser.addoption("--is_parallel_leader", action="store_true", default=False, help="Is the parallel leader")
    parser.addoption("--parallel_followers", action="store", default=0, type=int, help="Number of parallel followers")

    ############################
    #   SmartSwitch options    #
    ############################
    parser.addoption("--dpu-pattern", action="store", default="all", help="dpu host name")

    ##################################
    #   Container Upgrade options    #
    ##################################
    parser.addoption("--containers", action="store", default=None, type=str,
                     help="Container bundle to test on each iteration")
    parser.addoption("--os_versions", action="store", default=None, type=str,
                     help="OS Versions to install, one per iteration")
    parser.addoption("--image_url_template", action="store", default=None, type=str,
                     help="Template url to use to download image")
    parser.addoption("--parameters_file", action="store", default=None, type=str,
                     help="File that containers parameters for each container")
    parser.addoption("--testcase_file", action="store", default=None, type=str,
                     help="File that contains testcases to execute per iteration")

    #################################
    #   Stress test options         #
    #################################
    parser.addoption("--run-stress-tests", action="store_true", default=False, help="Run only tests stress tests")


def pytest_configure(config):
    if config.getoption("enable_macsec"):
        topo = config.getoption("topology")
        if topo is not None and "t2" in topo:
            config.pluginmanager.register(MacsecPluginT2())
        else:
            config.pluginmanager.register(MacsecPluginT0())


@pytest.fixture(scope="session", autouse=True)
def enhance_inventory(request, tbinfo):
    """
    This fixture is to enhance the capability of parsing the value of pytest cli argument '--inventory'.
    The pytest-ansible plugin always assumes that the value of cli argument '--inventory' is a single
    inventory file. With this enhancement, we can pass in multiple inventory files using the cli argument
    '--inventory'. The multiple inventory files can be separated by comma ','.

    For example:
        pytest --inventory "inventory1, inventory2" <other arguments>
        pytest --inventory inventory1,inventory2 <other arguments>

    This fixture is automatically applied, you don't need to declare it in your test script.
    """
    inv_opt = request.config.getoption("ansible_inventory")
    if isinstance(inv_opt, list):
        return
    inv_files = [inv_file.strip() for inv_file in inv_opt.split(",")]

    if request.config.getoption("trim_inv"):
        target_hostname = get_target_hostname(request)
        trim_inventory(inv_files, tbinfo, target_hostname)

    try:
        logger.info(f"Inventory file: {inv_files}")
        setattr(request.config.option, "ansible_inventory", inv_files)
    except AttributeError:
        logger.error("Failed to set enhanced 'ansible_inventory' to request.config.option")


def pytest_cmdline_main(config):

    # Filter out unnecessary pytest_ansible plugin log messages
    pytest_ansible_logger = logging.getLogger("pytest_ansible")
    if pytest_ansible_logger:
        pytest_ansible_logger.setLevel(logging.WARNING)

    # Filter out unnecessary ansible log messages (ansible v2.8)
    # The logger name of ansible v2.8 is nasty
    mypid = str(os.getpid())
    user = getpass.getuser()
    ansible_loggerv28 = logging.getLogger("p=%s u=%s | " % (mypid, user))
    if ansible_loggerv28:
        ansible_loggerv28.setLevel(logging.WARNING)

    # Filter out unnecessary ansible log messages (latest ansible)
    ansible_logger = logging.getLogger("ansible")
    if ansible_logger:
        ansible_logger.setLevel(logging.WARNING)

    # Filter out unnecessary logs generated by calling the ptfadapter plugin
    dataplane_logger = logging.getLogger("dataplane")
    if dataplane_logger:
        dataplane_logger.setLevel(logging.ERROR)


def pytest_collection(session):
    """Workaround to reduce messy plugin logs generated during collection only

    Args:
        session (ojb): Pytest session object
    """
    if session.config.option.collectonly:
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.WARNING)


def get_target_hostname(request):
    return request.config.getoption("--target_hostname")


def get_parallel_state_file(request):
    return request.config.getoption("--parallel_state_file")


def is_parallel_run(request):
    return get_target_hostname(request) is not None


def is_parallel_leader(request):
    return request.config.getoption("--is_parallel_leader")


def get_parallel_followers(request):
    return request.config.getoption("--parallel_followers")


def get_tbinfo(request):
    """
    Helper function to create and return testbed information
    """
    tbname = request.config.getoption("--testbed")
    tbfile = request.config.getoption("--testbed_file")
    if tbname is None or tbfile is None:
        raise ValueError("testbed and testbed_file are required!")

    testbedinfo = cache.read(tbname, 'tbinfo')
    if testbedinfo is cache.NOTEXIST:
        testbedinfo = TestbedInfo(tbfile)
        cache.write(tbname, 'tbinfo', testbedinfo)

    return tbname, testbedinfo.testbed_topo.get(tbname, {})


@pytest.fixture(scope="session")
def tbinfo(request):
    """
    Create and return testbed information
    """
    _, testbedinfo = get_tbinfo(request)
    return testbedinfo


@pytest.fixture(scope="session")
def parallel_run_context(request):
    return (
        is_parallel_run(request),
        get_target_hostname(request),
        is_parallel_leader(request),
        get_parallel_followers(request),
        get_parallel_state_file(request),
    )


def get_specified_device_info(request, device_pattern):
    """
    Get a list of device hostnames specified with the --host-pattern or --dpu-pattern CLI option
    """
    tbname, tbinfo = get_tbinfo(request)
    testbed_duts = tbinfo['duts']

    if is_parallel_run(request):
        return [get_target_hostname(request)]

    host_pattern = request.config.getoption(device_pattern)
    if host_pattern == 'all':
        if device_pattern == '--dpu-pattern':
            testbed_duts = [dut for dut in testbed_duts if 'dpu' in dut]
            logger.info(f"dpu duts: {testbed_duts}")
        return testbed_duts
    else:
        specified_duts = get_duts_from_host_pattern(host_pattern)

    if any([dut not in testbed_duts for dut in specified_duts]):
        pytest.fail("One of the specified DUTs {} does not belong to the testbed {}".format(specified_duts, tbname))

    if len(testbed_duts) != specified_duts:
        duts = specified_duts
        logger.debug("Different DUTs specified than in testbed file, using {}"
                     .format(str(duts)))

    return duts


def get_specified_duts(request):
    """
    Get a list of DUT hostnames specified with the --host-pattern CLI option
    or -d if using `run_tests.sh`
    """
    return get_specified_device_info(request, "--host-pattern")


def get_specified_dpus(request):
    """
    Get a list of DUT hostnames specified with the --dpu-pattern CLI option
    """
    return get_specified_device_info(request, "--dpu-pattern")


def pytest_sessionstart(session):
    # reset all the sonic_custom_msg keys from cache
    # reset here because this fixture will always be very first fixture to be called
    cache_dir = session.config.cache._cachedir
    keys = [p.name for p in cache_dir.glob('**/*') if p.is_file() and p.name.startswith(CUSTOM_MSG_PREFIX)]
    for key in keys:
        logger.debug("reset existing key: {}".format(key))
        session.config.cache.set(key, None)

    # Invoke the build-gnmi-stubs.sh script
    script_path = os.path.join(os.path.dirname(__file__), "build-gnmi-stubs.sh")
    base_dir = os.getcwd()  # Use the current working directory as the base directory
    logger.info(f"Invoking {script_path} with base directory: {base_dir}")

    try:
        result = subprocess.run(
            [script_path, base_dir],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False  # Do not raise an exception automatically on non-zero exit
        )
        logger.info(f"Output of {script_path}:\n{result.stdout}")
        # logger.error(f"Error output of {script_path}:\n{result.stderr}")

        if result.returncode != 0:
            logger.error(f"{script_path} failed with exit code {result.returncode}")
            session.exitstatus = 1  # Fail the pytest session
        else:
            # Add the generated directory to sys.path for module imports
            generated_path = os.path.join(base_dir, "common", "sai_validation", "generated")
            if generated_path not in sys.path:
                sys.path.insert(0, generated_path)
                logger.info(f"Added {generated_path} to sys.path")
    except Exception as e:
        logger.error(f"Exception occurred while invoking {script_path}: {e}")
        session.exitstatus = 1  # Fail the pytest session


def pytest_sessionfinish(session, exitstatus):
    if session.config.cache.get("duthosts_fixture_failed", None):
        session.config.cache.set("duthosts_fixture_failed", None)
        session.exitstatus = DUTHOSTS_FIXTURE_FAILED_RC


@pytest.fixture(name="duthosts", scope="session")
def fixture_duthosts(enhance_inventory, ansible_adhoc, tbinfo, request):
    """
    @summary: fixture to get DUT hosts defined in testbed.
    @param enhance_inventory: fixture to enhance the capability of parsing the value of pytest cli argument
    @param ansible_adhoc: Fixture provided by the pytest-ansible package.
        Source of the various device objects. It is
        mandatory argument for the class constructors.
    @param tbinfo: fixture provides information about testbed.
    @param request: pytest request object
    """
    try:
        host = DutHosts(ansible_adhoc, tbinfo, request, get_specified_duts(request),
                        target_hostname=get_target_hostname(request), is_parallel_leader=is_parallel_leader(request))
        return host
    except BaseException as e:
        logger.error("Failed to initialize duthosts.")
        request.config.cache.set("duthosts_fixture_failed", True)
        pt_assert(False, "!!!!!!!!!!!!!!!! duthosts fixture failed !!!!!!!!!!!!!!!!"
                  "Exception: {}".format(repr(e)))


@pytest.fixture(scope="session")
def duthost(duthosts, request):
    '''
    @summary: Shortcut fixture for getting DUT host. For a lengthy test case, test case module can
              pass a request to disable sh time out mechanis on dut in order to avoid ssh timeout.
              After test case completes, the fixture will restore ssh timeout.
    @param duthosts: fixture to get DUT hosts
    @param request: request parameters for duthost test fixture
    '''
    dut_index = getattr(request.session, "dut_index", 0)
    assert dut_index < len(duthosts), \
        "DUT index '{0}' is out of bound '{1}'".format(dut_index,
                                                       len(duthosts))

    duthost = duthosts[dut_index]

    return duthost


@pytest.fixture(scope="session")
def enable_nat_for_dpuhosts(duthosts, ansible_adhoc, request):
    """
    @summary: fixture to enable nat for dpuhost.
    @param duthosts: fixture to get DUT hosts
    @param ansible_adhoc: Fixture provided by the pytest-ansible package.
        Source of the various device objects. It is
        mandatory argument for the class constructors.
    @param request: request parameters for duthost test fixture
    """
    dpuhost_names = get_specified_dpus(request)
    if dpuhost_names:
        logging.info(f"dpuhost_names: {dpuhost_names}")
        for duthost in duthosts:
            if not is_enabled_nat_for_dpu(duthost, request):
                dpu_name_ssh_port_dict = get_dpu_names_and_ssh_ports(duthost, dpuhost_names, ansible_adhoc)
                enable_nat_for_dpus(duthost, dpu_name_ssh_port_dict, request)


@pytest.fixture(name="dpuhosts", scope="session")
def fixture_dpuhosts(enhance_inventory, ansible_adhoc, tbinfo, request, enable_nat_for_dpuhosts):
    """
    @summary: fixture to get DPU hosts defined in testbed.
    @param ansible_adhoc: Fixture provided by the pytest-ansible package.
        Source of the various device objects. It is
        mandatory argument for the class constructors.
    @param tbinfo: fixture provides information about testbed.
    """
    # Before calling dpuhosts, we must enable NAT on NPU.
    # E.g. run sonic-dpu-mgmt-traffic.sh on NPU to enable NAT
    # sonic-dpu-mgmt-traffic.sh inbound -e --dpus all --ports 5021,5022,5023,5024
    try:
        host = DutHosts(ansible_adhoc, tbinfo, request, get_specified_dpus(request),
                        target_hostname=get_target_hostname(request), is_parallel_leader=is_parallel_leader(request))
        return host
    except BaseException as e:
        logger.error("Failed to initialize dpuhosts.")
        request.config.cache.set("dpuhosts_fixture_failed", True)
        pt_assert(False, "!!!!!!!!!!!!!!!! dpuhosts fixture failed !!!!!!!!!!!!!!!!"
                  "Exception: {}".format(repr(e)))


@pytest.fixture(scope="session")
def dpuhost(dpuhosts, request):
    '''
    @summary: Shortcut fixture for getting DPU host. For a lengthy test case, test case module can
              pass a request to disable sh time out mechanis on dut in order to avoid ssh timeout.
              After test case completes, the fixture will restore ssh timeout.
    @param duthosts: fixture to get DPU hosts
    @param request: request parameters for duphost test fixture
    '''
    dpu_index = getattr(request.session, "dpu_index", 0)
    assert dpu_index < len(dpuhosts), \
        "DPU index '{0}' is out of bound '{1}'".format(dpu_index,
                                                       len(dpuhosts))

    duthost = dpuhosts[dpu_index]

    return duthost


@pytest.fixture(scope="session")
def mg_facts(duthost):
    return duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']


@pytest.fixture(scope="session")
def macsec_duthost(duthosts, tbinfo):
    # get the first macsec capable node
    macsec_dut = None
    if 't2' in tbinfo['topo']['name']:
        # currently in the T2 topo only the uplink linecard will have
        # macsec enabled
        for duthost in duthosts:
            if duthost.is_macsec_capable_node():
                macsec_dut = duthost
            break
    else:
        return duthosts[0]
    return macsec_dut


@pytest.fixture(scope="session")
def is_macsec_enabled_for_test(duthosts):
    # If macsec is enabled, use the override option to get macsec profile from golden config
    macsec_en = False
    request = duthosts.request
    if request:
        macsec_en = request.config.getoption("--enable_macsec", default=False)
    return macsec_en


# Make sure in same test module, always use same random DUT
rand_one_dut_hostname_var = None


def set_rand_one_dut_hostname(request):
    global rand_one_dut_hostname_var
    if rand_one_dut_hostname_var is None:
        dut_hostnames = generate_params_dut_hostname(request)
        if len(dut_hostnames) > 1:
            dut_hostnames = random.sample(dut_hostnames, 1)
        rand_one_dut_hostname_var = dut_hostnames[0]
        logger.info("Randomly select dut {} for testing".format(rand_one_dut_hostname_var))


@pytest.fixture(scope="module")
def rand_one_dut_hostname(request):
    """
    """
    global rand_one_dut_hostname_var
    if rand_one_dut_hostname_var is None:
        set_rand_one_dut_hostname(request)
    return rand_one_dut_hostname_var


@pytest.fixture(scope="module")
def rand_selected_dut(duthosts, rand_one_dut_hostname):
    """
    Return the randomly selected duthost
    """
    return duthosts[rand_one_dut_hostname]


@pytest.fixture(scope="module")
def selected_rand_dut(request):
    global rand_one_dut_hostname_var
    if rand_one_dut_hostname_var is None:
        set_rand_one_dut_hostname(request)
    return rand_one_dut_hostname_var


@pytest.fixture(scope="module")
def rand_one_dut_front_end_hostname(request):
    """
    """
    dut_hostnames = generate_params_frontend_hostname(request)
    if len(dut_hostnames) > 1:
        dut_hostnames = random.sample(dut_hostnames, 1)
    logger.info("Randomly select dut {} for testing".format(dut_hostnames[0]))
    return dut_hostnames[0]


@pytest.fixture(scope="module")
def rand_one_tgen_dut_hostname(request, tbinfo, rand_one_dut_front_end_hostname, rand_one_dut_hostname):
    """
    Return the randomly selected duthost for TGEN test cases
    """
    # For T2, we need to skip supervisor, only use linecards.
    if 't2' in tbinfo['topo']['name']:
        return rand_one_dut_front_end_hostname
    return rand_one_dut_hostname


@pytest.fixture(scope="module")
def rand_selected_front_end_dut(duthosts, rand_one_dut_front_end_hostname):
    """
    Return the randomly selected duthost
    """
    return duthosts[rand_one_dut_front_end_hostname]


@pytest.fixture(scope="module")
def rand_unselected_dut(request, duthosts, rand_one_dut_hostname):
    """
    Return the left duthost after random selection.
    Return None for non dualtor testbed
    """
    dut_hostnames = generate_params_dut_hostname(request)
    if len(dut_hostnames) <= 1:
        return None
    idx = dut_hostnames.index(rand_one_dut_hostname)
    return duthosts[dut_hostnames[1 - idx]]


@pytest.fixture(scope="module")
def selected_rand_one_per_hwsku_hostname(request):
    """
    Return the selected hostnames for the given module.
    This fixture will return the list of selected dut hostnames
    when another fixture like enum_rand_one_per_hwsku_hostname
    or enum_rand_one_per_hwsku_frontend_hostname is used.
    """
    if request.module in _hosts_per_hwsku_per_module:
        return _hosts_per_hwsku_per_module[request.module]
    else:
        return []


@pytest.fixture(scope="module")
def rand_one_dut_portname_oper_up(request):
    oper_up_ports = generate_port_lists(request, "oper_up_ports")
    if len(oper_up_ports) > 1:
        oper_up_ports = random.sample(oper_up_ports, 1)
    return oper_up_ports[0]


@pytest.fixture(scope="module")
def rand_one_dut_lossless_prio(request):
    lossless_prio_list = generate_priority_lists(request, 'lossless')
    if len(lossless_prio_list) > 1:
        lossless_prio_list = random.sample(lossless_prio_list, 1)
    return lossless_prio_list[0]


@pytest.fixture(scope="module", autouse=True)
def reset_critical_services_list(duthosts):
    """
    Resets the critical services list between test modules to ensure that it is
    left in a known state after tests finish running.
    """
    [a_dut.critical_services_tracking_list() for a_dut in duthosts]


@pytest.fixture(scope="session")
def localhost(ansible_adhoc):
    return Localhost(ansible_adhoc)


@pytest.fixture(scope="session")
def ptfhost(ptfhosts):
    if not ptfhosts:
        return ptfhosts
    return ptfhosts[0]  # For backward compatibility, this is for single ptfhost testbed.


@pytest.fixture(scope="session")
def ptfhosts(enhance_inventory, ansible_adhoc, tbinfo, duthost, request):
    _hosts = []
    if 'ptp' in tbinfo['topo']['name']:
        return None
    if "ptf_image_name" in tbinfo and "docker-keysight-api-server" in tbinfo["ptf_image_name"]:
        return None
    if "ptf" in tbinfo:
        _hosts.append(PTFHost(ansible_adhoc, tbinfo["ptf"], duthost, tbinfo,
                              macsec_enabled=request.config.option.enable_macsec))
    elif "servers" in tbinfo:
        for server in tbinfo["servers"].values():
            if "ptf" in server and server["ptf"]:
                _host = PTFHost(ansible_adhoc, server["ptf"], duthost, tbinfo,
                                macsec_enabled=request.config.option.enable_macsec)
                _hosts.append(_host)
    else:
        # when no ptf defined in testbed.csv
        # try to parse it from inventory
        ptf_host = duthost.host.options["inventory_manager"].get_host(duthost.hostname).get_vars()["ptf_host"]
        _hosts.apend(PTFHost(ansible_adhoc, ptf_host, duthost, tbinfo,
                             macsec_enabled=request.config.option.enable_macsec))
    return _hosts


@pytest.fixture(scope="module")
def k8smasters(enhance_inventory, ansible_adhoc, request):
    """
    Shortcut fixture for getting Kubernetes master hosts
    """
    k8s_master_ansible_group = request.config.getoption("--kube_master")
    master_vms = {}
    inv_files = request.config.getoption("ansible_inventory")
    k8s_inv_file = None
    for inv_file in inv_files:
        if "k8s" in inv_file:
            k8s_inv_file = inv_file
    if not k8s_inv_file:
        pytest.skip("k8s inventory not found, skipping tests")
    with open('../ansible/{}'.format(k8s_inv_file), 'r') as kinv:
        k8sinventory = yaml.safe_load(kinv)
        for hostname, attributes in list(k8sinventory[k8s_master_ansible_group]['hosts'].items()):
            if 'haproxy' in attributes:
                is_haproxy = True
            else:
                is_haproxy = False
            master_vms[hostname] = {'host': K8sMasterHost(ansible_adhoc,
                                                          hostname,
                                                          is_haproxy)}
    return master_vms


@pytest.fixture(scope="module")
def k8scluster(k8smasters):
    k8s_master_cluster = K8sMasterCluster(k8smasters)
    return k8s_master_cluster


@pytest.fixture(scope="session")
def nbrhosts(enhance_inventory, ansible_adhoc, tbinfo, creds, request):
    """
    Shortcut fixture for getting VM host
    """
    logger.info("Fixture nbrhosts started")
    devices = {}
    if ('vm_base' in tbinfo and not tbinfo['vm_base'] and 'tgen' in tbinfo['topo']['name']) or \
        'ptf' in tbinfo['topo']['name'] or \
            'ixia' in tbinfo['topo']['name']:
        logger.info("No VMs exist for this topology: {}".format(tbinfo['topo']['name']))
        return devices

    neighbor_type = request.config.getoption("--neighbor_type")
    if 'VMs' not in tbinfo['topo']['properties']['topology']:
        logger.info("No VMs exist for this topology: {}".format(tbinfo['topo']['properties']['topology']))
        return devices

    def initial_neighbor(neighbor_name, vm_name):
        logger.info(f"nbrhosts started: {neighbor_name}_{vm_name}")
        if neighbor_type == "eos":
            device = NeighborDevice(
                {
                    'host': EosHost(
                        ansible_adhoc,
                        vm_name,
                        creds['eos_login'],
                        creds['eos_password'],
                        shell_user=creds['eos_root_user'] if 'eos_root_user' in creds else None,
                        shell_passwd=creds['eos_root_password'] if 'eos_root_password' in creds else None
                    ),
                    'conf': tbinfo['topo']['properties']['configuration'][neighbor_name]
                }
            )
        elif neighbor_type == "sonic":
            device = NeighborDevice(
                {
                    'host': SonicHost(
                        ansible_adhoc,
                        vm_name,
                        ssh_user=creds['sonic_login'] if 'sonic_login' in creds else None,
                        ssh_passwd=creds['sonic_password'] if 'sonic_password' in creds else None
                    ),
                    'conf': tbinfo['topo']['properties']['configuration'][neighbor_name]
                }
            )
        elif neighbor_type == "cisco":
            device = NeighborDevice(
                {
                    'host': CiscoHost(
                        ansible_adhoc,
                        vm_name,
                        creds['cisco_login'],
                        creds['cisco_password'],
                    ),
                    'conf': tbinfo['topo']['properties']['configuration'][neighbor_name]
                }
            )
        else:
            raise ValueError("Unknown neighbor type %s" % (neighbor_type,))
        devices[neighbor_name] = device
        logger.info(f"nbrhosts finished: {neighbor_name}_{vm_name}")

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=8)
    futures = []
    servers = []
    if 'servers' in tbinfo:
        servers.extend(tbinfo['servers'].values())
    elif 'server' in tbinfo:
        servers.append(tbinfo)
    else:
        logger.warning("Unknown testbed schema for setup nbrhosts")
    for server in servers:
        vm_base = int(server['vm_base'][2:])
        vm_name_fmt = 'VM%0{}d'.format(len(server['vm_base']) - 2)
        vms = MultiServersUtils.parse_topology_vms(
                tbinfo['topo']['properties']['topology']['VMs'],
                server['dut_interfaces']
            ) if 'dut_interfaces' in server else tbinfo['topo']['properties']['topology']['VMs']
        for neighbor_name, neighbor in vms.items():
            vm_name = vm_name_fmt % (vm_base + neighbor['vm_offset'])
            futures.append(executor.submit(initial_neighbor, neighbor_name, vm_name))

    for future in as_completed(futures):
        # if exception caught in the sub-thread, .result() will raise it in the main thread
        _ = future.result()
    executor.shutdown(wait=True)
    logger.info("Fixture nbrhosts finished")
    return devices


@pytest.fixture(scope="module")
def fanouthosts(enhance_inventory, ansible_adhoc, conn_graph_facts, creds, duthosts):      # noqa: F811
    """
    Shortcut fixture for getting Fanout hosts
    """

    dev_conn = conn_graph_facts.get('device_conn', {})
    fanout_hosts = {}
    # WA for virtual testbed which has no fanout
    for dut_host, value in list(dev_conn.items()):
        duthost = duthosts[dut_host]
        if duthost.facts['platform'] == 'x86_64-kvm_x86_64-r0':
            continue  # skip for kvm platform which has no fanout
        mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
        for dut_port in list(value.keys()):
            fanout_rec = value[dut_port]
            fanout_host = str(fanout_rec['peerdevice'])
            fanout_port = str(fanout_rec['peerport'])

            if fanout_host in list(fanout_hosts.keys()):
                fanout = fanout_hosts[fanout_host]
            else:
                host_vars = ansible_adhoc().options[
                    'inventory_manager'].get_host(fanout_host).vars
                os_type = host_vars.get('os', 'eos')
                if 'fanout_tacacs_user' in creds:
                    fanout_user = creds['fanout_tacacs_user']
                    fanout_password = creds['fanout_tacacs_password']
                elif 'fanout_tacacs_{}_user'.format(os_type) in creds:
                    fanout_user = creds['fanout_tacacs_{}_user'.format(os_type)]
                    fanout_password = creds['fanout_tacacs_{}_password'.format(os_type)]
                elif os_type == 'sonic':
                    fanout_user = creds.get('fanout_sonic_user', None)
                    fanout_password = creds.get('fanout_sonic_password', None)
                elif os_type == 'eos':
                    fanout_user = creds.get('fanout_network_user', None)
                    fanout_password = creds.get('fanout_network_password', None)
                elif os_type == 'onyx':
                    fanout_user = creds.get('fanout_mlnx_user', None)
                    fanout_password = creds.get('fanout_mlnx_password', None)
                elif os_type == 'ixia':
                    # Skip for ixia device which has no fanout
                    continue
                else:
                    # when os is mellanox, not supported
                    pytest.fail("os other than sonic and eos not supported")

                eos_shell_user = None
                eos_shell_password = None
                if os_type == "eos":
                    admin_user = creds['fanout_admin_user']
                    admin_password = creds['fanout_admin_password']
                    eos_shell_user = creds.get('fanout_shell_user', admin_user)
                    eos_shell_password = creds.get('fanout_shell_password', admin_password)

                fanout = FanoutHost(ansible_adhoc,
                                    os_type,
                                    fanout_host,
                                    'FanoutLeaf',
                                    fanout_user,
                                    fanout_password,
                                    eos_shell_user=eos_shell_user,
                                    eos_shell_passwd=eos_shell_password)
                fanout.dut_hostnames = [dut_host]
                fanout_hosts[fanout_host] = fanout

                if fanout.os == 'sonic':
                    ifs_status = fanout.host.get_interfaces_status()
                    for key, interface_info in list(ifs_status.items()):
                        fanout.fanout_port_alias_to_name[interface_info['alias']] = interface_info['interface']
                    logging.info("fanout {} fanout_port_alias_to_name {}"
                                 .format(fanout_host, fanout.fanout_port_alias_to_name))

            fanout.add_port_map(encode_dut_port_name(dut_host, dut_port), fanout_port)

            # Add port name to fanout port mapping port if dut_port is alias.
            if dut_port in mg_facts['minigraph_port_alias_to_name_map']:
                mapped_port = mg_facts['minigraph_port_alias_to_name_map'][dut_port]
                # only add the mapped port which isn't in device_conn ports to avoid overwriting port map wrongly,
                # it happens when an interface has the same name with another alias, for example:
                # Interface     Alias
                # --------------------
                # Ethernet108   Ethernet32
                # Ethernet32    Ethernet13/1
                if mapped_port not in list(value.keys()):
                    fanout.add_port_map(encode_dut_port_name(dut_host, mapped_port), fanout_port)

            if dut_host not in fanout.dut_hostnames:
                fanout.dut_hostnames.append(dut_host)

    return fanout_hosts


@pytest.fixture(scope="session")
def vmhost(vmhosts):
    if not vmhosts:
        return vmhosts
    return vmhosts[0]  # For backward compatibility, this is for single vmhost testbed.


@pytest.fixture(scope="session")
def vmhosts(enhance_inventory, ansible_adhoc, request, tbinfo):
    hosts = []
    inv_files = get_inventory_files(request)
    if 'ptp' in tbinfo['topo']['name']:
        return None
    elif "servers" in tbinfo:
        for server in tbinfo["servers"].keys():
            vmhost = get_test_server_host(inv_files, server)
            hosts.append(VMHost(ansible_adhoc, vmhost.name))
    elif "server" in tbinfo:
        server = tbinfo["server"]
        vmhost = get_test_server_host(inv_files, server)
        hosts.append(VMHost(ansible_adhoc, vmhost.name))
    else:
        logger.info("No VM host exist for this topology: {}".format(tbinfo['topo']['name']))
    return hosts


@pytest.fixture(scope='session')
def eos():
    """ read and yield eos configuration """
    with open('eos/eos.yml') as stream:
        eos = yaml.safe_load(stream)
        return eos


@pytest.fixture(scope='session')
def sonic():
    """ read and yield sonic configuration """
    with open('sonic/sonic.yml') as stream:
        eos = yaml.safe_load(stream)
        return eos


@pytest.fixture(scope='session')
def pdu():
    """ read and yield pdu configuration """
    with open('../ansible/group_vars/pdu/pdu.yml') as stream:
        pdu = yaml.safe_load(stream)
        return pdu


@pytest.fixture(scope="session")
def creds(duthost):
    return creds_on_dut(duthost)


@pytest.fixture(scope='module')
def creds_all_duts(duthosts):
    creds_all_duts = dict()
    for duthost in duthosts.nodes:
        creds_all_duts[duthost.hostname] = creds_on_dut(duthost)
    return creds_all_duts


def update_custom_msg(custom_msg, key, value):
    if custom_msg is None:
        custom_msg = {}
    chunks = key.split('.')
    if chunks[0] == CUSTOM_MSG_PREFIX:
        chunks = chunks[1:]
    if len(chunks) == 1:
        custom_msg.update({chunks[0]: value})
        return custom_msg
    if chunks[0] not in custom_msg:
        custom_msg[chunks[0]] = {}
    custom_msg[chunks[0]] = update_custom_msg(custom_msg[chunks[0]], '.'.join(chunks[1:]), value)
    return custom_msg


def log_custom_msg(item):
    # temp log output to track module name
    logger.debug("[log_custom_msg] item: {}".format(item))

    cache_dir = item.session.config.cache._cachedir
    keys = [p.name for p in cache_dir.glob('**/*') if p.is_file() and p.name.startswith(CUSTOM_MSG_PREFIX)]

    custom_msg = {}
    for key in keys:
        value = item.session.config.cache.get(key, None)
        if value is not None:
            custom_msg = update_custom_msg(custom_msg, key, value)

    if custom_msg:
        logger.debug("append custom_msg: {}".format(custom_msg))
        item.user_properties.append(('CustomMsg', json.dumps(custom_msg)))


# This function is a pytest hook implementation that is called to create a test report.
# By placing the call to log_custom_msg in the 'teardown' phase, we ensure that it is executed
# at the end of each test, after all other fixture teardowns. This guarantees that any custom
# messages are logged at the latest possible stage in the test lifecycle.
@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):

    if call.when == 'setup':
        item.user_properties.append(('start', str(datetime.fromtimestamp(call.start))))
    elif call.when == 'teardown':
        if item.nodeid == item.session.items[-1].nodeid:
            log_custom_msg(item)
        item.user_properties.append(('end', str(datetime.fromtimestamp(call.stop))))

    # Filter out unnecessary logs captured on "stdout" and "stderr"
    item._report_sections = list([report for report in item._report_sections if report[1] not in ("stdout", "stderr")])

    # execute all other hooks to obtain the report object
    outcome = yield
    rep = outcome.get_result()

    # set a report attribute for each phase of a call, which can
    # be "setup", "call", "teardown"

    setattr(item, "rep_" + rep.when, rep)


# This function is a pytest hook implementation that is called in runtest call stage.
# We are using this hook to set ptf.testutils to DummyTestUtils if the test is marked with "skip_traffic_test",
# DummyTestUtils would always return True for all verify function in ptf.testutils.
@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_call(item):
    # See tests/common/plugins/conditional_mark/tests_mark_conditions_skip_traffic_test.yaml
    if "skip_traffic_test" in item.keywords:
        logger.info("Got skip_traffic_test marker, will skip traffic test")
        with DummyTestUtils():
            logger.info("Set ptf.testutils to DummyTestUtils to skip traffic test")
            yield
            logger.info("Reset ptf.testutils")
    else:
        yield


def collect_techsupport_on_dut(request, a_dut):
    # request.node is an "item" because we use the default
    # "function" scope
    testname = request.node.name
    if request.config.getoption("--collect_techsupport") and request.node.rep_call.failed:
        res = a_dut.shell("generate_dump -s \"-2 hours\"")
        fname = res['stdout_lines'][-1]
        a_dut.fetch(src=fname, dest="logs/{}".format(testname))

        logging.info("########### Collected tech support for test {} ###########".format(testname))


@pytest.fixture
def collect_techsupport(request, duthosts, enum_dut_hostname):
    yield
    # request.node is an "item" because we use the default
    # "function" scope
    duthost = duthosts[enum_dut_hostname]
    collect_techsupport_on_dut(request, duthost)


@pytest.fixture
def collect_techsupport_all_duts(request, duthosts):
    yield
    [collect_techsupport_on_dut(request, a_dut) for a_dut in duthosts]


@pytest.fixture
def collect_techsupport_all_nbrs(request, nbrhosts):
    yield
    if request.config.getoption("neighbor_type") == "sonic":
        [collect_techsupport_on_dut(request, nbrhosts[nbrhost]['host']) for nbrhost in nbrhosts]


@pytest.fixture(scope="session", autouse=True)
def tag_test_report(request, pytestconfig, tbinfo, duthost, record_testsuite_property):
    if not request.config.getoption("--junit-xml"):
        return

    # Test run information
    record_testsuite_property("topology", tbinfo["topo"]["name"])
    record_testsuite_property("testbed", tbinfo["conf-name"])
    record_testsuite_property("timestamp", datetime.utcnow())

    # Device information
    record_testsuite_property("host", duthost.hostname)
    record_testsuite_property("asic", duthost.facts["asic_type"])
    record_testsuite_property("platform", duthost.facts["platform"])
    record_testsuite_property("hwsku", duthost.facts["hwsku"])
    record_testsuite_property("os_version", duthost.os_version)


@pytest.fixture(scope="module", autouse=True)
def clear_neigh_entries(duthosts, tbinfo):
    """
        This is a stop bleeding change for dualtor testbed. Because dualtor duts will
        learn the same set of arp entries during tests. But currently the test only
        cleans up on the dut under test. So the other dut will accumulate arp entries
        until kernel start to barf.
        Adding this fixture to flush out IPv4/IPv6 static ARP entries after each test
        moduel is done.
    """

    yield

    if 'dualtor' in tbinfo['topo']['name']:
        for dut in duthosts:
            dut.command("sudo ip neigh flush nud permanent")


@pytest.fixture(scope="module")
def patch_lldpctl():
    def patch_lldpctl(localhost, duthost):
        output = localhost.shell('ansible --version')
        if 'ansible 2.8.12' in output['stdout']:
            """
                Work around a known lldp module bug in ansible version 2.8.12:
                When neighbor sent more than one unknown tlv. Ansible will throw
                exception.
                This function applies the patch before test.
            """
            duthost.shell(
                'sudo sed -i -e \'s/lldp lldpctl "$@"$/lldp lldpctl "$@" | grep -v "unknown-tlvs"/\' /usr/bin/lldpctl'
            )

    return patch_lldpctl


@pytest.fixture(scope="module")
def unpatch_lldpctl():
    def unpatch_lldpctl(localhost, duthost):
        output = localhost.shell('ansible --version')
        if 'ansible 2.8.12' in output['stdout']:
            """
                Work around a known lldp module bug in ansible version 2.8.12:
                When neighbor sent more than one unknown tlv. Ansible will throw
                exception.
                This function removes the patch after the test is done.
            """
            duthost.shell(
                'sudo sed -i -e \'s/lldp lldpctl "$@"$/lldp lldpctl "$@" | grep -v "unknown-tlvs"/\' /usr/bin/lldpctl'
            )

    return unpatch_lldpctl


@pytest.fixture(scope="module")
def disable_container_autorestart():
    def disable_container_autorestart(duthost, testcase="", feature_list=None):
        '''
        @summary: Disable autorestart of the features present in feature_list.

        @param duthosts: Instance of DutHost
        @param testcase: testcase name used to save pretest autorestart state. Later to be used for restoration.
        @feature_list: List of features to disable autorestart. If None, autorestart of all the features will be
                       disabled.
        '''
        command_output = duthost.shell("show feature autorestart", module_ignore_errors=True)
        if command_output['rc'] != 0:
            logging.info("Feature autorestart utility not supported. Error: {}".format(command_output['stderr']))
            logging.info("Skipping disable_container_autorestart")
            return
        container_autorestart_states = duthost.get_container_autorestart_states()
        state_file_name = "/tmp/autorestart_state_{}_{}.json".format(duthost.hostname, testcase)
        # Dump autorestart state to file
        with open(state_file_name, "w") as f:
            json.dump(container_autorestart_states, f)
        # Disable autorestart for all containers
        logging.info("Disable container autorestart")
        cmd_disable = "config feature autorestart {} disabled"
        cmds_disable = []
        for name, state in list(container_autorestart_states.items()):
            if state == "enabled" and (feature_list is None or name in feature_list):
                cmds_disable.append(cmd_disable.format(name))
        # Write into config_db
        cmds_disable.append("config save -y")
        duthost.shell_cmds(cmds=cmds_disable)

    return disable_container_autorestart


@pytest.fixture(scope="module")
def enable_container_autorestart():
    def enable_container_autorestart(duthost, testcase="", feature_list=None):
        '''
        @summary: Enable autorestart of the features present in feature_list.

        @param duthosts: Instance of DutHost
        @param testcase: testcase name used to find corresponding file to restore autorestart state.
        @feature_list: List of features to enable autorestart. If None, autorestart of all the features will
                       be disabled.
        '''
        state_file_name = "/tmp/autorestart_state_{}_{}.json".format(duthost.hostname, testcase)
        if not os.path.exists(state_file_name):
            return
        stored_autorestart_states = {}
        with open(state_file_name, "r") as f:
            stored_autorestart_states = json.load(f)
        container_autorestart_states = duthost.get_container_autorestart_states()
        # Recover autorestart states
        logging.info("Recover container autorestart")
        cmd_enable = "config feature autorestart {} enabled"
        cmds_enable = []
        for name, state in list(container_autorestart_states.items()):
            if state == "disabled" and (feature_list is None or name in feature_list) \
                    and name in stored_autorestart_states \
                    and stored_autorestart_states[name] == "enabled":
                cmds_enable.append(cmd_enable.format(name))
        # Write into config_db
        cmds_enable.append("config save -y")
        duthost.shell_cmds(cmds=cmds_enable)
        os.remove(state_file_name)

    return enable_container_autorestart


@pytest.fixture(scope='module')
def swapSyncd(request, duthosts, enum_rand_one_per_hwsku_frontend_hostname, creds, tbinfo, lower_tor_host):
    """
        Swap syncd on DUT host

        Args:
            request (Fixture): pytest request object
            duthost (AnsibleHost): Device Under Test (DUT)

        Returns:
            None
    """
    if 'dualtor' in tbinfo['topo']['name']:
        duthost = lower_tor_host
    else:
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    swapSyncd = request.config.getoption("--qos_swap_syncd")
    public_docker_reg = request.config.getoption("--public_docker_registry")
    try:
        if swapSyncd:
            if public_docker_reg:
                new_creds = copy.deepcopy(creds)
                new_creds['docker_registry_host'] = new_creds['public_docker_registry_host']
                new_creds['docker_registry_username'] = ''
                new_creds['docker_registry_password'] = ''
            else:
                new_creds = creds
            docker.swap_syncd(duthost, new_creds)

        yield
    finally:
        if swapSyncd:
            docker.restore_default_syncd(duthost, new_creds)


def get_host_data(request, dut):
    '''
    This function parses multple inventory files and returns the dut information present in the inventory
    '''
    inv_files = get_inventory_files(request)
    return get_host_vars(inv_files, dut)


def generate_params_frontend_hostname(request, macsec_only=False):
    frontend_duts = []
    tbname, tbinfo = get_tbinfo(request)
    duts = get_specified_duts(request)
    inv_files = get_inventory_files(request)
    host_type = "frontend"

    if macsec_only:
        host_type = "macsec"
        if 't2' in tbinfo['topo']['name']:
            # currently in the T2 topo only the uplink linecard will have
            # macsec enabled
            for dut in duts:
                if is_frontend_node(inv_files, dut) and is_macsec_capable_node(inv_files, dut):
                    frontend_duts.append(dut)
        else:
            frontend_duts.append(duts[0])
    else:
        for dut in duts:
            if is_frontend_node(inv_files, dut):
                frontend_duts.append(dut)

    assert len(frontend_duts) > 0, \
        "Test selected require at-least one {} node, " \
        "none of the DUTs '{}' in testbed '{}' are a {} node".format(host_type, duts, tbname, host_type)
    return frontend_duts


def generate_params_hostname_rand_per_hwsku(request, frontend_only=False, macsec_only=False):
    hosts = get_specified_duts(request)
    if frontend_only:
        hosts = generate_params_frontend_hostname(request, macsec_only=macsec_only)

    hosts_per_hwsku = get_hosts_per_hwsku(request, hosts)
    return hosts_per_hwsku


def get_hosts_per_hwsku(request, hosts):
    inv_files = get_inventory_files(request)
    # Create a list of hosts per hwsku
    host_hwskus = {}
    for a_host in hosts:
        host_vars = get_host_visible_vars(inv_files, a_host)
        a_host_hwsku = None
        if 'hwsku' in host_vars:
            a_host_hwsku = host_vars['hwsku']
        else:
            # Lets try 'sonic_hwsku' as well
            if 'sonic_hwsku' in host_vars:
                a_host_hwsku = host_vars['sonic_hwsku']
        if a_host_hwsku:
            if a_host_hwsku not in host_hwskus:
                host_hwskus[a_host_hwsku] = [a_host]
            else:
                host_hwskus[a_host_hwsku].append(a_host)
        else:
            pytest.fail("Test selected require a node per hwsku, but 'hwsku' for '{}' not defined in the inventory"
                        .format(a_host))

    hosts_per_hwsku = []
    for hosts in list(host_hwskus.values()):
        if len(hosts) == 1:
            hosts_per_hwsku.append(hosts[0])
        else:
            hosts_per_hwsku.extend(random.sample(hosts, 1))

    return hosts_per_hwsku


def generate_params_supervisor_hostname(request):
    duts = get_specified_duts(request)
    if len(duts) == 1:
        # We have a single node - dealing with pizza box, return it
        return [duts[0]]
    inv_files = get_inventory_files(request)
    for dut in duts:
        # Expecting only a single supervisor node
        if is_supervisor_node(inv_files, dut):
            return [dut]
    # If there are no supervisor cards in a multi-dut tesbed, we are dealing with all pizza box in the testbed,
    # pick the first DUT
    return [duts[0]]


def generate_param_asic_index(request, dut_hostnames, param_type, random_asic=False):
    _, tbinfo = get_tbinfo(request)
    inv_files = get_inventory_files(request)
    logging.info("generating {} asic indicies for  DUT [{}] in ".format(param_type, dut_hostnames))

    asic_index_params = []
    for dut in dut_hostnames:
        inv_data = get_host_visible_vars(inv_files, dut)
        # if the params are not present treat the device as a single asic device
        dut_asic_params = [DEFAULT_ASIC_ID]
        if inv_data:
            if param_type == ASIC_PARAM_TYPE_ALL and ASIC_PARAM_TYPE_ALL in inv_data:
                if int(inv_data[ASIC_PARAM_TYPE_ALL]) == 1:
                    dut_asic_params = [DEFAULT_ASIC_ID]
                else:
                    if ASICS_PRESENT in inv_data:
                        dut_asic_params = inv_data[ASICS_PRESENT]
                    else:
                        dut_asic_params = list(range(int(inv_data[ASIC_PARAM_TYPE_ALL])))
            elif param_type == ASIC_PARAM_TYPE_FRONTEND and ASIC_PARAM_TYPE_FRONTEND in inv_data:
                dut_asic_params = inv_data[ASIC_PARAM_TYPE_FRONTEND]
            logging.info("dut name {}  asics params = {}".format(dut, dut_asic_params))

        if random_asic:
            asic_index_params.append(random.sample(dut_asic_params, 1))
        else:
            asic_index_params.append(dut_asic_params)
    return asic_index_params


def generate_params_dut_index(request):
    tbname, _ = get_tbinfo(request)
    num_duts = len(get_specified_duts(request))
    logging.info("Using {} duts from testbed '{}'".format(num_duts, tbname))

    return list(range(num_duts))


def generate_params_dut_hostname(request):
    tbname, _ = get_tbinfo(request)
    duts = get_specified_duts(request)
    logging.info("Using DUTs {} in testbed '{}'".format(str(duts), tbname))

    return duts


def get_completeness_level_metadata(request):
    completeness_level = request.config.getoption("--completeness_level")
    # if completeness_level is not set or an unknown completeness_level is set
    # return "thorough" to run all test set
    if not completeness_level or completeness_level not in ["debug", "basic", "confident", "thorough"]:
        return "debug"
    return completeness_level


def get_testbed_metadata(request):
    """
    Get the metadata for the testbed name. Return None if tbname is
    not provided, or metadata file not found or metadata does not
    contain tbname
    """
    tbname = request.config.getoption("--testbed")
    if not tbname:
        return None

    folder = 'metadata'
    filepath = os.path.join(folder, tbname + '.json')
    metadata = None

    try:
        with open(filepath, 'r') as yf:
            metadata = json.load(yf)
    except IOError:
        return None

    return metadata.get(tbname)


def get_snappi_testbed_metadata(request):
    """
    Get the metadata for the testbed name. Return None if tbname is
    not provided, or metadata file not found or metadata does not
    contain tbname
    """
    tbname = request.config.getoption("--testbed")
    if not tbname:
        return None

    folder = 'metadata/snappi_tests'
    filepath = os.path.join(folder, tbname + '.json')
    metadata = None

    try:
        with open(filepath, 'r') as yf:
            metadata = json.load(yf)
    except IOError:
        return None

    return metadata.get(tbname)


def generate_port_lists(request, port_scope, with_completeness_level=False):
    empty = [encode_dut_port_name('unknown', 'unknown')]
    if 'ports' in port_scope:
        scope = 'Ethernet'
    elif 'pcs' in port_scope:
        scope = 'PortChannel'
    else:
        return empty

    if 'all' in port_scope:
        state = None
    elif 'oper_up' in port_scope:
        state = 'oper_state'
    elif 'admin_up' in port_scope:
        state = 'admin_state'
    else:
        return empty

    dut_ports = get_testbed_metadata(request)

    if dut_ports is None:
        return empty

    dut_port_map = {}
    for dut, val in list(dut_ports.items()):
        dut_port_pairs = []
        if 'intf_status' not in val:
            continue
        for intf, status in list(val['intf_status'].items()):
            if scope in intf and (not state or status[state] == 'up'):
                dut_port_pairs.append(encode_dut_port_name(dut, intf))
        dut_port_map[dut] = dut_port_pairs
    logger.info("Generate dut_port_map: {}".format(dut_port_map))

    if with_completeness_level:
        completeness_level = get_completeness_level_metadata(request)
        # if completeness_level in ["debug", "basic", "confident"],
        # only select several ports on every DUT to save test time

        def trim_dut_port_lists(dut_port_list, target_len):
            if len(dut_port_list) <= target_len:
                return dut_port_list
            # for diversity, fetch the ports from both the start and the end of the original list
            pos_1 = target_len // 2
            pos_2 = target_len - pos_1
            return dut_ports[:pos_1] + dut_ports[-pos_2:]

        if completeness_level in ["debug"]:
            for dut, dut_ports in list(dut_port_map.items()):
                dut_port_map[dut] = trim_dut_port_lists(dut_ports, 1)
        elif completeness_level in ["basic", "confident"]:
            for dut, dut_ports in list(dut_port_map.items()):
                dut_port_map[dut] = trim_dut_port_lists(dut_ports, 4)

    ret = sum(list(dut_port_map.values()), [])
    logger.info("Generate port_list: {}".format(ret))
    return ret if ret else empty


def generate_dut_feature_container_list(request):
    """
    Generate list of containers given the list of features.
    List of features and container names are both obtained from
    metadata file
    """
    empty = [encode_dut_and_container_name("unknown", "unknown")]

    meta = get_testbed_metadata(request)

    if meta is None:
        return empty

    container_list = []

    for dut, val in list(meta.items()):
        if "features" not in val:
            continue
        for feature in list(val["features"].keys()):
            if "disabled" in val["features"][feature]:
                continue

            dut_info = meta[dut]

            if "asic_services" in dut_info and dut_info["asic_services"].get(feature) is not None:
                for service in dut_info["asic_services"].get(feature):
                    container_list.append(encode_dut_and_container_name(dut, service))
            else:
                container_list.append(encode_dut_and_container_name(dut, feature))

    return container_list


def generate_dut_feature_list(request, duts_selected, asics_selected):
    """
    Generate a list of features.
    The list of features willl be obtained from
    metadata file.
    This list will be features that can be stopped
    or restarted.
    """
    meta = get_testbed_metadata(request)
    tuple_list = []

    if meta is None:
        return tuple_list

    skip_feature_list = ['database', 'database-chassis', 'gbsyncd']

    for a_dut_index, a_dut in enumerate(duts_selected):
        if len(asics_selected):
            for a_asic in asics_selected[a_dut_index]:
                # Create tuple of dut and asic index
                if "features" in meta[a_dut]:
                    for a_feature in list(meta[a_dut]["features"].keys()):
                        if a_feature not in skip_feature_list:
                            tuple_list.append((a_dut, a_asic, a_feature))
                else:
                    tuple_list.append((a_dut, a_asic, None))
        else:
            if "features" in meta[a_dut]:
                for a_feature in list(meta[a_dut]["features"].keys()):
                    if a_feature not in skip_feature_list:
                        tuple_list.append((a_dut, None, a_feature))
            else:
                tuple_list.append((a_dut, None, None))
    return tuple_list


def generate_dut_backend_asics(request, duts_selected):
    dut_asic_list = []

    metadata = get_testbed_metadata(request)

    if metadata is None:
        return [[None]]*len(duts_selected)

    for dut in duts_selected:
        mdata = metadata.get(dut)
        if mdata is None:
            dut_asic_list.append([None])
        dut_asic_list.append(mdata.get("backend_asics", [None]))

    return dut_asic_list


def generate_priority_lists(request, prio_scope, with_completeness_level=False, one_dut_only=False):
    empty = []

    tbname = request.config.getoption("--testbed")
    if not tbname:
        return empty

    folder = 'priority'
    filepath = os.path.join(folder, tbname + '-' + prio_scope + '.json')

    try:
        with open(filepath, 'r') as yf:
            info = json.load(yf)
    except IOError:
        return empty

    if tbname not in info:
        return empty

    dut_prio = info[tbname]
    ret = []

    for dut, priorities in list(dut_prio.items()):
        for p in priorities:
            ret.append('{}|{}'.format(dut, p))

        if one_dut_only:
            break

    if with_completeness_level:
        completeness_level = get_completeness_level_metadata(request)
        # if completeness_level in ["debug", "basic", "confident"],
        # select a small subnet to save test time
        # if completeness_level in ["debug"], only select one item
        # if completeness_level in ["basic", "confident"], select 1 priority per DUT

        if completeness_level in ["debug"] and ret:
            ret = random.sample(ret, 1)
        elif completeness_level in ["basic", "confident"]:
            ret = []
            for dut, priorities in list(dut_prio.items()):
                if priorities:
                    p = random.choice(priorities)
                    ret.append('{}|{}'.format(dut, p))

                if one_dut_only:
                    break

    return ret if ret else empty


def pfc_pause_delay_test_params(request):
    empty = []

    tbname = request.config.getoption("--testbed")
    if not tbname:
        return empty

    folder = 'pfc_headroom_test_params'
    filepath = os.path.join(folder, tbname + '.json')

    try:
        with open(filepath, 'r') as yf:
            info = json.load(yf)
    except IOError:
        return empty

    if tbname not in info:
        return empty

    dut_pfc_delay_params = info[tbname]
    ret = []

    for dut, pfc_pause_delay_params in list(dut_pfc_delay_params.items()):
        for pfc_delay, headroom_result in list(pfc_pause_delay_params.items()):
            ret.append('{}|{}|{}'.format(dut, pfc_delay, headroom_result))

    return ret if ret else empty


_frontend_hosts_per_hwsku_per_module = {}
_hosts_per_hwsku_per_module = {}
_rand_one_asic_per_module = {}
_rand_one_frontend_asic_per_module = {}
_macsec_frontend_hosts_per_hwsku_per_module = {}
def pytest_generate_tests(metafunc):        # noqa: E302
    # The topology always has atleast 1 dut
    dut_fixture_name = None
    duts_selected = None
    global _frontend_hosts_per_hwsku_per_module, _hosts_per_hwsku_per_module
    global _macsec_frontend_hosts_per_hwsku_per_module
    global _rand_one_asic_per_module, _rand_one_frontend_asic_per_module
    # Enumerators for duts are mutually exclusive
    target_hostname = get_target_hostname(metafunc)
    if target_hostname:
        duts_selected = [target_hostname]
        if "enum_dut_hostname" in metafunc.fixturenames:
            dut_fixture_name = "enum_dut_hostname"
        elif "enum_supervisor_dut_hostname" in metafunc.fixturenames:
            dut_fixture_name = "enum_supervisor_dut_hostname"
        elif "enum_frontend_dut_hostname" in metafunc.fixturenames:
            dut_fixture_name = "enum_frontend_dut_hostname"
        elif "enum_rand_one_per_hwsku_hostname" in metafunc.fixturenames:
            if metafunc.module not in _hosts_per_hwsku_per_module:
                _hosts_per_hwsku_per_module[metafunc.module] = duts_selected

            dut_fixture_name = "enum_rand_one_per_hwsku_hostname"
        elif "enum_rand_one_per_hwsku_frontend_hostname" in metafunc.fixturenames:
            if metafunc.module not in _frontend_hosts_per_hwsku_per_module:
                _frontend_hosts_per_hwsku_per_module[metafunc.module] = duts_selected

            dut_fixture_name = "enum_rand_one_per_hwsku_frontend_hostname"
        elif "enum_rand_one_per_hwsku_macsec_frontend_hostname" in metafunc.fixturenames:
            if metafunc.module not in _macsec_frontend_hosts_per_hwsku_per_module:
                _macsec_frontend_hosts_per_hwsku_per_module[metafunc.module] = duts_selected
            dut_fixture_name = "enum_rand_one_per_hwsku_macsec_frontend_hostname"
    else:
        if "enum_dut_hostname" in metafunc.fixturenames:
            duts_selected = generate_params_dut_hostname(metafunc)
            dut_fixture_name = "enum_dut_hostname"
        elif "enum_supervisor_dut_hostname" in metafunc.fixturenames:
            duts_selected = generate_params_supervisor_hostname(metafunc)
            dut_fixture_name = "enum_supervisor_dut_hostname"
        elif "enum_frontend_dut_hostname" in metafunc.fixturenames:
            duts_selected = generate_params_frontend_hostname(metafunc)
            dut_fixture_name = "enum_frontend_dut_hostname"
        elif "enum_rand_one_per_hwsku_hostname" in metafunc.fixturenames:
            if metafunc.module not in _hosts_per_hwsku_per_module:
                hosts_per_hwsku = generate_params_hostname_rand_per_hwsku(metafunc)
                _hosts_per_hwsku_per_module[metafunc.module] = hosts_per_hwsku
            duts_selected = _hosts_per_hwsku_per_module[metafunc.module]
            dut_fixture_name = "enum_rand_one_per_hwsku_hostname"
        elif "enum_rand_one_per_hwsku_frontend_hostname" in metafunc.fixturenames:
            if metafunc.module not in _frontend_hosts_per_hwsku_per_module:
                hosts_per_hwsku = generate_params_hostname_rand_per_hwsku(metafunc, frontend_only=True)
                _frontend_hosts_per_hwsku_per_module[metafunc.module] = hosts_per_hwsku
            duts_selected = _frontend_hosts_per_hwsku_per_module[metafunc.module]
            dut_fixture_name = "enum_rand_one_per_hwsku_frontend_hostname"
        elif "enum_rand_one_per_hwsku_macsec_frontend_hostname" in metafunc.fixturenames:
            if metafunc.module not in _macsec_frontend_hosts_per_hwsku_per_module:
                hosts_per_hwsku = generate_params_hostname_rand_per_hwsku(
                    metafunc, frontend_only=True, macsec_only=True
                )
                _macsec_frontend_hosts_per_hwsku_per_module[metafunc.module] = hosts_per_hwsku
            duts_selected = _macsec_frontend_hosts_per_hwsku_per_module[metafunc.module]
            dut_fixture_name = "enum_rand_one_per_hwsku_macsec_frontend_hostname"

    asics_selected = None
    asic_fixture_name = None

    tbname, tbinfo = get_tbinfo(metafunc)
    if duts_selected is None:
        duts_selected = [tbinfo["duts"][0]]

    possible_asic_enums = ["enum_asic_index", "enum_frontend_asic_index", "enum_backend_asic_index",
                           "enum_rand_one_asic_index", "enum_rand_one_frontend_asic_index"]
    enums_asic_fixtures = set(metafunc.fixturenames).intersection(possible_asic_enums)
    assert len(enums_asic_fixtures) < 2, \
        "The number of asic_enum fixtures should be 1 or zero, " \
        "the following fixtures conflict one with each other: {}".format(str(enums_asic_fixtures))

    if "enum_asic_index" in metafunc.fixturenames:
        asic_fixture_name = "enum_asic_index"
        asics_selected = generate_param_asic_index(metafunc, duts_selected, ASIC_PARAM_TYPE_ALL)
    elif "enum_frontend_asic_index" in metafunc.fixturenames:
        asic_fixture_name = "enum_frontend_asic_index"
        asics_selected = generate_param_asic_index(metafunc, duts_selected, ASIC_PARAM_TYPE_FRONTEND)
    elif "enum_backend_asic_index" in metafunc.fixturenames:
        asic_fixture_name = "enum_backend_asic_index"
        asics_selected = generate_dut_backend_asics(metafunc, duts_selected)
    elif "enum_rand_one_asic_index" in metafunc.fixturenames:
        asic_fixture_name = "enum_rand_one_asic_index"
        if metafunc.module not in _rand_one_asic_per_module:
            asics_selected = generate_param_asic_index(metafunc, duts_selected,
                                                       ASIC_PARAM_TYPE_ALL, random_asic=True)
            _rand_one_asic_per_module[metafunc.module] = asics_selected
        asics_selected = _rand_one_asic_per_module[metafunc.module]
    elif "enum_rand_one_frontend_asic_index" in metafunc.fixturenames:
        asic_fixture_name = "enum_rand_one_frontend_asic_index"
        if metafunc.module not in _rand_one_frontend_asic_per_module:
            asics_selected = generate_param_asic_index(metafunc, duts_selected,
                                                       ASIC_PARAM_TYPE_FRONTEND, random_asic=True)
            _rand_one_frontend_asic_per_module[metafunc.module] = asics_selected
        asics_selected = _rand_one_frontend_asic_per_module[metafunc.module]

    # Create parameterization tuple of dut_fixture_name, asic_fixture_name and feature to parameterize
    if dut_fixture_name and asic_fixture_name and ("enum_dut_feature" in metafunc.fixturenames):
        tuple_list = generate_dut_feature_list(metafunc, duts_selected, asics_selected)
        feature_fixture = "enum_dut_feature"
        metafunc.parametrize(dut_fixture_name + "," + asic_fixture_name + "," + feature_fixture,
                             tuple_list, scope="module", indirect=True)
    # Create parameterization tuple of dut_fixture_name and asic_fixture_name to parameterize
    elif dut_fixture_name and asic_fixture_name:
        # parameterize on both - create tuple for each
        tuple_list = []
        for a_dut_index, a_dut in enumerate(duts_selected):
            if len(asics_selected):
                for a_asic in asics_selected[a_dut_index]:
                    # Create tuple of dut and asic index
                    tuple_list.append((a_dut, a_asic))
            else:
                tuple_list.append((a_dut, None))
        metafunc.parametrize(dut_fixture_name + "," + asic_fixture_name, tuple_list, scope="module", indirect=True)
    elif dut_fixture_name:
        # parameterize only on DUT
        metafunc.parametrize(dut_fixture_name, duts_selected, scope="module", indirect=True)
    elif asic_fixture_name:
        # We have no duts selected, so need asic list for the first DUT
        if len(asics_selected):
            metafunc.parametrize(asic_fixture_name, asics_selected[0], scope="module", indirect=True)
        else:
            metafunc.parametrize(asic_fixture_name, [None], scope="module", indirect=True)

    # When selected_dut used and select a dut for test, parameterize dut for enable TACACS on all UT
    if dut_fixture_name and "selected_dut" in metafunc.fixturenames:
        metafunc.parametrize("selected_dut", duts_selected, scope="module", indirect=True)

    if "enum_dut_portname" in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_portname", generate_port_lists(metafunc, "all_ports"))

    def format_portautoneg_test_id(param):
        speeds = param['speeds'] if 'speeds' in param else [param['speed']]
        return "{}|{}|{}".format(param['dutname'], param['port'], ','.join(speeds))

    if "enum_dut_portname_module_fixture" in metafunc.fixturenames or \
            "enum_speed_per_dutport_fixture" in metafunc.fixturenames:
        autoneg_tests_data = get_autoneg_tests_data()
        if "enum_dut_portname_module_fixture" in metafunc.fixturenames:
            metafunc.parametrize(
                "enum_dut_portname_module_fixture",
                autoneg_tests_data,
                scope="module",
                ids=format_portautoneg_test_id,
                indirect=True
            )

        if "enum_speed_per_dutport_fixture" in metafunc.fixturenames:
            metafunc.parametrize(
                "enum_speed_per_dutport_fixture",
                parametrise_per_supported_port_speed(autoneg_tests_data),
                scope="module",
                ids=format_portautoneg_test_id,
                indirect=True
            )

    if "enum_dut_portname_oper_up" in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_portname_oper_up", generate_port_lists(metafunc, "oper_up_ports"))
    if "enum_dut_portname_admin_up" in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_portname_admin_up", generate_port_lists(metafunc, "admin_up_ports"))
    if "enum_dut_portchannel" in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_portchannel", generate_port_lists(metafunc, "all_pcs"))
    if "enum_dut_portchannel_oper_up" in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_portchannel_oper_up", generate_port_lists(metafunc, "oper_up_pcs"))
    if "enum_dut_portchannel_admin_up" in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_portchannel_admin_up", generate_port_lists(metafunc, "admin_up_pcs"))
    if "enum_dut_portchannel_with_completeness_level" in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_portchannel_with_completeness_level",
                             generate_port_lists(metafunc, "all_pcs", with_completeness_level=True))
    if "enum_dut_feature_container" in metafunc.fixturenames:
        metafunc.parametrize(
            "enum_dut_feature_container", generate_dut_feature_container_list(metafunc)
        )
    if 'enum_dut_all_prio' in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_all_prio", generate_priority_lists(metafunc, 'all'))
    if 'enum_dut_lossless_prio' in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_lossless_prio", generate_priority_lists(metafunc, 'lossless'))
    if 'enum_one_dut_lossless_prio' in metafunc.fixturenames:
        metafunc.parametrize("enum_one_dut_lossless_prio",
                             generate_priority_lists(metafunc, 'lossless', one_dut_only=True))
    if 'enum_dut_lossless_prio_with_completeness_level' in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_lossless_prio_with_completeness_level",
                             generate_priority_lists(metafunc, 'lossless', with_completeness_level=True))
    if 'enum_one_dut_lossless_prio_with_completeness_level' in metafunc.fixturenames:
        metafunc.parametrize("enum_one_dut_lossless_prio_with_completeness_level",
                             generate_priority_lists(metafunc, 'lossless', with_completeness_level=True,
                                                     one_dut_only=True))
    if 'enum_dut_lossy_prio' in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_lossy_prio", generate_priority_lists(metafunc, 'lossy'))
    if 'enum_one_dut_lossy_prio' in metafunc.fixturenames:
        metafunc.parametrize("enum_one_dut_lossy_prio",
                             generate_priority_lists(metafunc, 'lossy', one_dut_only=True))
    if 'enum_dut_lossy_prio_with_completeness_level' in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_lossy_prio_with_completeness_level",
                             generate_priority_lists(metafunc, 'lossy', with_completeness_level=True))
    if 'enum_one_dut_lossy_prio_with_completeness_level' in metafunc.fixturenames:
        metafunc.parametrize("enum_one_dut_lossy_prio_with_completeness_level",
                             generate_priority_lists(metafunc, 'lossy', with_completeness_level=True,
                                                     one_dut_only=True))
    if 'enum_pfc_pause_delay_test_params' in metafunc.fixturenames:
        metafunc.parametrize("enum_pfc_pause_delay_test_params", pfc_pause_delay_test_params(metafunc))

    if 'topo_scenario' in metafunc.fixturenames:
        if tbinfo['topo']['type'] == 'm0' and 'topo_scenario' in metafunc.fixturenames:
            metafunc.parametrize('topo_scenario', ['m0_vlan_scenario', 'm0_l3_scenario'], scope='module')
        else:
            metafunc.parametrize('topo_scenario', ['default'], scope='module')

    if 'tgen_port_info' in metafunc.fixturenames:
        metafunc.parametrize('tgen_port_info', generate_skeleton_port_info(metafunc), indirect=True)

    if 'vlan_name' in metafunc.fixturenames:
        if tbinfo['topo']['type'] == 'm0' and 'topo_scenario' in metafunc.fixturenames:
            if tbinfo['topo']['name'] == 'm0-2vlan':
                metafunc.parametrize('vlan_name', ['Vlan1000', 'Vlan2000'], scope='module')
            else:
                metafunc.parametrize('vlan_name', ['Vlan1000'], scope='module')
        # Non M0 topo
        else:
            try:
                if tbinfo["topo"]["type"] in ["t0", "mx"]:
                    default_vlan_config = tbinfo["topo"]["properties"]["topology"][
                        "DUT"
                    ]["vlan_configs"]["default_vlan_config"]
                    if default_vlan_config == "two_vlan_a":
                        logger.info("default_vlan_config is two_vlan_a")
                        vlan_list = list(
                            tbinfo["topo"]["properties"]["topology"]["DUT"][
                                "vlan_configs"
                            ]["two_vlan_a"].keys()
                        )
                    elif default_vlan_config == "one_vlan_a":
                        logger.info("default_vlan_config is one_vlan_a")
                        vlan_list = list(
                            tbinfo["topo"]["properties"]["topology"]["DUT"][
                                "vlan_configs"
                            ]["one_vlan_a"].keys()
                        )
                    else:
                        vlan_list = ["Vlan1000"]
                    logger.info("parametrize vlan_name: {}".format(vlan_list))
                    metafunc.parametrize("vlan_name", vlan_list, scope="module")
                else:
                    metafunc.parametrize("vlan_name", ["no_vlan"], scope="module")
            except KeyError:
                logger.error("topo {} keys are missing in the tbinfo={}".format(tbinfo['topo']['name'], tbinfo))
                if tbinfo['topo']['type'] in ['t0', 'mx']:
                    metafunc.parametrize('vlan_name', ['Vlan1000'], scope='module')
                else:
                    metafunc.parametrize('vlan_name', ['no_vlan'], scope='module')


@lru_cache
def parse_override(testbed, field):
    is_dynamic_only = "--enable-snappi-dynamic-ports" in sys.argv

    if is_dynamic_only and field != "pfcQueueGroupSize":
        # Args "--enable-snappi-dynamic-ports" should not affect field `pfcQueueGroupSize`
        return False, None

    override_file = "snappi_tests/variables.override.yml"

    with open(override_file, 'r') as f:
        all_values = yaml.safe_load(f)
        if testbed not in all_values or field not in all_values[testbed]:
            return False, None

        return True, all_values[testbed][field]

    return False, None


def generate_skeleton_port_info(request):
    """
    Return minimal port_info parameters to populate later in the format of <speed>-<category>. i.e

    ["400.0-single_linecard_single_asic", "400.0-multiple_linecard_multiple_asic",...]
    """
    is_override, override_data = parse_override(
        request.config.getoption("--testbed"),
        'multidut_port_info'
    )

    if is_override:
        return override_data

    dut_info = get_snappi_testbed_metadata(request) or []
    available_interfaces = {}
    matrix = {}
    for index, linecard in enumerate(dut_info):
        interface_to_asic = {}
        for asic in dut_info[linecard]["asic_to_interface"]:
            for interface in dut_info[linecard]["asic_to_interface"][asic]:
                interface_to_asic[interface] = asic

        available_interfaces[linecard] = [dut_info[linecard]['intf_status'][interface]
                                          for interface in dut_info[linecard]['intf_status']
                                          if dut_info[linecard]['intf_status'][interface]["admin_state"] == "up"]

        for interface in available_interfaces[linecard]:
            for key, value in dut_info[linecard]["asic_to_interface"].items():
                if interface['name'] in value:
                    interface['asic'] = key

        for interface in available_interfaces[linecard]:
            speed = float(re.match(r"([\d.]+)", interface['speed']).group(0))
            asic = interface['asic']
            if (speed not in matrix):
                matrix[speed] = {}
            if (linecard not in matrix[speed]):
                matrix[speed][linecard] = {}
            if (asic not in matrix[speed][linecard]):
                matrix[speed][linecard][asic] = 1
            else:
                matrix[speed][linecard][asic] += 1

    def build_params(speed, category):
        return f"{speed}-{category}"

    flattened_list = set()

    for speed, linecards in matrix.items():
        if len(linecards) >= 2:
            flattened_list.add(build_params(speed, 'multiple_linecard_multiple_asic'))

        for linecard, asic_list in linecards.items():
            if len(asic_list) >= 2:
                flattened_list.add(build_params(speed, 'single_linecard_multiple_asic'))

            for asics, port_count in asic_list.items():
                if int(port_count) >= 2:
                    flattened_list.add(build_params(speed, 'single_linecard_single_asic'))

    return list(flattened_list)


def get_autoneg_tests_data():
    folder = 'metadata'
    filepath = os.path.join(folder, 'autoneg-test-params.json')
    if not os.path.exists(filepath):
        logger.warning('Autoneg tests datafile is missing: {}. " \
            "Run test_pretest -k test_update_testbed_metadata to create it'.format(filepath))
        return [{'dutname': 'unknown', 'port': 'unknown', 'speeds': ['unknown']}]
    data = {}
    with open(filepath) as yf:
        data = json.load(yf)

    return [
        {'dutname': dutname, 'port': dutport, 'speeds': portinfo['common_port_speeds']}
        for dutname, ports in list(data.items())
        for dutport, portinfo in list(ports.items())
    ]


def parametrise_per_supported_port_speed(data):
    return [
        {'dutname': conn_info['dutname'], 'port': conn_info['port'], 'speed': speed}
        for conn_info in data for speed in conn_info['speeds']
    ]


# Override enum fixtures for duts and asics to ensure that parametrization happens once per module.
@pytest.fixture(scope="module")
def enum_dut_hostname(request):
    return request.param


@pytest.fixture(scope="module")
def enum_supervisor_dut_hostname(request):
    return request.param


@pytest.fixture(scope="module")
def enum_frontend_dut_hostname(request):
    return request.param


@pytest.fixture(scope="module")
def selected_dut(request):
    try:
        logger.debug("selected_dut host: {}".format(request.param))
        return request.param
    except AttributeError:
        return None


@pytest.fixture(scope="module")
def enum_rand_one_per_hwsku_hostname(request):
    return request.param


@pytest.fixture(scope="module")
def enum_rand_one_per_hwsku_frontend_hostname(request):
    return request.param


@pytest.fixture(scope="module")
def enum_rand_one_per_hwsku_macsec_frontend_hostname(request):
    return request.param


@pytest.fixture(scope="module")
def enum_asic_index(request):
    return request.param


@pytest.fixture(scope="module")
def enum_frontend_asic_index(request):
    return request.param


@pytest.fixture(scope="module")
def enum_backend_asic_index(request):
    return request.param


@pytest.fixture(scope="module")
def enum_rand_one_asic_index(request):
    return request.param


@pytest.fixture(scope="module")
def enum_dut_feature(request):
    return request.param


@pytest.fixture(scope="module")
def enum_rand_one_frontend_asic_index(request):
    return request.param


@pytest.fixture(scope='module')
def enum_upstream_dut_hostname(duthosts, tbinfo):
    if tbinfo["topo"]["type"] == "m0":
        upstream_nbr_type = "M1"
    elif tbinfo["topo"]["type"] == "mx":
        upstream_nbr_type = "M0"
    elif tbinfo["topo"]["type"] == "t0":
        upstream_nbr_type = "T1"
    elif tbinfo["topo"]["type"] == "t1":
        upstream_nbr_type = "T2"
    else:
        upstream_nbr_type = "T3"

    for a_dut in duthosts.frontend_nodes:
        minigraph_facts = a_dut.get_extended_minigraph_facts(tbinfo)
        minigraph_neighbors = minigraph_facts['minigraph_neighbors']
        for key, value in minigraph_neighbors.items():
            if upstream_nbr_type in value['name']:
                return a_dut.hostname

    pytest.fail("Did not find a dut in duthosts that for topo type {} that has upstream nbr type {}".
                format(tbinfo["topo"]["type"], upstream_nbr_type))


@pytest.fixture(scope="module")
def duthost_console(duthosts, enum_supervisor_dut_hostname, localhost, conn_graph_facts, creds):   # noqa: F811
    duthost = duthosts[enum_supervisor_dut_hostname]
    host = create_duthost_console(duthost, localhost, conn_graph_facts, creds)

    yield host
    host.disconnect()


@pytest.fixture(scope='session')
def cleanup_cache_for_session(request):
    """
    This fixture allows developers to cleanup the cached data for all DUTs in the testbed before test.
    Use cases:
      - Running tests where some 'facts' about the DUT that get cached are changed.
      - Running tests/regression without running test_pretest which has a test to clean up cache (PR#2978)
      - Test case development phase to work out testbed information changes.

    This fixture is not automatically applied, if you want to use it, you have to add a call to it in your tests.
    """
    tbname, tbinfo = get_tbinfo(request)
    inv_files = get_inventory_files(request)
    cache.cleanup(zone=tbname)
    for a_dut in tbinfo['duts']:
        cache.cleanup(zone=a_dut)
    inv_data = get_host_visible_vars(inv_files, a_dut)
    if 'num_asics' in inv_data and inv_data['num_asics'] > 1:
        for asic_id in range(0, inv_data['num_asics']):
            cache.cleanup(zone="{}-asic{}".format(a_dut, asic_id))


def get_l2_info(dut):
    """
    Helper function for l2 mode fixture
    """
    config_facts = dut.get_running_config_facts()
    mgmt_intf_table = config_facts['MGMT_INTERFACE']
    metadata_table = config_facts['DEVICE_METADATA']['localhost']
    mgmt_ip = None
    for ip in list(mgmt_intf_table['eth0'].keys()):
        if type(ip_interface(ip)) is IPv4Interface:
            mgmt_ip = ip
    mgmt_gw = mgmt_intf_table['eth0'][mgmt_ip]['gwaddr']
    hwsku = metadata_table['hwsku']

    return mgmt_ip, mgmt_gw, hwsku


@pytest.fixture(scope='session')
def enable_l2_mode(duthosts, tbinfo, backup_and_restore_config_db_session):     # noqa: F811
    """
    Configures L2 switch mode according to
    https://github.com/sonic-net/SONiC/wiki/L2-Switch-mode

    Currently not compatible with version 201811

    This fixture does not auto-cleanup after itself
    A manual config reload is required to restore regular state
    """
    base_config_db_cmd = 'echo \'{}\' | config reload /dev/stdin -y'
    l2_preset_cmd = 'sonic-cfggen --preset l2 -p -H -k {} -a \'{}\' | config load /dev/stdin -y'
    is_dualtor = 'dualtor' in tbinfo['topo']['name']

    for dut in duthosts:
        logger.info("Setting L2 mode on {}".format(dut))
        cmds = []
        mgmt_ip, mgmt_gw, hwsku = get_l2_info(dut)
        # step 1
        base_config_db = {
                            "MGMT_INTERFACE": {
                                "eth0|{}".format(mgmt_ip): {
                                    "gwaddr": "{}".format(mgmt_gw)
                                }
                            },
                            "DEVICE_METADATA": {
                                "localhost": {
                                    "hostname": "sonic"
                                }
                            }
                        }

        if is_dualtor:
            base_config_db["DEVICE_METADATA"]["localhost"]["subtype"] = "DualToR"
        cmds.append(base_config_db_cmd.format(json.dumps(base_config_db)))

        # step 2
        cmds.append('sonic-cfggen -H --write-to-db')

        # step 3 is optional and skipped here
        # step 4
        if is_dualtor:
            mg_facts = dut.get_extended_minigraph_facts(tbinfo)
            all_ports = list(mg_facts['minigraph_ports'].keys())
            downlinks = []
            for vlan_info in list(mg_facts['minigraph_vlans'].values()):
                downlinks.extend(vlan_info['members'])
            uplinks = [intf for intf in all_ports if intf not in downlinks]
            extra_args = {
                'is_dualtor': 'true',
                'uplinks': uplinks,
                'downlinks': downlinks
            }
        else:
            extra_args = {}
        cmds.append(l2_preset_cmd.format(hwsku, json.dumps(extra_args)))

        # extra step needed to render the feature table correctly
        if is_dualtor:
            cmds.append('while [ $(show feature config mux | awk \'{print $2}\' | tail -n 1) != "enabled" ]; '
                        'do sleep 1; done')

        # step 5
        cmds.append('config save -y')

        # step 6
        cmds.append('config reload -y')

        logger.debug("Commands to be run:\n{}".format(cmds))

        dut.shell_cmds(cmds=cmds)


@pytest.fixture(scope='session')
def duts_running_config_facts(duthosts):
    """Return running config facts for all multi-ASIC DUT hosts

    Args:
        duthosts (DutHosts): Instance of DutHosts for interacting with DUT hosts.

    Returns:
        dict: {
            <dut hostname>: [
                (asic0_idx, {asic0_cfg_facts}),
                (asic1_idx, {asic1_cfg_facts})
            ]
        }
    """
    cfg_facts = {}
    for duthost in duthosts:
        cfg_facts[duthost.hostname] = []
        for asic in duthost.asics:
            if asic.is_it_backend():
                continue
            asic_cfg_facts = asic.config_facts(source='running')['ansible_facts']
            cfg_facts[duthost.hostname].append((asic.asic_index, asic_cfg_facts))
    return cfg_facts


@pytest.fixture(scope='class')
def dut_test_params_qos(duthosts, tbinfo, ptfhost, get_src_dst_asic_and_duts, lower_tor_host, creds,
                        mux_server_url, mux_status_from_nic_simulator, duts_running_config_facts, duts_minigraph_facts):
    if 'dualtor' in tbinfo['topo']['name']:
        all_duts = [lower_tor_host]
    else:
        all_duts = get_src_dst_asic_and_duts['all_duts']

    src_asic = get_src_dst_asic_and_duts['src_asic']
    dst_asic = get_src_dst_asic_and_duts['dst_asic']

    src_dut = get_src_dst_asic_and_duts['src_dut']
    src_dut_ip = src_dut.host.options['inventory_manager'].get_host(src_dut.hostname).vars['ansible_host']
    src_server = "{}:{}".format(src_dut_ip, src_asic.get_rpc_port_ssh_tunnel())

    duthost = all_duts[0]
    mgFacts = duthost.get_extended_minigraph_facts(tbinfo)
    topo = tbinfo["topo"]["name"]

    rtn_dict = {
        "topo": topo,
        "hwsku": mgFacts["minigraph_hwsku"],
        "basicParams": {
            "router_mac": duthost.facts["router_mac"],
            "src_server": src_server,
            "port_map_file": ptf_test_port_map_active_active(
                ptfhost, tbinfo, duthosts, mux_server_url,
                duts_running_config_facts, duts_minigraph_facts,
                mux_status_from_nic_simulator()),
            "sonic_asic_type": duthost.facts['asic_type'],
            "sonic_version": duthost.os_version,
            "src_dut_index": get_src_dst_asic_and_duts['src_dut_index'],
            "src_asic_index": get_src_dst_asic_and_duts['src_asic_index'],
            "dst_dut_index": get_src_dst_asic_and_duts['dst_dut_index'],
            "dst_asic_index": get_src_dst_asic_and_duts['dst_asic_index'],
            "dut_username": creds['sonicadmin_user'],
            "dut_password": creds['sonicadmin_password']
        },

    }

    # Add dst server info if src and dst asic are different
    if src_asic != dst_asic:
        dst_dut = get_src_dst_asic_and_duts['dst_dut']
        dst_dut_ip = dst_dut.host.options['inventory_manager'].get_host(dst_dut.hostname).vars['ansible_host']
        rtn_dict["basicParams"]["dst_server"] = "{}:{}".format(dst_dut_ip, dst_asic.get_rpc_port_ssh_tunnel())

    if 'platform_asic' in duthost.facts:
        rtn_dict['basicParams']["platform_asic"] = duthost.facts['platform_asic']

    yield rtn_dict


@pytest.fixture(scope='class')
def dut_test_params(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo,
                    ptf_portmap_file, lower_tor_host, creds):   # noqa: F811
    """
        Prepares DUT host test params

        Args:
            duthost (AnsibleHost): Device Under Test (DUT)
            tbinfo (Fixture, dict): Map containing testbed information
            ptfPortMapFile (Fxiture, str): filename residing
              on PTF host and contains port maps information

        Returns:
            dut_test_params (dict): DUT host test params
    """
    if 'dualtor' in tbinfo['topo']['name']:
        duthost = lower_tor_host
    else:
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mgFacts = duthost.get_extended_minigraph_facts(tbinfo)
    topo = tbinfo["topo"]["name"]

    rtn_dict = {
        "topo": topo,
        "hwsku": mgFacts["minigraph_hwsku"],
        "basicParams": {
            "router_mac": duthost.facts["router_mac"],
            "server": duthost.host.options['inventory_manager'].get_host(
                        duthost.hostname
                    ).vars['ansible_host'],
            "port_map_file": ptf_portmap_file,
            "sonic_asic_type": duthost.facts['asic_type'],
            "sonic_version": duthost.os_version,
            "dut_username": creds['sonicadmin_user'],
            "dut_password": creds['sonicadmin_password']
        }
    }
    if 'platform_asic' in duthost.facts:
        rtn_dict['basicParams']["platform_asic"] = duthost.facts['platform_asic']

    yield rtn_dict


@pytest.fixture(scope='module')
def duts_minigraph_facts(duthosts, tbinfo):
    """Return minigraph facts for all DUT hosts

    Args:
        duthosts (DutHosts): Instance of DutHosts for interacting with DUT hosts.
        tbinfo (object): Instance of TestbedInfo.

    Returns:
        dict: {
            <dut hostname>: [
                (asic0_idx, {asic0_mg_facts}),
                (asic1_idx, {asic1_mg_facts})
            ]
        }
    """
    mg_facts = {}
    for duthost in duthosts:
        mg_facts[duthost.hostname] = []
        for asic in duthost.asics:
            if asic.is_it_backend():
                continue
            asic_mg_facts = asic.get_extended_minigraph_facts(tbinfo)
            mg_facts[duthost.hostname].append((asic.asic_index, asic_mg_facts))

    return mg_facts


@pytest.fixture(scope="module", autouse=True)
def get_reboot_cause(duthost):
    uptime_start = duthost.get_up_time()
    yield
    uptime_end = duthost.get_up_time()
    if not uptime_end == uptime_start:
        if "201811" in duthost.os_version or "201911" in duthost.os_version:
            duthost.show_and_parse("show reboot-cause")
        else:
            duthost.show_and_parse("show reboot-cause history")


def collect_db_dump_on_duts(request, duthosts):
    '''When test failed, this fixture will dump all the DBs on DUT and collect them to local
    '''
    if hasattr(request.node, 'rep_call') and request.node.rep_call.failed:
        dut_file_path = "/tmp/db_dump"
        local_file_path = "./logs/db_dump"

        # Remove characters that can't be used in filename
        nodename = safe_filename(request.node.nodeid)
        db_dump_path = os.path.join(dut_file_path, nodename)
        db_dump_tarfile = os.path.join(dut_file_path, "{}.tar.gz".format(nodename))

        # We don't need to collect all DBs, db_names specify the DBs we want to collect
        db_names = ["APPL_DB", "ASIC_DB", "COUNTERS_DB", "CONFIG_DB", "STATE_DB"]
        raw_db_config = duthosts[0].shell("cat /var/run/redis/sonic-db/database_config.json")["stdout"]
        db_config = json.loads(raw_db_config).get("DATABASES", {})
        db_ids = set()
        for db_name in db_names:
            # Skip STATE_DB dump on release 201911.
            # JINJA2_CACHE can't be dumped by "redis-dump", and it is stored in STATE_DB on 201911 release.
            # Please refer to issue: https://github.com/sonic-net/sonic-buildimage/issues/5587.
            # The issue has been fixed in https://github.com/sonic-net/sonic-buildimage/pull/5646.
            # However, the fix is not included in 201911 release. So we have to skip STATE_DB on release 201911
            # to avoid raising exception when dumping the STATE_DB.
            if db_name == "STATE_DB" and duthosts[0].sonic_release in ['201911']:
                continue

            if db_name in db_config:
                db_ids.add(db_config[db_name].get("id", 0))

        namespace_list = duthosts[0].get_asic_namespace_list() if duthosts[0].is_multi_asic else []
        if namespace_list:
            for namespace in namespace_list:
                # Collect DB dump
                dump_dest_path = os.path.join(db_dump_path, namespace)
                dump_cmds = ["mkdir -p {}".format(dump_dest_path)]
                for db_id in db_ids:
                    dump_cmd = "ip netns exec {} redis-dump -d {} -y -o {}/{}" \
                               .format(namespace, db_id, dump_dest_path, db_id)
                    dump_cmds.append(dump_cmd)
                duthosts.shell_cmds(cmds=dump_cmds)
        else:
            # Collect DB dump
            dump_dest_path = db_dump_path
            dump_cmds = ["mkdir -p {}".format(dump_dest_path)]
            for db_id in db_ids:
                dump_cmd = "redis-dump -d {} -y -o {}/{}".format(db_id, dump_dest_path, db_id)
                dump_cmds.append(dump_cmd)
            duthosts.shell_cmds(cmds=dump_cmds)

        # compress dump file and fetch to docker
        duthosts.shell("tar -czf {} -C {} {}".format(db_dump_tarfile, dut_file_path, nodename))
        duthosts.fetch(src=db_dump_tarfile, dest=local_file_path)

        # remove dump file from dut
        duthosts.shell("rm -fr {} {}".format(db_dump_tarfile, db_dump_path))


@pytest.fixture(autouse=True)
def collect_db_dump(request, duthosts):
    """This autoused fixture is to generate DB dumps on DUT and collect them to local for later troubleshooting when
    a test case failed.
    """
    yield
    if request.config.getoption("--collect_db_data"):
        collect_db_dump_on_duts(request, duthosts)


def restore_config_db_and_config_reload(duts_data, duthosts):
    # First copy the pre_running_config to the config_db.json files
    for duthost in duthosts:
        logger.info("dut reload called on {}".format(duthost.hostname))
        duthost.copy(content=json.dumps(duts_data[duthost.hostname]["pre_running_config"][None], indent=4),
                     dest='/etc/sonic/config_db.json', verbose=False)

        if duthost.is_multi_asic:
            for asic_index in range(0, duthost.facts.get('num_asic')):
                asic_ns = "asic{}".format(asic_index)
                asic_cfg_file = "/tmp/{}_config_db{}.json".format(duthost.hostname, asic_index)
                with open(asic_cfg_file, "w") as outfile:
                    outfile.write(json.dumps(duts_data[duthost.hostname]['pre_running_config'][asic_ns], indent=4))
                duthost.copy(src=asic_cfg_file, dest='/etc/sonic/config_db{}.json'.format(asic_index), verbose=False)
                os.remove(asic_cfg_file)

    # Second execute config reload on all duthosts
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for duthost in duthosts:
            executor.submit(config_reload, duthost, wait_before_force_reload=300, safe_reload=True,
                            check_intf_up_ports=True, wait_for_bgp=True)


def compare_running_config(pre_running_config, cur_running_config):
    if type(pre_running_config) != type(cur_running_config):
        return False
    if pre_running_config == cur_running_config:
        return True
    else:
        if type(pre_running_config) is dict:
            if set(pre_running_config.keys()) != set(cur_running_config.keys()):
                return False
            for key in pre_running_config.keys():
                if not compare_running_config(pre_running_config[key], cur_running_config[key]):
                    return False
            return True
        # We only have string in list in running config now, so we can ignore the order of the list.
        elif type(pre_running_config) is list:
            if set(pre_running_config) != set(cur_running_config):
                return False
            else:
                return True
        else:
            return False


@pytest.fixture(scope="module", autouse=True)
def core_dump_and_config_check(duthosts, tbinfo, request,
                               # make sure the tear down of sanity_check happened after core_dump_and_config_check
                               sanity_check):
    '''
    Check if there are new core dump files and if the running config is modified after the test case running.
    If so, we will reload the running config after test case running.
    '''

    is_par_run, target_hostname, is_par_leader, par_followers, par_state_file = (
        is_parallel_run(request),
        get_target_hostname(request),
        is_parallel_leader(request),
        get_parallel_followers(request),
        get_parallel_state_file(request),
    )

    initial_check_state = (InitialCheckState(par_followers, par_state_file) if is_par_run else None)
    if is_par_run and not is_par_leader:
        logger.info(
            "Fixture core_dump_and_config_check setup for non-leader nodes in parallel run is skipped. "
            "Please refer to the leader node log for core dump and config check status."
        )

        initial_check_state.wait_and_acknowledge_status(
            InitialCheckStatus.SETUP_COMPLETED,
            is_par_leader,
            target_hostname,
        )

        yield {}

        initial_check_state.mark_tests_completed_for_follower(target_hostname)
        logger.info(
            "Fixture core_dump_and_config_check teardown for non-leader nodes in parallel run is skipped. "
            "Please refer to the leader node log for core dump and config check status."
        )
    else:
        check_flag = True
        if hasattr(request.config.option, 'enable_macsec') and request.config.option.enable_macsec:
            check_flag = False
        if hasattr(request.config.option, 'markexpr') and request.config.option.markexpr:
            if "bsl" in request.config.option.markexpr:
                check_flag = False
        for m in request.node.iter_markers():
            if m.name == "skip_check_dut_health":
                check_flag = False

        module_name = request.node.name

        duts_data = {}

        if check_flag:

            def collect_before_test(dut):
                logger.info("Dumping Disk and Memory Space information before test on {}".format(dut.hostname))
                dut.shell("free -h")
                dut.shell("df -h")

                logger.info("Collecting core dumps before test on {}".format(dut.hostname))
                duts_data[dut.hostname] = {}

                if "20191130" in dut.os_version:
                    pre_existing_core_dumps = dut.shell('ls /var/core/ | grep -v python || true')['stdout'].split()
                else:
                    pre_existing_core_dumps = dut.shell('ls /var/core/')['stdout'].split()
                duts_data[dut.hostname]["pre_core_dumps"] = pre_existing_core_dumps

                logger.info("Collecting running config before test on {}".format(dut.hostname))
                duts_data[dut.hostname]["pre_running_config"] = {}
                if not dut.stat(path="/etc/sonic/running_golden_config.json")['stat']['exists']:
                    logger.info("Collecting running golden config before test on {}".format(dut.hostname))
                    dut.shell("sonic-cfggen -d --print-data > /etc/sonic/running_golden_config.json")
                duts_data[dut.hostname]["pre_running_config"][None] = \
                    json.loads(dut.shell("cat /etc/sonic/running_golden_config.json", verbose=False)['stdout'])

                if dut.is_multi_asic:
                    for asic_index in range(0, dut.facts.get('num_asic')):
                        asic_ns = "asic{}".format(asic_index)
                        if not dut.stat(
                                path="/etc/sonic/running_golden_config{}.json".format(asic_index))['stat']['exists']:
                            dut.shell(
                                "sonic-cfggen -n {} -d --print-data > /etc/sonic/running_golden_config{}.json".format(
                                    asic_ns,
                                    asic_index,
                                )
                            )
                        duts_data[dut.hostname]['pre_running_config'][asic_ns] = \
                            json.loads(dut.shell("cat /etc/sonic/running_golden_config{}.json".format(asic_index),
                                                 verbose=False)['stdout'])

            with SafeThreadPoolExecutor(max_workers=8) as executor:
                for duthost in duthosts:
                    executor.submit(collect_before_test, duthost)

        if is_par_run and is_par_leader:
            initial_check_state.set_new_status(InitialCheckStatus.SETUP_COMPLETED, is_par_leader, target_hostname)
            initial_check_state.wait_for_all_acknowledgments(InitialCheckStatus.SETUP_COMPLETED)

        yield duts_data

        if is_par_run and is_par_leader:
            initial_check_state.wait_for_all_acknowledgments(InitialCheckStatus.TESTS_COMPLETED)
            initial_check_state.set_new_status(InitialCheckStatus.TEARDOWN_STARTED, is_par_leader, target_hostname)

        inconsistent_config = {}
        pre_only_config = {}
        cur_only_config = {}
        new_core_dumps = {}

        core_dump_check_failed = False
        config_db_check_failed = False

        check_result = {}

        if check_flag:

            def collect_after_test(dut):
                inconsistent_config[dut.hostname] = {}
                pre_only_config[dut.hostname] = {}
                cur_only_config[dut.hostname] = {}
                new_core_dumps[dut.hostname] = []

                logger.info("Dumping Disk and Memory Space information after test on {}".format(dut.hostname))
                dut.shell("free -h")
                dut.shell("df -h")

                logger.info("Collecting core dumps after test on {}".format(dut.hostname))
                if "20191130" in dut.os_version:
                    cur_cores = dut.shell('ls /var/core/ | grep -v python || true')['stdout'].split()
                else:
                    cur_cores = dut.shell('ls /var/core/')['stdout'].split()
                duts_data[dut.hostname]["cur_core_dumps"] = cur_cores

                cur_core_dumps_set = set(duts_data[dut.hostname]["cur_core_dumps"])
                pre_core_dumps_set = set(duts_data[dut.hostname]["pre_core_dumps"])
                new_core_dumps[dut.hostname] = list(cur_core_dumps_set - pre_core_dumps_set)

                logger.info("Collecting running config after test on {}".format(dut.hostname))
                # get running config after running
                duts_data[dut.hostname]["cur_running_config"] = {}
                duts_data[dut.hostname]["cur_running_config"][None] = \
                    json.loads(dut.shell("sonic-cfggen -d --print-data", verbose=False)['stdout'])
                if dut.is_multi_asic:
                    for asic_index in range(0, dut.facts.get('num_asic')):
                        asic_ns = "asic{}".format(asic_index)
                        duts_data[dut.hostname]["cur_running_config"][asic_ns] = \
                            json.loads(dut.shell("sonic-cfggen -n {} -d --print-data".format(asic_ns),
                                                 verbose=False)['stdout'])

            with SafeThreadPoolExecutor(max_workers=8) as executor:
                for duthost in duthosts:
                    executor.submit(collect_after_test, duthost)

            for duthost in duthosts:
                if new_core_dumps[duthost.hostname]:
                    core_dump_check_failed = True

                    base_dir = os.path.dirname(os.path.realpath(__file__))
                    for new_core_dump in new_core_dumps[duthost.hostname]:
                        duthost.fetch(src="/var/core/{}".format(new_core_dump), dest=os.path.join(base_dir, "logs"))

                # The tables that we don't care
                exclude_config_table_names = set([])
                # The keys that we don't care
                # Current skipped keys:
                # 1. "MUX_LINKMGR|LINK_PROBER"
                # 2. "MUX_LINKMGR|TIMED_OSCILLATION"
                # 3. "LOGGER|linkmgrd"
                # NOTE: this key is edited by the `run_icmp_responder_session` or `run_icmp_responder`
                # to account for the lower performance of the ICMP responder/mux simulator compared to
                # real servers and mux cables.
                # Linkmgrd is the only service to consume this table so it should not affect other test cases.
                # Let's keep this setting in db and we don't want any config reload caused by this key, so
                # let's skip checking it.
                if "dualtor" in tbinfo["topo"]["name"]:
                    exclude_config_key_names = [
                        'MUX_LINKMGR|LINK_PROBER',
                        'MUX_LINKMGR|TIMED_OSCILLATION',
                        'LOGGER|linkmgrd'
                    ]
                else:
                    exclude_config_key_names = []

                def _remove_entry(table_name, key_name, config):
                    if table_name in config and key_name in config[table_name]:
                        config[table_name].pop(key_name)
                        if len(config[table_name]) == 0:
                            config.pop(table_name)

                for cfg_context in duts_data[duthost.hostname]['pre_running_config']:
                    pre_only_config[duthost.hostname][cfg_context] = {}
                    cur_only_config[duthost.hostname][cfg_context] = {}
                    inconsistent_config[duthost.hostname][cfg_context] = {}

                    pre_running_config = duts_data[duthost.hostname]["pre_running_config"][cfg_context]
                    cur_running_config = duts_data[duthost.hostname]["cur_running_config"][cfg_context]

                    # Remove ignored keys from base config
                    for exclude_key in exclude_config_key_names:
                        fields = exclude_key.split('|')
                        if len(fields) != 2:
                            continue
                        _remove_entry(fields[0], fields[1], pre_running_config)
                        _remove_entry(fields[0], fields[1], cur_running_config)

                    pre_running_config_keys = set(pre_running_config.keys())
                    cur_running_config_keys = set(cur_running_config.keys())

                    # Check if there are extra keys in pre running config
                    pre_config_extra_keys = list(
                        pre_running_config_keys - cur_running_config_keys - exclude_config_table_names)
                    for key in pre_config_extra_keys:
                        pre_only_config[duthost.hostname][cfg_context].update({key: pre_running_config[key]})

                    # Check if there are extra keys in cur running config
                    cur_config_extra_keys = list(
                        cur_running_config_keys - pre_running_config_keys - exclude_config_table_names)
                    for key in cur_config_extra_keys:
                        cur_only_config[duthost.hostname][cfg_context].update({key: cur_running_config[key]})

                    # Get common keys in pre running config and cur running config
                    common_config_keys = list(pre_running_config_keys & cur_running_config_keys -
                                              exclude_config_table_names)

                    # Check if the running config is modified after module running
                    for key in common_config_keys:
                        # TODO: remove these code when solve the problem of "FLEX_COUNTER_DELAY_STATUS"
                        if key == "FLEX_COUNTER_TABLE":
                            for sub_key, sub_value in list(pre_running_config[key].items()):
                                try:
                                    pre_value = pre_running_config[key][sub_key]
                                    cur_value = cur_running_config[key][sub_key]
                                    if pre_value["FLEX_COUNTER_STATUS"] != cur_value["FLEX_COUNTER_STATUS"]:
                                        inconsistent_config[duthost.hostname][cfg_context].update(
                                            {
                                                key: {
                                                    "pre_value": pre_running_config[key],
                                                    "cur_value": cur_running_config[key]
                                                }
                                            }
                                        )
                                except KeyError:
                                    inconsistent_config[duthost.hostname][cfg_context].update(
                                        {
                                            key: {
                                                "pre_value": pre_running_config[key],
                                                "cur_value": cur_running_config[key]
                                            }
                                        }
                                    )
                        elif not compare_running_config(pre_running_config[key], cur_running_config[key]):
                            inconsistent_config[duthost.hostname][cfg_context].update(
                                {
                                    key: {
                                        "pre_value": pre_running_config[key],
                                        "cur_value": cur_running_config[key]
                                    }
                                }
                            )

                    if pre_only_config[duthost.hostname][cfg_context] or \
                            cur_only_config[duthost.hostname][cfg_context] or \
                            inconsistent_config[duthost.hostname][cfg_context]:
                        config_db_check_failed = True

            if core_dump_check_failed or config_db_check_failed:
                check_result = {
                    "core_dump_check": {
                        "failed": core_dump_check_failed,
                        "new_core_dumps": new_core_dumps
                    },
                    "config_db_check": {
                        "failed": config_db_check_failed,
                        "pre_only_config": pre_only_config,
                        "cur_only_config": cur_only_config,
                        "inconsistent_config": inconsistent_config
                    }
                }
                logger.warning("Core dump or config check failed for {}, results: {}"
                               .format(module_name, json.dumps(check_result)))

                restore_config_db_and_config_reload(duts_data, duthosts)
            else:
                logger.info("Core dump and config check passed for {}".format(module_name))

        if check_result:
            logger.debug("core_dump_and_config_check failed, check_result: {}".format(json.dumps(check_result)))
            add_custom_msg(request, f"{DUT_CHECK_NAMESPACE}.core_dump_check_failed", core_dump_check_failed)
            add_custom_msg(request, f"{DUT_CHECK_NAMESPACE}.config_db_check_failed", config_db_check_failed)


@pytest.fixture(scope="module", autouse=True)
def temporarily_disable_route_check(request, duthosts):
    check_flag = False
    for m in request.node.iter_markers():
        if m.name == "disable_route_check":
            check_flag = True
            break

    def wait_for_route_check_to_pass(dut):

        def run_route_check():
            res = dut.shell("sudo route_check.py", module_ignore_errors=True)
            return res["rc"] == 0

        pt_assert(
            wait_until(180, 15, 0, run_route_check),
            "route_check.py is still failing after timeout",
        )

    if check_flag:
        # If a pytest.fail or any other exceptions are raised in the setup stage of a fixture (before the yield),
        # the teardown code (after the yield) will not run, so we are using try...finally... to ensure the
        # routeCheck monit will always be started after this fixture.
        try:
            with SafeThreadPoolExecutor(max_workers=8) as executor:
                for duthost in duthosts.frontend_nodes:
                    executor.submit(wait_for_route_check_to_pass, duthost)

            with SafeThreadPoolExecutor(max_workers=8) as executor:
                for duthost in duthosts.frontend_nodes:
                    executor.submit(duthost.shell, "sudo monit stop routeCheck")

            yield

            with SafeThreadPoolExecutor(max_workers=8) as executor:
                for duthost in duthosts.frontend_nodes:
                    executor.submit(wait_for_route_check_to_pass, duthost)
        finally:
            with SafeThreadPoolExecutor(max_workers=8) as executor:
                for duthost in duthosts.frontend_nodes:
                    executor.submit(duthost.shell, "sudo monit start routeCheck")
    else:
        logger.info("Skipping temporarily_disable_route_check fixture")
        yield
        logger.info("Skipping temporarily_disable_route_check fixture")


@pytest.fixture(scope="function")
def on_exit():
    '''
    Utility to register callbacks for cleanup. Runs callbacks despite assertion
    failures. Callbacks are executed in reverse order of registration.
    '''
    class OnExit():
        def __init__(self):
            self.cbs = []

        def register(self, fn):
            self.cbs.append(fn)

        def cleanup(self):
            while len(self.cbs) != 0:
                self.cbs.pop()()

    on_exit = OnExit()
    yield on_exit
    on_exit.cleanup()


@pytest.fixture(scope="session", autouse=True)
def add_mgmt_test_mark(duthosts):
    '''
    @summary: Create mark file at /etc/sonic/mgmt_test_mark, and DUT can use this mark to detect mgmt test.
    @param duthosts: fixture to get DUT hosts
    '''
    mark_file = "/etc/sonic/mgmt_test_mark"
    duthosts.shell("touch %s" % mark_file, module_ignore_errors=True)


def verify_packets_any_fixed(test, pkt, ports=[], device_number=0, timeout=None):
    """
    Check that a packet is received on _any_ of the specified ports belonging to
    the given device (default device_number is 0).

    Also verifies that the packet is not received on any other ports for this
    device, and that no other packets are received on the device (unless --relax
    is in effect).

    The function is redefined here to workaround code bug in testutils.verify_packets_any
    """
    received = False
    failures = []
    for device, port in testutils.ptf_ports():
        if device != device_number:
            continue
        if port in ports:
            logging.debug("Checking for pkt on device %d, port %d", device_number, port)
            result = testutils.dp_poll(test, device_number=device, port_number=port,
                                       timeout=timeout, exp_pkt=pkt)
            if isinstance(result, test.dataplane.PollSuccess):
                received = True
            else:
                failures.append((port, result))
        else:
            testutils.verify_no_packet(test, pkt, (device, port))
    testutils.verify_no_other_packets(test)

    if not received:
        def format_failure(port, failure):
            return "On port %d:\n%s" % (port, failure.format())
        failure_report = "\n".join([format_failure(*f) for f in failures])
        test.fail("Did not receive expected packet on any of ports %r for device %d.\n%s"
                  % (ports, device_number, failure_report))


# HACK: testutils.verify_packets_any to workaround code bug
# TODO: delete me when ptf version is advanced than https://github.com/p4lang/ptf/pull/139
testutils.verify_packets_any = verify_packets_any_fixed

# HACK: We are using set_do_not_care_scapy but it will be deprecated.
if not hasattr(Mask, "set_do_not_care_scapy"):
    Mask.set_do_not_care_scapy = Mask.set_do_not_care_packet


def run_logrotate(duthost, stop_event):
    logger.info("Start rotate_syslog on {}".format(duthost))
    while not stop_event.is_set():
        try:
            # Run logrotate for rsyslog
            duthost.shell("logrotate -f /etc/logrotate.conf", module_ignore_errors=True)
        except subprocess.CalledProcessError as e:
            logger.error("Error: {}".format(str(e)))
        # Wait for 60 seconds before the next rotation
        time.sleep(60)


@pytest.fixture(scope="function")
def rotate_syslog(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    stop_event = threading.Event()
    thread = InterruptableThread(
        target=run_logrotate,
        args=(duthost, stop_event,)
    )
    thread.daemon = True
    thread.start()

    yield
    stop_event.set()
    try:
        if thread.is_alive():
            thread.join(timeout=30)
            logger.info("thread {} joined".format(thread))
    except Exception as e:
        logger.debug("Exception occurred in thread {}".format(str(e)))

    logger.info("rotate_syslog exit {}".format(thread))


@pytest.fixture(scope="module")
def gnxi_path(ptfhost):
    """
    gnxi's location is updated from /gnxi to /root/gnxi
    in RP https://github.com/sonic-net/sonic-buildimage/pull/10599.
    But old docker-ptf images don't have this update,
    test case will fail for these docker-ptf images,
    because it should still call /gnxi files.
    For avoiding this conflict, check gnxi path before test and set GNXI_PATH to correct value.
    Add a new gnxi_path module fixture to make sure to set GNXI_PATH before test.
    """
    path_exists = ptfhost.stat(path="/root/gnxi/")
    if path_exists["stat"]["exists"] and path_exists["stat"]["isdir"]:
        gnxipath = "/root/gnxi/"
    else:
        gnxipath = "/gnxi/"
    return gnxipath


@pytest.fixture(scope="module")
def selected_asic_index(request):
    asic_index = DEFAULT_ASIC_ID
    if "enum_asic_index" in request.fixturenames:
        asic_index = request.getfixturevalue("enum_asic_index")
    elif "enum_frontend_asic_index" in request.fixturenames:
        asic_index = request.getfixturevalue("enum_frontend_asic_index")
    elif "enum_backend_asic_index" in request.fixturenames:
        asic_index = request.getfixturevalue("enum_backend_asic_index")
    elif "enum_rand_one_asic_index" in request.fixturenames:
        asic_index = request.getfixturevalue("enum_rand_one_asic_index")
    elif "enum_rand_one_frontend_asic_index" in request.fixturenames:
        asic_index = request.getfixturevalue("enum_rand_one_frontend_asic_index")
    logger.info(f"Selected asic_index {asic_index}")
    return asic_index


@pytest.fixture(scope="module")
def ip_netns_namespace_prefix(request, selected_asic_index):
    """
    Construct the formatted namespace prefix for executed commands inside the specific
    network namespace or for linux commands.
    """
    if selected_asic_index == DEFAULT_ASIC_ID:
        return ''
    else:
        return f'sudo ip netns exec {NAMESPACE_PREFIX}{selected_asic_index}'


@pytest.fixture(scope="module")
def cli_namespace_prefix(request, selected_asic_index):
    """
    Construct the formatted namespace prefix for executed commands inside the specific
    network namespace or for CLI commands.
    """
    if selected_asic_index == DEFAULT_ASIC_ID:
        return ''
    else:
        return f'-n {NAMESPACE_PREFIX}{selected_asic_index}'


def pytest_collection_modifyitems(config, items):
    # Skip all stress_tests if --run-stress-test is not set
    if not config.getoption("--run-stress-tests"):
        skip_stress_tests = pytest.mark.skip(reason="Stress tests run only if --run-stress-tests is passed")
        for item in items:
            if "stress_test" in item.keywords:
                item.add_marker(skip_stress_tests)


def update_t1_test_ports(duthost, mg_facts, test_ports, tbinfo):
    """
    Find out active IP interfaces and use the list to
    remove inactive ports from test_ports
    """
    ip_ifaces = duthost.get_active_ip_interfaces(tbinfo, asic_index=0)
    port_list = []
    for iface in list(ip_ifaces.keys()):
        if iface.startswith("PortChannel"):
            port_list.extend(
                mg_facts["minigraph_portchannels"][iface]["members"]
            )
        else:
            port_list.append(iface)
    port_list_set = set(port_list)
    for port in list(test_ports.keys()):
        if port not in port_list_set:
            del test_ports[port]
    return test_ports


@pytest.fixture(scope="module")
def setup_pfc_test(
    duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfhost, conn_graph_facts, tbinfo,     # noqa F811
):
    """
    Sets up all the parameters needed for the PFC Watchdog tests

    Args:
        duthost: AnsibleHost instance for DUT
        ptfhost: AnsibleHost instance for PTF
        conn_graph_facts: fixture that contains the parsed topology info

    Yields:
        setup_info: dictionary containing pfc timers, generated test ports and selected test ports
    """
    SUPPORTED_T1_TOPOS = {"t1-lag", "t1-64-lag", "t1-56-lag", "t1-28-lag", "t1-32-lag"}
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    port_list = list(mg_facts['minigraph_ports'].keys())
    neighbors = conn_graph_facts['device_conn'].get(duthost.hostname, {})
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    dut_eth0_ip = duthost.mgmt_ip
    vlan_nw = None

    if mg_facts['minigraph_vlans']:
        # Filter VLANs with one interface inside only(PortChannel interface in case of t0-56-po2vlan topo)
        unexpected_vlans = []
        for vlan, vlan_data in list(mg_facts['minigraph_vlans'].items()):
            if len(vlan_data['members']) < 2:
                unexpected_vlans.append(vlan)

        # Update minigraph_vlan_interfaces with only expected VLAN interfaces
        expected_vlan_ifaces = []
        for vlan in unexpected_vlans:
            for mg_vl_iface in mg_facts['minigraph_vlan_interfaces']:
                if vlan != mg_vl_iface['attachto']:
                    expected_vlan_ifaces.append(mg_vl_iface)
        if expected_vlan_ifaces:
            mg_facts['minigraph_vlan_interfaces'] = expected_vlan_ifaces

        # gather all vlan specific info
        vlan_addr = mg_facts['minigraph_vlan_interfaces'][0]['addr']
        vlan_prefix = mg_facts['minigraph_vlan_interfaces'][0]['prefixlen']
        vlan_dev = mg_facts['minigraph_vlan_interfaces'][0]['attachto']
        vlan_ips = duthost.get_ip_in_range(
            num=1, prefix="{}/{}".format(vlan_addr, vlan_prefix),
            exclude_ips=[vlan_addr])['ansible_facts']['generated_ips']
        vlan_nw = vlan_ips[0].split('/')[0]

    topo = tbinfo["topo"]["name"]
    # build the port list for the test
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    tp_handle = TrafficPorts(mg_facts, neighbors, vlan_nw, topo, config_facts)
    test_ports = tp_handle.build_port_list()

    # In T1 topology update test ports by removing inactive ports
    if topo in SUPPORTED_T1_TOPOS:
        test_ports = update_t1_test_ports(
            duthost, mg_facts, test_ports, tbinfo
        )
    # select a subset of ports from the generated port list
    selected_ports = select_test_ports(test_ports)

    setup_info = {'test_ports': test_ports,
                  'port_list': port_list,
                  'selected_test_ports': selected_ports,
                  'pfc_timers': set_pfc_timers(),
                  'neighbors': neighbors,
                  'eth0_ip': dut_eth0_ip
                  }

    if mg_facts['minigraph_vlans']:
        setup_info['vlan'] = {'addr': vlan_addr,
                              'prefix': vlan_prefix,
                              'dev': vlan_dev
                              }
    else:
        setup_info['vlan'] = None

    # stop pfcwd
    logger.info("--- Stopping Pfcwd ---")
    duthost.command("pfcwd stop")

    # set poll interval
    duthost.command("pfcwd interval {}".format(setup_info['pfc_timers']['pfc_wd_poll_time']))

    # set bulk counter chunk size
    logger.info("--- Setting bulk counter polling chunk size ---")
    duthost.command('redis-cli -n 4 hset "FLEX_COUNTER_TABLE|PORT" BULK_CHUNK_SIZE 64'
                    ' BULK_CHUNK_SIZE_PER_PREFIX "SAI_PORT_STAT_IF_OUT_QLEN:0;SAI_PORT_STAT_IF_IN_FEC:32"')

    logger.info("setup_info : {}".format(setup_info))
    yield setup_info


@pytest.fixture(scope="session")
def setup_gnmi_server(request, localhost, duthost):
    """
    SAI validation library uses gNMI to access sonic-db data
    objects. This fixture is used by tests to set up gNMI server
    """
    disable_sai_validation = request.config.getoption("--disable_sai_validation")
    if disable_sai_validation:
        logger.info("SAI validation is disabled")
        yield duthost, None
        return
    gnmi_insecure = request.config.getoption("--gnmi_insecure")
    if gnmi_insecure:
        logger.info("gNMI insecure mode is enabled")
        yield duthost, None
        return
    else:
        checkpoint_name = "before-applying-gnmi-certs"
        cert_path = pathlib.Path("/tmp/gnmi_certificates")
        gnmi_setup.create_certificates(localhost, duthost.mgmt_ip, cert_path)
        gnmi_setup.copy_certificates_to_dut(cert_path, duthost)
        gnmi_setup.apply_certs(duthost, checkpoint_name)
        yield duthost, cert_path
        gnmi_setup.remove_certs(duthost, checkpoint_name)


@pytest.fixture(scope="session")
def setup_connection(request, setup_gnmi_server):
    duthost, cert_path = setup_gnmi_server
    disable_sai_validation = request.config.getoption("--disable_sai_validation")
    if disable_sai_validation:
        logger.info("SAI validation is disabled")
        yield None
        return
    else:
        # Dynamically import create_gnmi_stub
        gnmi_client_module = importlib.import_module("tests.common.sai_validation.gnmi_client")
        create_gnmi_stub = getattr(gnmi_client_module, "create_gnmi_stub")

        # if cert_path is None then it is insecure mode
        gnmi_insecure = request.config.getoption("--gnmi_insecure")
        gnmi_target_port = int(request.config.getoption("--gnmi_port"))
        duthost_mgmt_ip = duthost.mgmt_ip
        channel = None
        gnmi_connection = None
        if gnmi_insecure:
            channel, gnmi_connection = create_gnmi_stub(ip=duthost_mgmt_ip,
                                                        port=gnmi_target_port, secure=False)
        else:
            root_cert = str(cert_path / 'gnmiCA.pem')
            client_cert = str(cert_path / 'gnmiclient.crt')
            client_key = str(cert_path / 'gnmiclient.key')
            channel, gnmi_connection = create_gnmi_stub(ip=duthost_mgmt_ip,
                                                        port=gnmi_target_port, secure=True,
                                                        root_cert_path=root_cert,
                                                        client_cert_path=client_cert,
                                                        client_key_path=client_key)
        yield gnmi_connection
        channel.close()


@pytest.fixture(scope="session")
def gnmi_connection(request, setup_connection):
    connection = setup_connection
    yield connection
