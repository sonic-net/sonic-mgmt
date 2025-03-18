import pytest
import logging
import json
import time

from tests.common.dualtor.dual_tor_utils import get_crm_nexthop_counter
from tests.common.dualtor.dual_tor_utils import mux_cable_server_ip
from tests.common.helpers.assertions import pytest_assert as py_assert
from tests.common.helpers.assertions import pytest_require as py_require
from tests.common.fixtures.ptfhost_utils import change_mac_addresses, run_garp_service, \
                                                copy_arp_responder_py   # noqa F401
from tests.common.dualtor.dual_tor_mock import *                        # noqa F401
from tests.common.utilities import get_host_visible_vars


CRM_POLL_INTERVAL = 1
CRM_DEFAULT_POLL_INTERVAL = 300


@pytest.fixture
def set_crm_polling_interval(rand_selected_dut):
    """
    A function level fixture to set crm polling interval to 1 second
    """
    wait_time = 2
    logging.info("Setting crm polling interval to {} seconds".format(CRM_POLL_INTERVAL))
    rand_selected_dut.command("crm config polling interval {}".format(CRM_POLL_INTERVAL))
    logging.info("Waiting {} sec for CRM counters to become updated".format(wait_time))
    time.sleep(wait_time)
    yield
    logging.info("Setting crm polling interval to {} seconds".format(CRM_DEFAULT_POLL_INTERVAL))
    rand_selected_dut.command("crm config polling interval {}".format(CRM_DEFAULT_POLL_INTERVAL))


@pytest.fixture
def verify_crm_nexthop_counter_not_increased(rand_selected_dut, set_crm_polling_interval):
    """
    A function level fixture to verify crm nexthop counter not increased
    """
    original_counter = get_crm_nexthop_counter(rand_selected_dut)
    logging.info("Before test: crm nexthop counter = {}".format(original_counter))
    yield
    time.sleep(CRM_POLL_INTERVAL)
    diff = get_crm_nexthop_counter(rand_selected_dut) - original_counter
    logging.info("Before test: crm nexthop counter = {}".format(original_counter + diff))
    py_assert(diff <= 0, "crm nexthop counter is increased by {}.".format(diff))


def pytest_addoption(parser):
    """
    Adds pytest options that are used by dual ToR tests
    """

    dual_tor_group = parser.getgroup("Dual ToR test suite options")

    dual_tor_group.addoption(
        "--mux-stress-count",
        action="store",
        default=2,
        type=int,
        help="The number of iterations for mux stress test"
    )


@pytest.fixture(scope="module", autouse=True)
def common_setup_teardown(rand_selected_dut, request, tbinfo, vmhost):
    # Skip dualtor test cases on unsupported platform
    if rand_selected_dut.facts['asic_type'] != 'vs':
        supported_platforms = ['broadcom_td3_hwskus', 'broadcom_th2_hwskus', 'cisco_hwskus', 'mellanox_dualtor_hwskus']
        hostvars = get_host_visible_vars(rand_selected_dut.host.options['inventory'], rand_selected_dut.hostname)
        hwsku = rand_selected_dut.facts['hwsku']
        skip = True
        for platform in supported_platforms:
            supported_skus = hostvars.get(platform, [])
            if hwsku in supported_skus:
                skip = False
                break
        py_require(not skip, "Skip on unsupported platform")

    if 'dualtor' in tbinfo['topo']['name']:
        request.getfixturevalue('run_garp_service')


def _setup_arp_responder(rand_selected_dut, ptfhost, tbinfo, ip_type):
    logging.info('Setup ARP responder in the PTF container  {}'.format(ptfhost.hostname))
    duthost = rand_selected_dut
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    minigraph_ptf_indices = mg_facts['minigraph_ptf_indices']
    mux_config = mux_cable_server_ip(duthost)
    if ip_type == 'ipv4':
        arp_responder_conf = {"eth%s" % minigraph_ptf_indices[port]: [config["server_ipv4"].split("/")[0]]
                              for port, config in list(mux_config.items())}
    else:
        arp_responder_conf = {"eth%s" % minigraph_ptf_indices[port]: [config["server_ipv6"].split("/")[0]]
                              for port, config in list(mux_config.items())}
    ptfhost.copy(content=json.dumps(arp_responder_conf, indent=4), dest="/tmp/from_t1.json")

    ptfhost.host.options["variable_manager"].extra_vars.update({"arp_responder_args": ""})
    ptfhost.template(src="templates/arp_responder.conf.j2", dest="/etc/supervisor/conf.d/arp_responder.conf")
    ptfhost.shell('supervisorctl reread && supervisorctl update')
    ptfhost.shell('supervisorctl restart arp_responder')


@pytest.fixture(scope="module")
def run_arp_responder_ipv6(rand_selected_dut, ptfhost, tbinfo, apply_mock_dual_tor_tables):
    """Run arp_responder to enable ptf to respond neighbor solicitation messages"""
    _setup_arp_responder(rand_selected_dut, ptfhost, tbinfo, 'ipv6')
    yield

    ptfhost.shell('supervisorctl stop arp_responder', module_ignore_errors=True)


@pytest.fixture(scope="module")
def run_arp_responder(rand_selected_dut, ptfhost, tbinfo):
    _setup_arp_responder(rand_selected_dut, ptfhost, tbinfo, 'ipv4')
    yield

    ptfhost.shell('supervisorctl stop arp_responder', module_ignore_errors=True)


@pytest.fixture(scope="module")
def config_facts(rand_selected_dut):
    return rand_selected_dut.config_facts(host=rand_selected_dut.hostname, source="running")['ansible_facts']


def pytest_configure(config):

    config.addinivalue_line(
        "markers", "enable_active_active: mark test to run with 'active_active' ports"
    )

    config.addinivalue_line(
        "markers", "skip_active_standby: mark test to skip running with 'active_standby' ports"
    )
