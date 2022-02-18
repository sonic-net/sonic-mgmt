import pytest
import ipaddress
import os

from collections import defaultdict
from natsort import natsorted
from tests.common.reboot import reboot
from mclag_helpers import get_dut_routes
from mclag_helpers import get_interconnected_links
from mclag_helpers import get_vm_links
from mclag_helpers import DUT1_INDEX, DUT2_INDEX
from mclag_helpers import PC_NAME_TEMPLATE, SUBNET_CHECK
from mclag_helpers import CONFIG_DB_TEMP, CONFIG_DB_BACKUP, MAX_MCLAG_INTF
from mclag_helpers import TEMPLATE_DIR, PTF_NN_AGENT_TEMPLATE
from tests.common.ptf_agent_updater import PtfAgentUpdater

def pytest_addoption(parser):
    """
        Adds options to pytest that are used by the mclag test.
    """
    parser.addoption(
        "--amount_mclag_intf",
        action="store",
        type=int,
        default=6,
        help="Amount of mclag interfaces to test, default value is 6",
    )


@pytest.fixture(scope='module')
def mclag_intf_num(request):
    argument = request.config.getoption("--amount_mclag_intf")
    assert(argument <= MAX_MCLAG_INTF)
    return argument


@pytest.fixture(scope='module')
def duthost1(duthosts):
    return duthosts[DUT1_INDEX]


@pytest.fixture(scope='module')
def duthost2(duthosts):
    return duthosts[DUT2_INDEX]


@pytest.fixture(scope='module')
def mg_facts(duthosts, tbinfo):
    return {dut.hostname:dut.get_extended_minigraph_facts(tbinfo) for dut in duthosts}


@pytest.fixture(scope='module')
def get_router_macs(duthost1, duthost2):
    router_mac1 = duthost1.facts['router_mac']
    router_mac2 = duthost2.facts['router_mac']
    return router_mac1, router_mac2


@pytest.fixture(scope="module", autouse=True)
def tear_down(duthost1, duthost2, ptfhost, localhost, collect):
    """
    Performs tear down of all configuration on PTF and DUTs
    Args:
        duthost1: DUT host object
        duthost2: DUT host object
        ptfhost: PTF host object
        localhost: localhost object
        collect: Fixture which collects main info about link connection
    """
    yield

    mclag_interfaces = collect[duthost1.hostname]['mclag_interfaces']
    cmds_to_del_lags = ['ip link del {}'.format(lag) for lag in mclag_interfaces]
    ptfhost.shell_cmds(cmds=cmds_to_del_lags)

    ptfhost.remove_ip_addresses()
    duthost1.shell("mv {} {}".format(CONFIG_DB_BACKUP, CONFIG_DB_TEMP))
    reboot(duthost1, localhost)

    duthost2.shell("mv {} {}".format(CONFIG_DB_BACKUP, CONFIG_DB_TEMP))
    reboot(duthost2, localhost)


@pytest.fixture(scope="module")
def get_routes(duthost1, duthost2, collect, mg_facts):
    """
    Get bgp routes that are advertised to each DUT
    Args:
        duthost1: DUT host object
        duthost2: DUT host object
        collect: Fixture which collects main info about link connection
        mg_facts: Dict with minigraph facts for each DUT
    """
    dut1_routes_all = get_dut_routes(duthost1, collect, mg_facts)
    dut2_routes_all = get_dut_routes(duthost2, collect, mg_facts)
    dut_1_diff_routes = list(set(dut1_routes_all).difference(set(dut2_routes_all)))
    dut_2_diff_routes = list(set(dut2_routes_all).difference(set(dut1_routes_all)))
    res1 = natsorted([route for route in dut_1_diff_routes if ipaddress.ip_network(route).subnet_of(ipaddress.ip_network(SUBNET_CHECK))])
    res2 = natsorted([route for route in dut_2_diff_routes if ipaddress.ip_network(route).subnet_of(ipaddress.ip_network(SUBNET_CHECK))])
    return {duthost1.hostname: res1, duthost2.hostname: res2}


@pytest.fixture(scope="module")
def collect(duthosts, tbinfo):
    """
    Collect main information about link connection from tbinfo
    Args:
        duthosts: Duthosts fixture
        tbinfo: Testbed object
    """
    duts_map = tbinfo['duts_map']
    res = defaultdict(dict)
    for dut in duthosts:
        dut_indx = duts_map[dut.hostname]
        dut_hostname = dut.hostname
        res[dut_hostname]['devices_interconnect_interfaces'] = get_interconnected_links(tbinfo, dut_indx)
        res[dut_hostname]['vm_links'] = get_vm_links(tbinfo, dut_indx)
        host_interfaces = tbinfo['topo']['ptf_map'][str(dut_indx)]
        res[dut_hostname]['vm_link_on_ptf'] = host_interfaces[res[dut_hostname]['vm_links'][0]]
        _ = [host_interfaces.pop(vm) for vm in res[dut_hostname]['vm_links'] if vm in host_interfaces.keys()]
        res[dut_hostname]['host_interfaces'] = natsorted(host_interfaces)
        res[dut_hostname]['ptf_map'] = host_interfaces
        res[dut_hostname]['all_links'] = natsorted(res[dut_hostname]['host_interfaces'] + res[dut_hostname]['devices_interconnect_interfaces'] + res[dut_hostname]['vm_links'])
        res[dut_hostname]['mclag_interfaces'] = natsorted([PC_NAME_TEMPLATE.format(indx + 1) for indx, _ in enumerate(res[dut_hostname]['host_interfaces'][:-2])])
    return res


@pytest.fixture()
def update_and_clean_ptf_agent(duthost1, ptfhost, ptfadapter, collect):
    """
    Fixture that will add new interfaces to interfaces map of ptfadapter and remove them
    Args:
        duthost1: DUT host object
        ptfhost: PTF host object
        ptfadapter: PTF adapter
        collect: Fixture which collects main info about link connection
    """
    ptf_agent_updater = PtfAgentUpdater(ptfhost=ptfhost,
                                        ptfadapter=ptfadapter,
                                        ptf_nn_agent_template=os.path.join(TEMPLATE_DIR, PTF_NN_AGENT_TEMPLATE))
    mclag_interfaces = collect[duthost1.hostname]['mclag_interfaces']
    ptf_agent_updater.configure_ptf_nn_agent(mclag_interfaces)

    yield

    ptf_agent_updater.cleanup_ptf_nn_agent(mclag_interfaces)
