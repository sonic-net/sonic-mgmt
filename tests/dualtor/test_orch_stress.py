"""
Dual ToR Orchagent - Stress Test

This script is to cover the stress test case in the Dual ToR Orchagent test plan:
https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testplan/dual_tor/dual_tor_orch_test_plan.md

Test summary:

    Continuous mux state change based on configurable parameter 'N':

    | Step                                                         | Goal | Expected results                                                  |     # noqa F501
    | ------------------------------------------------------------ | ---- | ----------------------------------------------------------------- |     # noqa F501
    | Change mux state from Active->Standby->Active 'N' times      | CRM  | Verify CRM values for routes/nexthop and check for leaks          |     # noqa F501
    |                                                              |      |                                                                   |     # noqa F501
    | Flush and re-learn Neighbor entry 'N' times in Standby state | CRM  | Verify CRM values for routes/neighbor/nexthop and check for leaks |     # noqa F501
    |                                                              |      |                                                                   |     # noqa F501
    | Flush and re-learn Neighbor entry 'N' times in Active state  | CRM  | Verify CRM values for routes/neighbor/nexthop and check for leaks |     # noqa F501
"""
import json
import logging
import os

import pytest

from tests.common.utilities import wait
from tests.common.utilities import compare_crm_facts
from tests.common.helpers.assertions import pytest_assert
from tests.common.dualtor.dual_tor_utils import tor_mux_intfs       # noqa F401
from tests.common.dualtor.dual_tor_mock import *                    # noqa F401

pytestmark = [
    pytest.mark.topology("t0")
]

logger = logging.getLogger(__name__)

SWSS_MUX_STATE_ACTIVE_CONFIG_FILE = '/tmp/swss_mux_state_active_config.json'
SWSS_MUX_STATE_STANDBY_CONFIG_FILE = '/tmp/swss_mux_state_standby_config.json'
SWSS_MUX_STATE_DEL_CONFIG_FILE = '/tmp/swss_mux_state_del_config.json'


def mux_state_configs(mux_intfs, state, op='SET'):
    """Generate mux cable state configs

    Args:
        mux_intfs (list): List of interface names that are connected to mux cable.
            Example: ['Ethernet0', 'Ethernet4', ...]
        state (str): State of mux cable, allowed values: 'active', 'standby'
        op (str, optional): Operation to be performed by swssconfig, allowed values: 'SET', 'DEL'. Defaults to 'SET'.

    Returns:
        list of dict: Returns mux state configs in a list of dict. Example:
            [
                {
                    'MUX_CABLE_TABLE:Ethernet0':
                        {
                            'state': 'active'
                        },
                    'OP': 'SET'
                },
                {
                    'MUX_CABLE_TABLE:Ethernet4':
                        {
                            'state': 'active'
                        },
                    'OP': 'SET'
                },
                ...
            ]
    """
    configs = []
    for intf in mux_intfs:
        config = {
            'MUX_CABLE_TABLE:{}'.format(intf):
                {
                    'state': state,
                },
            'OP': op
        }
        configs.append(config)
    return configs


def load_swss_config(dut, config_file):
    """Load swss config file specified by 'config_file' in swss docker using command 'swssconfig'

    Args:
        dut (obj): Object for interacting with DUT.
        config_file (str): Path and filename of the config file in swss docker container.
    """
    logger.info('Loading swss config {} ...'.format(config_file))
    dut.shell('docker exec swss sh -c "swssconfig {}"'.format(config_file))
    wait(10, 'for CRMs to be updated and corresponding codeflow finished')
    logger.info('Loading swss config {} done'.format(config_file))


def _swss_path(filename):
    """Helper function to transform swss config file path.

    Copy files using 'docker cp swss' won't work if the destination path in 'swss' docker is '/tmp'.
    This helper function is to transform path like '/tmp/filename.json' to '/filename.json'.

    Args:
        filename (str): Filename

    Returns:
        str: '/' + basename of filename.
    """
    return os.path.join('/', os.path.basename(filename))


@pytest.fixture(scope='module', autouse=True)
def swss_config_files(rand_selected_dut, tor_mux_intfs):            # noqa F811
    """This fixture is to generate/cleanup the swss config files in the swss docker.

    Args:
        rand_selected_dut (obj): Object for interacting with DUT.
        tor_mux_intfs (list): List of interface names that are connected to mux cable.
            Example: ['Ethernet0', 'Ethernet4', ...]
    """
    dut = rand_selected_dut
    swss_configs = [
        ('active', 'SET', SWSS_MUX_STATE_ACTIVE_CONFIG_FILE),
        ('standby', 'SET', SWSS_MUX_STATE_STANDBY_CONFIG_FILE),
        ('active', 'DEL', SWSS_MUX_STATE_DEL_CONFIG_FILE),
    ]
    for cfg in swss_configs:
        mux_config = mux_state_configs(tor_mux_intfs, cfg[0], op=cfg[1])
        dut.copy(content=json.dumps(mux_config, indent=4), dest=cfg[2])
        dut.shell('docker cp {} swss:{}'.format(cfg[2], _swss_path(cfg[2])))

    yield

    for cfg in swss_configs:
        dut.shell('docker exec swss sh -c "rm {}"'.format(_swss_path(cfg[2])))
        dut.file(path=cfg[2], state='absent')


@pytest.fixture(scope='module', autouse=True)
def config_crm_polling_interval(rand_selected_dut):
    dut = rand_selected_dut
    logger.info('Set CRM polling interval to 1 second')
    dut.shell('crm config polling interval 1')
    yield
    logger.info('Set CRM polling interval to 300 seconds')
    dut.shell('crm config polling interval 300')


def test_change_mux_state(
        apply_mock_dual_tor_tables,
        apply_mock_dual_tor_kernel_configs,
        rand_selected_dut,
        request):

    dut = rand_selected_dut

    wait(20, 'extra wait for presetup flow')

    # Apply mux active state
    load_swss_config(dut, _swss_path(SWSS_MUX_STATE_ACTIVE_CONFIG_FILE))
    load_swss_config(dut, _swss_path(SWSS_MUX_STATE_STANDBY_CONFIG_FILE))
    load_swss_config(dut, _swss_path(SWSS_MUX_STATE_ACTIVE_CONFIG_FILE))

    wait(10, 'extra wait for initial CRMs to be updated')

    crm_facts1 = dut.get_crm_facts()
    logger.info(json.dumps(crm_facts1, indent=4))

    # Set all mux state to 'standby'/'active' N times.
    for _ in range(request.config.getoption('--mux-stress-count')):
        load_swss_config(dut, _swss_path(SWSS_MUX_STATE_STANDBY_CONFIG_FILE))
        load_swss_config(dut, _swss_path(SWSS_MUX_STATE_ACTIVE_CONFIG_FILE))

    wait(10, 'extra wait for CRMs to be updated')

    crm_facts2 = dut.get_crm_facts()
    logger.info(json.dumps(crm_facts2, indent=4))

    # Check CRM values for leak
    unmatched_crm_facts = compare_crm_facts(crm_facts1, crm_facts2)
    pytest_assert(len(unmatched_crm_facts) == 0, 'Unmatched CRM facts: {}'
                  .format(json.dumps(unmatched_crm_facts, indent=4)))


def remove_neighbors(dut, neighbors, interface):
    """Helper function for removing specified neighbors.

    Args:
        dut (obj): Object for interacting with DUT.
        neighbors (dict): Dict of neighbors, key is neighbor IP address, value is neighbor MAC address.
        interface (str): Name of the interface that the neighbors to be removed.
    """
    logger.info('Removing neighbors...')
    cmds = []
    for neighbor in list(neighbors.keys()):
        cmds.append('ip -4 neigh del {} dev {}'.format(neighbor, interface))
    dut.shell_cmds(cmds=cmds)
    wait(2, 'for CRMs to be updated')
    logger.info('Removing neighbors done')


def add_neighbors(dut, neighbors, interface):
    """Helper function for removing specified neighbors.

    Args:
        dut (obj): Object for interacting with DUT.
        neighbors (dict): Dict of neighbors, key is neighbor IP address, value is neighbor MAC address.
        interface (str): Name of the interface that the neighbors to be removed.
    """
    logger.info('Adding neighbors...')
    cmds = []
    for ip, mac in list(neighbors.items()):
        cmds.append('ip -4 neigh replace {} lladdr {} dev {}'.format(ip, mac, interface))
    dut.shell_cmds(cmds=cmds)
    wait(2, 'for CRMs to be updated')
    logger.info('Adding neighbors done')


def test_flap_neighbor_entry_active(
        apply_mock_dual_tor_tables,
        apply_mock_dual_tor_kernel_configs,
        rand_selected_dut,
        tbinfo,
        request,
        mock_server_ip_mac_map):

    dut = rand_selected_dut

    vlan_interface_name = list(dut.get_extended_minigraph_facts(tbinfo)['minigraph_vlans'].keys())[0]

    # Apply mux active state
    load_swss_config(dut, _swss_path(SWSS_MUX_STATE_ACTIVE_CONFIG_FILE))

    wait(3, 'extra wait for initial CRMs to be updated')

    crm_facts1 = dut.get_crm_facts()
    logger.info(json.dumps(crm_facts1, indent=4))

    for _ in range(request.config.getoption('--mux-stress-count')):
        remove_neighbors(dut, mock_server_ip_mac_map, vlan_interface_name)
        add_neighbors(dut, mock_server_ip_mac_map, vlan_interface_name)

    wait(3, 'extra wait for CRMs to be updated')

    crm_facts2 = dut.get_crm_facts()
    logger.info(json.dumps(crm_facts2, indent=4))

    unmatched_crm_facts = compare_crm_facts(crm_facts1, crm_facts2)
    pytest_assert(len(unmatched_crm_facts) == 0, 'Unmatched CRM facts: {}'
                  .format(json.dumps(unmatched_crm_facts, indent=4)))


def test_flap_neighbor_entry_standby(
        apply_mock_dual_tor_tables,
        apply_mock_dual_tor_kernel_configs,
        rand_selected_dut,
        tbinfo,
        request,
        mock_server_ip_mac_map):

    dut = rand_selected_dut

    vlan_interface_name = list(dut.get_extended_minigraph_facts(tbinfo)['minigraph_vlans'].keys())[0]

    # Apply mux standby state
    load_swss_config(dut, _swss_path(SWSS_MUX_STATE_STANDBY_CONFIG_FILE))

    wait(3, 'extra wait for initial CRMs to be updated')

    crm_facts1 = dut.get_crm_facts()
    logger.info(json.dumps(crm_facts1, indent=4))

    for _ in range(request.config.getoption('--mux-stress-count')):
        remove_neighbors(dut, mock_server_ip_mac_map, vlan_interface_name)
        add_neighbors(dut, mock_server_ip_mac_map, vlan_interface_name)

    wait(3, 'extra wait for CRMs to be updated')

    crm_facts2 = dut.get_crm_facts()
    logger.info(json.dumps(crm_facts2, indent=4))

    unmatched_crm_facts = compare_crm_facts(crm_facts1, crm_facts2)
    pytest_assert(len(unmatched_crm_facts) == 0, 'Unmatched CRM facts: {}'
                  .format(json.dumps(unmatched_crm_facts, indent=4)))
