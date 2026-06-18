'''This script is to test the BGP Bounce Back Routing (BBR) feature default state after restart.
'''
import json
import logging
import time
import pytest
from jinja2 import Template
from natsort import natsorted
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common.utilities import delete_running_config
from tests.common.gu_utils import apply_patch, expect_op_success
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import format_json_patch_for_multiasic
from tests.common.config_reload import config_reload
from bgp_bbr_helpers import get_bbr_default_state


pytestmark = [
    pytest.mark.topology('t1'),
    pytest.mark.device_type('vs')
    ]


logger = logging.getLogger(__name__)

CONSTANTS_FILE = '/etc/sonic/constants.yml'


@pytest.fixture(scope='module', autouse=True)
def prepare_bbr_config_files(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    bgp_bbr_config = Template(open("./bgp/templates/bgp_bbr_config.json.j2").read())
    duthost.copy(content=bgp_bbr_config.render(BGP_BBR_STATUS='disabled'), dest='/tmp/disable_bbr.json')
    duthost.copy(content=bgp_bbr_config.render(BGP_BBR_STATUS='enabled'), dest='/tmp/enable_bbr.json')
    yield
    del_bbr_json = [{"BGP_BBR": {}}]
    delete_running_config(del_bbr_json, duthost)


@pytest.fixture(scope='module')
def bbr_default_state(setup):
    return setup['bbr_default_state']


def add_bbr_config_to_running_config(duthost, status):
    logger.info('Add BGP_BBR config to running config')
    json_patch = [
        {
            "op": "add",
            "path": "/BGP_BBR",
            "value": {
                "all": {
                    "status": "{}".format(status)
                }
            }
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)
    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))
    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)
    time.sleep(3)


def config_bbr_by_gcu(duthost, status):
    logger.info('Config BGP_BBR by GCU cmd')
    json_patch = [
        {
            "op": "replace",
            "path": "/BGP_BBR/all/status",
            "value": "{}".format(status)
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)
    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))
    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)
    time.sleep(3)


def disable_bbr(duthost, namespace):
    logger.info('Disable BGP_BBR')
    # gcu doesn't support multi-asic for now, use sonic-cfggen instead
    if namespace:
        logger.info('Disable BGP_BBR in namespace {}'.format(namespace))
        duthost.shell('sonic-cfggen {} -j /tmp/disable_bbr.json -w '.format('-n ' + namespace))
        time.sleep(3)
    else:
        config_bbr_by_gcu(duthost, "disabled")


def get_bbr_status_from_config_db(duthost, namespace):
    namespace_prefix = '-n ' + namespace if namespace else ''
    return duthost.shell(
        'sonic-db-cli {} CONFIG_DB HGET "BGP_BBR|all" "status"'.format(namespace_prefix)
    )['stdout'].strip().strip('"')


def get_external_allowas_lines(duthost, namespace):
    bgp_cmd = 'vtysh -c "show running-configuration bgp"'
    cmd = duthost.get_vtysh_cmd_for_namespace(bgp_cmd, namespace)
    output = duthost.shell(cmd, module_ignore_errors=True)['stdout']
    return [
        line.strip() for line in output.splitlines()
        if 'allowas' in line and 'INTERNAL_PEER' not in line
    ]


def verify_bbr_disabled(duthost, namespace):
    bbr_status = get_bbr_status_from_config_db(duthost, namespace)
    pytest_assert(bbr_status == 'disabled',
                  "BGP_BBR status is '{}', expected 'disabled'".format(bbr_status))

    external_allowas = get_external_allowas_lines(duthost, namespace)
    pytest_assert(not external_allowas,
                  "BBR allowas-in found on external peers: {}".format(external_allowas))


@pytest.fixture
def config_bbr_disabled(duthosts, setup, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    disable_bbr(duthost, setup['tor1_namespace'])


@pytest.fixture(scope='module')
def setup(duthosts, rand_one_dut_hostname, tbinfo, nbrhosts):
    duthost = duthosts[rand_one_dut_hostname]
    constants_stat = duthost.stat(path=CONSTANTS_FILE)
    if not constants_stat['stat']['exists']:
        pytest.skip('No file {} on DUT, BBR is not supported')

    bbr_supported, bbr_default_state = get_bbr_default_state(duthost)
    if not bbr_supported:
        pytest.skip('BGP BBR is not supported')
    if bbr_default_state != 'disabled':
        pytest.skip('Test only applies when constants.yml BBR default is disabled')

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    tor_neighbors = natsorted([neighbor for neighbor in list(nbrhosts.keys()) if neighbor.endswith('T0')])
    pytest_assert(tor_neighbors, 'No T0 neighbor found in topology')
    tor1 = tor_neighbors[0]

    tor1_namespace = DEFAULT_NAMESPACE
    for _, neigh in list(mg_facts['minigraph_neighbors'].items()):
        if tor1 == neigh['name']:
            tor1_namespace = neigh.get('namespace', DEFAULT_NAMESPACE)
            break

    setup_info = {
        'bbr_default_state': bbr_default_state,
        'tor1': tor1,
        'tor1_namespace': tor1_namespace,
    }
    if not setup_info['tor1_namespace']:
        logger.info('non multi-asic environment, add bbr config to running config using gcu cmd')
        add_bbr_config_to_running_config(duthost, bbr_default_state)
    logger.info('setup_info: {}'.format(json.dumps(setup_info, indent=2)))
    return setup_info


@pytest.mark.disable_loganalyzer
def test_bbr_disabled_constants_yml_default(duthosts, rand_one_dut_hostname, setup, config_bbr_disabled, loganalyzer):
    duthost = duthosts[rand_one_dut_hostname]
    duthost.shell("sudo config save -y")
    config_reload(duthost, safe_reload=True)
    verify_bbr_disabled(duthost, setup['tor1_namespace'])
