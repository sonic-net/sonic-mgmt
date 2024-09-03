'''This script is to test the BGP Bounce Back Routing (BBR) feature of SONiC.
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
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.config_reload import config_reload

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

    bbr_default_state = 'disabled'
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    tor_neighbors = natsorted([neighbor for neighbor in list(nbrhosts.keys()) if neighbor.endswith('T0')])
    tor1 = tor_neighbors[0]

    tor1_namespace = DEFAULT_NAMESPACE
    for dut_port, neigh in list(mg_facts['minigraph_neighbors'].items()):
        if tor1 == neigh['name']:
            tor1_namespace = neigh['namespace']
            break

    setup_info = {
        'bbr_default_state': bbr_default_state,
        'tor1_namespace': tor1_namespace,
    }

    if not setup_info['tor1_namespace']:
        logger.info('non multi-asic environment, add bbr config to running config using gcu cmd')
        add_bbr_config_to_running_config(duthost, bbr_default_state)

    logger.info('setup_info: {}'.format(json.dumps(setup_info, indent=2)))

    return setup_info


def test_bbr_disabled_constants_yml_default(duthosts, rand_one_dut_hostname, setup, config_bbr_disabled):
    duthost = duthosts[rand_one_dut_hostname]
    duthost.shell("sudo config save -y")
    config_reload(duthost)
    is_bbr_enabled = duthost.shell("show runningconfiguration bgp | grep allowas", module_ignore_errors=True)['stdout']
    pytest_assert(is_bbr_enabled == "", "BBR is not disabled by default.")
