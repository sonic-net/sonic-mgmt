import pytest
import os
import pprint
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
import time
from random import randint
from tests.common.utilities import wait_until
from log_messages import *
import logging
logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

SUCCESS_CODE = 0
DEFAULT_LOOP_RANGE = 10
DEFAULT_LOOP_DELAY = 10

pytest.tar_stdout = ""

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
FILES_DIR = os.path.join(BASE_DIR, 'files')
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')

ACL_RUN_DIR = os.path.basename('acl_tmp')
ACL_RULES_FULL_TEMPLATE = 'acltb_test_rules.j2'
ACL_RULE_PERSISTENT_TEMPLATE = 'acl_rule_persistent.json.j2'
ACL_REMOVE_RULES_FILE = 'acl_rules_del.json'
ACL_RULE_PERSISTENT_FILE = 'acl_rule_persistent.json'
ACL_RULE_PERSISTENT_DEL_FILE = 'acl_rule_persistent-del.json'
ACL_TABLE_NAME = 'DATAACL'
MIRROR_RUN_DIR = os.path.basename('mirror_tmp')

EVERFLOW_TABLE_NAME = "EVERFLOW"
SESSION_INFO = {
    'name': "test_session_1",
    'src_ip': "1.1.1.1",
    'dst_ip': "2.2.2.2",
    'ttl': "1",
    'dscp': "8",
    'gre': "0x8949",
    'queue': "0"
}

# ACL PART #


def setup_acl_rules(duthost, acl_setup):
    """
    setup rules on DUT
    :param dut: DUT host
    :param setup: setup information
    :param acl_table: acl table creating fixture
    :return:
    """

    name = ACL_TABLE_NAME
    dut_conf_file_path = os.path.join(acl_setup['dut_tmp_dir'], 'acl_rules_{}.json'.format(name))

    logger.info('Generating configurations for ACL rules, ACL table {}'.format(name))
    extra_vars = {
        'acl_table_name':  name,
    }
    logger.info('Extra variables for ACL table:\n{}'.format(pprint.pformat(extra_vars)))
    duthost.host.options['variable_manager'].extra_vars.update(extra_vars)

    duthost.template(src=os.path.join(TEMPLATE_DIR, ACL_RULES_FULL_TEMPLATE),
                                        dest=dut_conf_file_path)

    logger.info('Applying {}'.format(dut_conf_file_path))
    duthost.command('config acl update full {}'.format(dut_conf_file_path))


@pytest.fixture(scope='function')
def acl_setup(duthost):
    """
    setup fixture gathers all test required information from DUT facts and testbed
    :param duthost: DUT host object
    :return: dictionary with all test required information
    """
    logger.info('Creating temporary folder for test {}'.format(ACL_RUN_DIR))
    duthost.command("mkdir -p {}".format(ACL_RUN_DIR))
    tmp_path = duthost.tempfile(path=ACL_RUN_DIR, state='directory', prefix='acl', suffix="")['path']

    setup_information = {
        'dut_tmp_dir': tmp_path,
    }
    yield setup_information


def teardown_acl(dut, acl_setup):
    """
    teardown ACL rules after test by applying empty configuration
    :param dut: DUT host object
    :param setup: setup information
    :return:
    """
    dst = acl_setup['dut_tmp_dir']
    logger.info('Removing all ACL rules')
    # copy rules remove configuration
    dut.copy(src=os.path.join(FILES_DIR, ACL_REMOVE_RULES_FILE), dest=dst)
    remove_rules_dut_path = os.path.join(dst, ACL_REMOVE_RULES_FILE)
    # remove rules
    dut.command('config acl update full {}'.format(remove_rules_dut_path))


@pytest.fixture(scope='function')
def acl(duthost, acl_setup):
    """
    setup/teardown ACL rules based on test class requirements
    :param duthost: DUT host object
    :param acl_setup: setup information
    :return:
    """
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix='acl')
    loganalyzer.load_common_config()

    try:
        loganalyzer.expect_regex = [LOG_EXPECT_ACL_RULE_CREATE_RE]
        with loganalyzer:
            setup_acl_rules(duthost, acl_setup)
    except LogAnalyzerError as err:
        # cleanup config DB in case of log analysis error
        teardown_acl(duthost, acl_setup)
        raise err

    try:
        yield
    finally:
        loganalyzer.expect_regex = [LOG_EXPECT_ACL_RULE_REMOVE_RE]
        with loganalyzer:
            teardown_acl(duthost, acl_setup)


# MIRRORING PART #

@pytest.fixture(scope='function')
def neighbor_ip(duthost, tbinfo):
    # ptf-32 topo is not supported in mirroring
    if tbinfo['topo']['name'] == 'ptf32':
        pytest.skip('Unsupported Topology')
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    dst_ip = None
    if mg_facts["minigraph_portchannel_interfaces"]:
        dst_ip = mg_facts["minigraph_portchannel_interfaces"][0]['peer_addr']
    else:
        peer_addr_list = [(item['peer_addr']) for item in mg_facts["minigraph_interfaces"] if 'peer_addr' in item]
        if peer_addr_list:
            dst_ip = peer_addr_list[0]

    if dst_ip is None:
        pytest.skip("No neighbor ip available. Skipping test.")

    yield str(dst_ip)


@pytest.fixture(scope='function')
def mirror_setup(duthost):
    """
    setup fixture
    """
    duthost.command('mkdir -p {}'.format(MIRROR_RUN_DIR))
    tmp_path = duthost.tempfile(path=MIRROR_RUN_DIR, state='directory', prefix='mirror', suffix="")['path']

    setup_info = {
        'dut_tmp_dir': tmp_path,
    }
    yield setup_info


@pytest.fixture(scope='function')
def gre_version(duthost):
    asic_type = duthost.facts['asic_type']
    if asic_type in ["mellanox"]:
        SESSION_INFO['gre'] = 0x8949  # Mellanox specific
    else:
        SESSION_INFO['gre'] = 0x6558


@pytest.fixture(scope='function')
def mirroring(duthost, neighbor_ip, mirror_setup, gre_version):
    """
    fixture gathers all configuration fixtures
    :param duthost: DUT host
    :param mirror_setup: mirror_setup fixture
    :param mirror_config: mirror_config fixture
    """
    logger.info("Adding mirror_session to DUT")
    acl_rule_file = os.path.join(mirror_setup['dut_tmp_dir'], ACL_RULE_PERSISTENT_FILE)
    extra_vars = {
        'acl_table_name':  EVERFLOW_TABLE_NAME,
    }
    logger.info('Extra variables for MIRROR table:\n{}'.format(pprint.pformat(extra_vars)))
    duthost.host.options['variable_manager'].extra_vars.update(extra_vars)

    duthost.template(src=os.path.join(TEMPLATE_DIR, ACL_RULE_PERSISTENT_TEMPLATE), dest=acl_rule_file)
    duthost.command('config mirror_session add {} {} {} {} {} {} {}'
    .format(SESSION_INFO['name'], SESSION_INFO['src_ip'], neighbor_ip,
     SESSION_INFO['dscp'], SESSION_INFO['ttl'], SESSION_INFO['gre'], SESSION_INFO['queue']))

    logger.info('Loading acl mirror rules ...')
    load_rule_cmd = "acl-loader update full {} --session_name={}".format(acl_rule_file, SESSION_INFO['name'])
    duthost.command('{}'.format(load_rule_cmd))

    try:
        yield
    finally:
        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix='acl')
        loganalyzer.load_common_config()

        try:
            loganalyzer.expect_regex = [LOG_EXCEPT_MIRROR_SESSION_REMOVE]
            with loganalyzer:
                teardown_mirroring(duthost, mirror_setup['dut_tmp_dir'])
        except LogAnalyzerError as err:
            raise err


def teardown_mirroring(dut, tmp_path):
    """
    teardown EVERFLOW rules after test by applying empty configuration
    :param dut: DUT host object
    :param setup: setup information
    :return:
    """
    logger.info('Removing Mirroring rules')
    # copy rules remove configuration
    dst = os.path.join(tmp_path, ACL_RULE_PERSISTENT_DEL_FILE)
    dut.copy(src=os.path.join(FILES_DIR, ACL_RULE_PERSISTENT_DEL_FILE), dest=dst)
    dut.command("acl-loader update full {}".format(dst))
    dut.command('config mirror_session remove {}'.format(SESSION_INFO['name']))


@pytest.fixture(scope='function', params=['acl', 'mirroring'], autouse=True)
def config(request):
    """
    fixture to add configurations on setup by received parameters.
    The parameters expected in request are the avaiable additional configurations.
    e.g. : test_techsupport[acl]
    """
    return request.getfixturevalue(request.param)


def execute_command(duthost, since):
    """
    Function to execute show techsupport command
    :param duthost: DUT
    :param since: since string enterd by user
    """
    stdout = duthost.command("show techsupport --since={}".format('"' + since + '"'))
    if stdout['rc'] == SUCCESS_CODE:
        pytest.tar_stdout = stdout['stdout']
    return stdout['rc'] == SUCCESS_CODE


def test_techsupport(request, config, duthost):
    """
    test the "show techsupport" command in a loop
    :param config: fixture to configure additional setups_list on dut.
    :param duthost: DUT host
    """
    loop_range = request.config.getoption("--loop_num") or DEFAULT_LOOP_RANGE
    loop_delay = request.config.getoption("--loop_delay") or DEFAULT_LOOP_DELAY
    since = request.config.getoption("--logs_since") or str(randint(1, 23)) + " minute ago"

    logger.debug("Loop_range is {} and loop_delay is {}".format(loop_range, loop_delay))

    for i in range(loop_range):
        logger.debug("Running show techsupport ... ")
        wait_until(300, 20, execute_command, duthost, str(since))
        tar_file = [j for j in pytest.tar_stdout.split('\n') if j != ''][-1]
        stdout = duthost.command("rm -rf {}".format(tar_file))
        logger.debug("Sleeping for {} seconds".format(loop_delay))
        time.sleep(loop_delay)
