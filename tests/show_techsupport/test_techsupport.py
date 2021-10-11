import os
import pprint
import pytest
import time

import logging

from random import randint
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from tests.common.utilities import wait_until

from log_messages import *

import tech_support_cmds as cmds 

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

SUCCESS_CODE = 0
DEFAULT_LOOP_RANGE = 2
DEFAULT_LOOP_DELAY = 2

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
def acl_setup(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    setup fixture gathers all test required information from DUT facts and testbed
    :param duthost: DUT host object
    :return: dictionary with all test required information
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
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
def acl(duthosts, enum_rand_one_per_hwsku_frontend_hostname, acl_setup):
    """
    setup/teardown ACL rules based on test class requirements
    :param duthost: DUT host object
    :param acl_setup: setup information
    :return:
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    acl_facts = duthost.acl_facts()["ansible_facts"]["ansible_acl_facts"]
    pytest_require(ACL_TABLE_NAME in acl_facts, "{} acl table not exists")

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
def neighbor_ip(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    # ptf-32 topo is not supported in mirroring
    if tbinfo['topo']['name'] == 'ptf32':
        pytest.skip('Unsupported Topology')
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
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
def mirror_setup(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    setup fixture
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    duthost.command('mkdir -p {}'.format(MIRROR_RUN_DIR))
    tmp_path = duthost.tempfile(path=MIRROR_RUN_DIR, state='directory', prefix='mirror', suffix="")['path']

    setup_info = {
        'dut_tmp_dir': tmp_path,
    }
    yield setup_info


@pytest.fixture(scope='function')
def gre_version(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic_type = duthost.facts['asic_type']
    if asic_type in ["mellanox"]:
        SESSION_INFO['gre'] = 0x8949  # Mellanox specific
    elif asic_type in ["barefoot"]:
        SESSION_INFO['gre'] = 0x22EB  # barefoot specific
    else:
        SESSION_INFO['gre'] = 0x6558


@pytest.fixture(scope='function')
def mirroring(duthosts, enum_rand_one_per_hwsku_frontend_hostname, neighbor_ip, mirror_setup, gre_version):
    """
    fixture gathers all configuration fixtures
    :param duthost: DUT host
    :param mirror_setup: mirror_setup fixture
    :param mirror_config: mirror_config fixture
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
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


@pytest.fixture(scope='function', params=['acl', 'mirroring'])
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


def test_techsupport(request, config, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    test the "show techsupport" command in a loop
    :param config: fixture to configure additional setups_list on dut.
    :param duthost: DUT host
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    loop_range = request.config.getoption("--loop_num") or DEFAULT_LOOP_RANGE
    loop_delay = request.config.getoption("--loop_delay") or DEFAULT_LOOP_DELAY
    since = request.config.getoption("--logs_since") or str(randint(1, 5)) + " minute ago"

    logger.debug("Loop_range is {} and loop_delay is {}".format(loop_range, loop_delay))

    for i in range(loop_range):
        logger.debug("Running show techsupport ... ")
        wait_until(300, 20, execute_command, duthost, str(since))
        tar_file = [j for j in pytest.tar_stdout.split('\n') if j != ''][-1]
        stdout = duthost.command("rm -rf {}".format(tar_file))
        logger.debug("Sleeping for {} seconds".format(loop_delay))
        time.sleep(loop_delay)


def add_asic_arg(format_str, cmds_list, asic_num):
    """ 
    Add ASIC specific arg using the supplied string formatter 

    New commands are added for each ASIC. In case of a regex
    paramter, new regex is created for each ASIC.
    """
    updated_cmds = []
    for cmd in cmds_list:
        if isinstance(cmd, str):
            if "{}" in cmd:
                if asic_num == 1:
                    updated_cmds.append(cmd.format(""))
                else:
                    for asic in range(0, asic_num):
                        asic_arg = format_str.format(asic)
                        updated_cmds.append(cmd.format(asic_arg))
            else:
                updated_cmds.append(cmd)
        else:
            if "{}" in cmd.pattern:
                if asic_num == 1:
                    mod_pattern = cmd.pattern.format("")
                    updated_cmds.append(re.compile(mod_pattern))
                else:
                    for asic in range(0, asic_num):
                        asic_arg = format_str.format(asic)
                        mod_pattern = cmd.pattern.format(asic_arg)
                        updated_cmds.append(re.compile(mod_pattern))
            else:
                updated_cmds.append(cmd)
    return updated_cmds


@pytest.fixture(scope='function')
def commands_to_check(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Prepare a list of commands to be expected in the 
    show techsupport output. All the expected commands are 
    categorized into groups. 

    For multi ASIC platforms, command strings are generated based on
    the number of ASICs.

    Also adds hardware specific commands

    Returns:
        A dict of command groups with each group containing a list of commands
    """

    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    num = duthost.num_asics()

    cmds_to_check = {
        "cp_proc_files": cmds.copy_proc_files,
        "show_platform_cmds": cmds.show_platform_cmds,
        "ip_cmds": cmds.ip_cmds,
        "bridge_cmds": cmds.bridge_cmds,
        "frr_cmds": add_asic_arg("  -n  {}", cmds.frr_cmds, num),
        "bgp_cmds": add_asic_arg("  -n  {}", cmds.bgp_cmds, num),
        "nat_cmds": cmds.nat_cmds,
        "bfd_cmds": add_asic_arg("  -n  {}", cmds.bfd_cmds, num),
        "redis_db_cmds": add_asic_arg("asic{} ", cmds.redis_db_cmds, num),
        "docker_cmds": add_asic_arg("{}", cmds.docker_cmds_201911 if '201911' in duthost.os_version else cmds.docker_cmds, num),
        "misc_show_cmds": add_asic_arg("asic{} ", cmds.misc_show_cmds, num),
        "misc_cmds": cmds.misc_cmds,
    }

    if duthost.facts["asic_type"] == "broadcom":
        cmds_to_check.update(
            {
                "broadcom_cmd_bcmcmd": 
                    add_asic_arg(" -n {}", cmds.broadcom_cmd_bcmcmd, num),
                "broadcom_cmd_misc": 
                    add_asic_arg("{}", cmds.broadcom_cmd_misc, num),
                "copy_config_cmds": 
                    add_asic_arg("/{}", cmds.copy_config_cmds, num),
            }
        )
    # Remove /proc/dma for armh
    elif duthost.facts["asic_type"] == "marvell":
        if 'armhf-' in duthost.facts["platform"]:
            cmds.copy_proc_files.remove("/proc/dma")

    return cmds_to_check


def check_cmds(cmd_group_name, cmd_group_to_check, cmdlist):
    """ 
    Check commands within a group against the command list 

    Returns: list commands not found
    """

    cmd_not_found = defaultdict(list)
    ignore_set = cmds.ignore_list.get(cmd_group_name)
    for cmd_name in cmd_group_to_check:
        found = False
        cmd_str = cmd_name if isinstance(cmd_name, str) else cmd_name.pattern
        logger.info("Checking for {}".format(cmd_str))

        for command in cmdlist:
            if isinstance(cmd_name, str):
                result = cmd_name in command
            else:
                result = cmd_name.search(command)
            if result:
                found = True
                break

        if not found:
            if not ignore_set or cmd_str not in ignore_set:
                cmd_not_found[cmd_group_name].append(cmd_str)

    return cmd_not_found


def test_techsupport_commands(
    duthosts, enum_rand_one_per_hwsku_frontend_hostname, commands_to_check
):
    """
    This test checks list of commands that will be run when executing
    'show techsupport' CLI against a standard expected list of commands
    to run.

    The test invokes show techsupport with noop option, which just
    returns the list of commands that will be run when collecting
    tech support data.

    Args:
    commands_to_check: contains a dict of command groups with each
    group containing a list of related commands.
    """

    cmd_not_found = defaultdict(list)
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    stdout = duthost.shell(
        'sudo generate_dump -n | grep -v "^mkdir\|^rm\|^tar\|^gzip"'
    )

    pytest_assert(stdout['rc'] == 0, 'generate_dump command failed')

    cmd_list = stdout["stdout_lines"]

    for cmd_group_name, cmd_group_to_check in commands_to_check.items():
        cmd_not_found.update(
            check_cmds(cmd_group_name, cmd_group_to_check, cmd_list)
        )

    pytest_assert(len(cmd_not_found) == 0, cmd_not_found)
