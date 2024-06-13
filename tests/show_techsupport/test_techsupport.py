import os
import pprint
import pytest
import re
import time
import logging
import allure
import tech_support_cmds as cmds
from random import randint
from collections import defaultdict
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from tests.common.utilities import wait_until
from log_messages import LOG_EXPECT_ACL_RULE_CREATE_RE, LOG_EXPECT_ACL_RULE_REMOVE_RE, LOG_EXCEPT_MIRROR_SESSION_REMOVE
from pkg_resources import parse_version

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

SUCCESS_CODE = 0
DEFAULT_LOOP_RANGE = 2
DEFAULT_LOOP_DELAY = 2
MIN_FILES_NUM = 50

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

DPU_PLATFORM_DUMP_FILES = ["sysfs_tree", "sys_version", "dmesg",
                           "dmidecode", "lsmod", "lspci", "top", "bin/platform-dump.sh"]

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
        'acl_table_name': name,
    }
    logger.info('Extra variables for ACL table:\n{}'.format(pprint.pformat(extra_vars)))
    duthost.host.options['variable_manager'].extra_vars.update(extra_vars)

    duthost.template(src=os.path.join(TEMPLATE_DIR, ACL_RULES_FULL_TEMPLATE), dest=dut_conf_file_path)

    logger.info('Applying {}'.format(dut_conf_file_path))
    duthost.command('config acl update full {}'.format(dut_conf_file_path))


def check_dut_is_dpu(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Check dut is dpu or not. True when dut is dpu, else False
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    return config_facts['DEVICE_METADATA']['localhost'].get('switch_type', '') == 'dpu'


@pytest.fixture(scope='module')
def skip_on_dpu(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    When dut is dpu, skip the case
    """
    if check_dut_is_dpu(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        pytest.skip("Skip the test, as it is not supported on DPU.")


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
    elif asic_type in ["cisco-8000"]:
        SESSION_INFO['gre'] = 0x88BE  # ERSPAN type-2
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
        'acl_table_name': EVERFLOW_TABLE_NAME,
    }
    logger.info('Extra variables for MIRROR table:\n{}'.format(pprint.pformat(extra_vars)))
    duthost.host.options['variable_manager'].extra_vars.update(extra_vars)

    duthost.template(src=os.path.join(TEMPLATE_DIR, ACL_RULE_PERSISTENT_TEMPLATE), dest=acl_rule_file)
    duthost.command('config mirror_session add {} {} {} {} {} {} {}'.format(SESSION_INFO['name'],
                                                                            SESSION_INFO['src_ip'], neighbor_ip,
                                                                            SESSION_INFO['dscp'], SESSION_INFO['ttl'],
                                                                            SESSION_INFO['gre'], SESSION_INFO['queue'])
                    )

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
    opt = "-r" if duthost.sonic_release not in ["201811", "201911"] else ""
    result = duthost.command(
        "show techsupport {} --since={}".format(opt, '"' + since + '"'),
        module_ignore_errors=True
    )
    if result['rc'] != SUCCESS_CODE:
        pytest.fail('Failed to create techsupport. \nstdout:{}. \nstderr:{}'.format(result['stdout'], result['stderr']))
    pytest.tar_stdout = result['stdout']
    return True


def extract_file_from_tar_file(duthost, tar_file, is_need_create_target_folder=False):
    extracted_dump_folder_name = tar_file.split('/')[-1].split('.')[0]
    target_folder = '/tmp/'
    if is_need_create_target_folder:
        target_folder = f'/tmp/{extracted_dump_folder_name}'
        create_target_folder = f"mkdir -p {target_folder}"
        duthost.command(create_target_folder)

    duthost.command(f"tar -xf {tar_file} -C {target_folder}")
    extracted_dump_folder_path = f'/tmp/{extracted_dump_folder_name}'
    return extracted_dump_folder_name, extracted_dump_folder_path


def validate_platform_dump_files(duthost, dump_folder_path, platform_dump_folder_name, platform_dump_name):
    """
    Validate platform-dump.tar.gz includes the following files:
     sysfs_tree, sys_version, dmesg, dmidecode, lsmod, lspci, top, bin/platform-dump.sh
    :param duthost: duthost object
    :param dump_folder_path: path to folder which has extracted dump file content
    :return: AssertionError in case of failure, else None
    """
    platform_dump_path = '{}/{}/'.format(dump_folder_path, platform_dump_folder_name)

    logger.info("extract {}".format(platform_dump_name))
    duthost.shell("tar -xf {}{} -C {} ".format(platform_dump_path, platform_dump_name, platform_dump_path))

    platform_dump_files_list = []
    print_last_column = "awk '{print $NF}'"
    cmd_list_file_name = "ls -l {folder_path} | grep '^{file_type}' | {print_last_column}"
    platform_dump_folders = duthost.shell(cmd_list_file_name.format(
        folder_path=platform_dump_path, file_type='d', print_last_column=print_last_column))["stdout_lines"]

    def collect_platform_dump_files(folder_name):
        temp_dump_folder_path = os.path.join(platform_dump_path, folder_name) if folder_name else platform_dump_path
        platform_dump_files = duthost.shell(cmd_list_file_name.format(
            folder_path=temp_dump_folder_path, file_type='-', print_last_column=print_last_column))["stdout_lines"]
        for file in platform_dump_files:
            dump_file_name = file.strip() if not folder_name else "{}/{}".format(folder_name, file.strip())
            platform_dump_files_list.append(dump_file_name)

    logger.info("Collect dump file name for {}".format(platform_dump_path))
    collect_platform_dump_files('')

    for folder_name in platform_dump_folders:
        logger.info("Collect dump file name for {}/{}".format(platform_dump_path, folder_name))
        collect_platform_dump_files(folder_name.strip())

    for dump_file in DPU_PLATFORM_DUMP_FILES:
        assert dump_file in platform_dump_files_list, "dump file {} doesn't exist in {}".format(
            dump_file, platform_dump_files_list)


def gen_dump_file(duthost, since):
    logger.debug("Running show techsupport ... ")
    wait_until(300, 20, 0, execute_command, duthost, str(since))
    tar_file = [j for j in pytest.tar_stdout.split('\n') if j != ''][-1]
    return tar_file


def test_techsupport(request, config, duthosts, enum_rand_one_per_hwsku_frontend_hostname, skip_on_dpu):  # noqa F811
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
        tar_file = gen_dump_file(duthost, since)
        duthost.command("tar -xf {} -C /tmp/".format(tar_file))
        extracted_dump_folder_name = tar_file.lstrip('/var/dump/').split('.')[0]
        extracted_dump_folder_path = '/tmp/{}'.format(extracted_dump_folder_name)
        try:
            validate_dump_file_content(duthost, extracted_dump_folder_path)
        except AssertionError as err:
            raise AssertionError(err)
        finally:
            duthost.command("rm -rf {}".format(tar_file))
            duthost.command("rm -rf {}".format(extracted_dump_folder_path))
            logger.debug("Sleeping for {} seconds".format(loop_delay))
            time.sleep(loop_delay)


def validate_dump_file_content(duthost, dump_folder_path):
    """
    Validate generated dump file content
    :param duthost: duthost object
    :param dump_folder_path: path to folder which has extracted dump file content
    :return: AssertionError in case of failure, else None
    """
    dump = duthost.command("ls {}/dump/".format(dump_folder_path))["stdout_lines"]
    etc = duthost.command("ls {}/etc/".format(dump_folder_path))["stdout_lines"]
    log = duthost.command("ls {}/log/".format(dump_folder_path))["stdout_lines"]

    # Check sai_sdk_dump only for mellanox platform
    if duthost.facts['asic_type'] in ["mellanox"]:
        sai_sdk_dump = duthost.command("ls {}/sai_sdk_dump/".format(dump_folder_path))["stdout_lines"]
        assert len(sai_sdk_dump), "Folder 'sai_sdk_dump' in dump archive is empty. Expected not empty folder"
    assert len(dump) > MIN_FILES_NUM, "Seems like not all expected files available in 'dump' folder in dump archive. " \
                                      "Test expects not less than 50 files. Available files: {}".format(dump)
    assert len(etc) > MIN_FILES_NUM, "Seems like not all expected files available in 'etc' folder in dump archive. " \
                                     "Test expects not less than 50 files. Available files: {}".format(etc)
    assert len(log), "Folder 'log' in dump archive is empty. Expected not empty folder"


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
        "frr_cmds": add_asic_arg(" -n {}", cmds.frr_cmds, num),
        "bgp_cmds": add_asic_arg(" -n {}", cmds.bgp_cmds, num),
        "evpn_cmds": add_asic_arg(" -n {}", cmds.evpn_cmds, num),
        "nat_cmds": cmds.nat_cmds,
        "bfd_cmds": add_asic_arg(" -n {}", cmds.bfd_cmds, num),
        "redis_db_cmds": add_asic_arg("asic{} ", cmds.redis_db_cmds, num),
        "misc_show_cmds": add_asic_arg("asic{} ", cmds.misc_show_cmds, num),
        "misc_cmds": cmds.misc_cmds,
    }

    if '201911' in duthost.os_version:
        docker_cmds = cmds.docker_cmds_201911
    elif duthost.facts['router_type'] == 'spinerouter':
        docker_cmds = cmds.docker_cmds_t2
    else:
        docker_cmds = cmds.docker_cmds

    cmds_to_check.update(
        {
            "docker_cmds":
                add_asic_arg("{}", docker_cmds, num)}
    )

    # /proc/sched_debug has been moved to debugfs starting with 5.13.0, and is
    # currently collected only on the older kernel versions
    if parse_version(duthost.kernel_version) < parse_version('5.13.0'):
        cmds.copy_proc_files.append("/proc/sched_debug")

    if duthost.facts["asic_type"] == "broadcom":
        if duthost.facts.get("platform_asic") == "broadcom-dnx":
            asic_cmds = cmds.broadcom_cmd_bcmcmd_dnx
        else:
            asic_cmds = cmds.broadcom_cmd_bcmcmd_xgs
        cmds_to_check.update(
            {
                "broadcom_cmd_bcmcmd":
                    add_asic_arg(" -n {}", asic_cmds, num),
                "broadcom_cmd_misc":
                    add_asic_arg("{}", cmds.broadcom_cmd_misc, num),
            }
        )
        if duthost.facts["platform"] in ['x86_64-cel_e1031-r0',
                                         'x86_64-arista_720dt_48s']:
            cmds_to_check.update(
                {
                    "copy_config_cmds":
                        add_asic_arg("/{}", cmds.copy_config_cmds_no_qos, num),
                }
            )
        else:
            cmds_to_check.update(
                {
                    "copy_config_cmds":
                        add_asic_arg("/{}", cmds.copy_config_cmds, num),
                }
            )
    # Remove /proc/dma for armh
    elif duthost.facts["asic_type"] == "marvell":
        if 'armhf-' in duthost.facts["platform"]:
            cmds.copy_proc_files.remove("/proc/dma")

    return cmds_to_check


def check_cmds(cmd_group_name, cmd_group_to_check, cmdlist, strbash_in_cmdlist):
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
                if strbash_in_cmdlist:
                    result = (cmd_name.replace('"', '\\"') in command)
                else:
                    result = (cmd_name in command)
            else:
                if strbash_in_cmdlist:
                    new_pattern = re.compile(cmd_name.pattern.replace('"', '\\\\"'))
                    result = new_pattern.search(command)
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
        duthosts, enum_rand_one_per_hwsku_frontend_hostname, commands_to_check, skip_on_dpu):  # noqa F811
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

    stdout = duthost.shell(r'sudo generate_dump -n | grep -v "^mkdir\|^rm\|^tar\|^gzip"')

    pytest_assert(stdout['rc'] == 0, 'generate_dump command failed')

    cmd_list = stdout["stdout_lines"]

    strbash_in_cmdlist = False
    for command in cmd_list:
        if "bash -c" in command:
            strbash_in_cmdlist = True
            break

    for cmd_group_name, cmd_group_to_check in list(commands_to_check.items()):
        cmd_not_found.update(
            check_cmds(cmd_group_name, cmd_group_to_check, cmd_list, strbash_in_cmdlist)
        )

    error_message = ''
    for key, commands in cmd_not_found.items():
        error_message += "Commands not found for '{}': ".format(key) + '; '.join(commands) + '\n'

    pytest_assert(len(cmd_not_found) == 0, error_message)


def test_techsupport_on_dpu(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    This test is to check some files exist or not in the dump file generated by show techsupport on DPU
    1. Generate dump file by " show techsupport -r --since 'xx xxx xxx' " ( select 1-5 minutes ago randomly)
    2. Validate that the dump file contains platform-dump.tar.gz archive
    3. Validate that platform-dump.tar.gz includes the following files:
         sysfs_tree, sys_version, dmesg, dmidecode, lsmod, lspci, top, bin/platform-dump.sh
    4. Validate that the dump file contains sai_sdk_dump folder
    5. Validate that sai_sdk_dump is not empty folder
    :param duthosts: DUT host
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    if not check_dut_is_dpu(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        pytest.skip("Skip the test, as it is supported only on DPU.")

    since = str(randint(1, 5)) + " minute ago"
    platform_dump_name = "platform-dump.tar.gz"
    sai_sdk_dump_folder_name = "sai_sdk_dump"
    platform_dump_folder_name = "platform-dump"

    tar_file = gen_dump_file(duthost, since)
    extracted_dump_folder_name, extracted_dump_folder_path = extract_file_from_tar_file(duthost, tar_file)

    try:
        with allure.step('Validate that the dump file contains {} archive'.format(platform_dump_name)):
            is_platform_dump_tar_gz_exist = duthost.shell("ls {}/{}/{}".format(
                extracted_dump_folder_path, platform_dump_folder_name, platform_dump_name))["stdout_lines"]
            assert is_platform_dump_tar_gz_exist, \
                "{} doesn't exist in {}".format(platform_dump_name, extracted_dump_folder_name)

        with allure.step('validate that {} includes the expected files'.format(platform_dump_name)):
            validate_platform_dump_files(duthost, extracted_dump_folder_path, platform_dump_folder_name,
                                         platform_dump_name)

        with allure.step('Validate that the dump file contains sai_sdk_dump folder'):
            is_existing_sai_sdk_dump_folder = duthost.shell(
                "find {} -maxdepth 1 -type d -name {}".format(
                    extracted_dump_folder_path, sai_sdk_dump_folder_name))["stdout_lines"]
            assert is_existing_sai_sdk_dump_folder, \
                "Folder {} doesn't exist in dump archive".format(sai_sdk_dump_folder_name)

        with allure.step('Validate sai_sdk_dump is not empty folder'):
            sai_sdk_dump = duthost.shell("ls {}/sai_sdk_dump/".format(extracted_dump_folder_path))["stdout_lines"]
            assert len(sai_sdk_dump), \
                "Folder {} in dump archive is empty. Expected not an empty folder".format(sai_sdk_dump_folder_name)
    except AssertionError as err:
        raise AssertionError(err)
    finally:
        duthost.command("rm -rf {}".format(tar_file))
        duthost.command("rm -rf {}".format(extracted_dump_folder_path))
