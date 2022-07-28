import pytest
import time
import logging
import dateutil.parser
import random
import copy

from tests.common.errors import RunAnsibleModuleFail
from tests.common.utilities import wait_until
from tests.common.multibranch.cli import SonicCli

try:
    import allure
except ImportError:
    pytest.skip('Allure library not available. Skipping tests')

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

max_limit_test_modes_list = ['techsupport', 'core']

DEFAULT_STATE = 'enabled'
DEFAULT_RATE_LIMIT_GLOBAL = 180
DEFAULT_RATE_LIMIT_FEATURE = 600
DEFAULT_MAX_TECHSUPPORT_LIMIT = 10
DEFAULT_MAX_CORE_LIMIT = 5
DEFAULT_SINCE = '2 days ago'

CMD_GET_AUTO_TECH_SUPPORT_HISTORY_REDIS_KEYS = 'sudo redis-cli --raw -n 6  KEYS AUTO_TECHSUPPORT*'


def cleanup(cleanup_list):
    """
    Execute all the functions in the cleanup list
    """
    for func, args, kwargs in cleanup_list:
        func(*args, **kwargs)


@pytest.fixture()
def cleanup_list():
    """
    Fixture to execute cleanup after test run
    """
    cleanup_list = []

    yield cleanup_list

    cleanup(cleanup_list)


class TestAutoTechSupport:
    duthost = None
    dut_cli = None
    dockers_list = []
    number_of_test_dockers = 0
    test_docker = None

    def set_test_dockers_list(self):
        auto_tech_support_features_list = self.dut_cli.auto_techsupport.parse_show_auto_techsupport_feature().keys()
        system_features_status = self.duthost.get_feature_status()
        for feature in auto_tech_support_features_list:
            if is_docker_enabled(system_features_status, feature):
                self.dockers_list.append(feature)

        self.number_of_test_dockers = len(self.dockers_list)
        self.test_docker = random.choice(self.dockers_list)

    @pytest.fixture(autouse=True)
    def common_configuration(self, duthosts, rand_one_dut_hostname):
        self.duthost = duthosts[rand_one_dut_hostname]
        self.dut_cli = SonicCli(self.duthost)
        self.set_test_dockers_list()

        logger.info('Waiting until existing(if exist) techsupport processes finish')
        wait_until(300, 10, 0, is_techsupport_generation_in_expected_state, self.duthost, False)

        clear_auto_techsupport_history(self.duthost)
        self.duthost.shell('sudo mkdir /var/dump/', module_ignore_errors=True)
        clear_folders(self.duthost)

        create_core_file_generator_script(self.duthost)

        yield

        clear_auto_techsupport_history(self.duthost)
        clear_folders(self.duthost)

    @pytest.fixture()
    def global_rate_limit_zero(self):
        set_auto_techsupport_global(self.duthost, rate_limit=0)

        yield

        set_auto_techsupport_global(self.duthost, rate_limit=DEFAULT_RATE_LIMIT_GLOBAL)

    @pytest.fixture()
    def feature_rate_limit_zero(self):
        update_auto_techsupport_feature(self.duthost, self.test_docker, rate_limit=0)

        yield

        update_auto_techsupport_feature(self.duthost, self.test_docker, rate_limit=DEFAULT_RATE_LIMIT_FEATURE)

    def test_sanity(self, cleanup_list):
        """
        Basic sanity test for auto tehcsupport feature
        Test logic is as follows:
        - Validate CLI default values(global and features)
        - Create core file in SONiC host(not in docker) - verify that techsupport generation not started
        - Remove randomly a feature from the tech-support feature list, validate CLI values
        - Create core file in the removed feature(docker) - verify that techsupport generation not started
        - Add back the removed feature tpo the auto-techsupport feature list, validate CLI values
        - Set global state to disabled, validate CLI values
        - Create core file in feature(docker) - verify that techsupport generation not started(disabled globally)
        - Set global state to enabled, validate CLI values
        - Set feature to disabled, validate CLI values
        - Create core file in feature(docker) - verify that techsupport generation not started(disabled for feature)
        - Set feature to enabled, validate CLI values
        - Set specific since value(choose randomly from 3 possible variants)
        - Create core file in feature(docker)
        - Create core file in feature(docker) + all other dockers
        - Verify that only 1 techsupport running
        - Verify techsupport file(check that no entries in syslog(s) older than since value)
        :param cleanup_list: cleanup list
        :return: exception in case of fail
        """
        with allure.step('Checking default global configuration'):
            validate_auto_techsupport_global_config(self.dut_cli, state=DEFAULT_STATE,
                                                    rate_limit_interval=DEFAULT_RATE_LIMIT_GLOBAL,
                                                    max_techsupport_limit=DEFAULT_MAX_TECHSUPPORT_LIMIT,
                                                    max_core_size=DEFAULT_MAX_CORE_LIMIT, since=DEFAULT_SINCE)
        with allure.step('Checking default feature configuration'):
            validate_auto_techsupport_feature_config(self.dut_cli)

        with allure.step('Create .core file in SONiC(not in docker) and check that techsupport not started'):
            create_core_file(self.duthost)
            validate_techsupport_generation(self.duthost, self.dut_cli, is_techsupport_expected=False)

        with allure.step('Setting global rate limit to 0'):
            set_auto_techsupport_global(self.duthost, rate_limit=0)
            cleanup_list.append((set_auto_techsupport_global,
                                 (self.duthost,),
                                 {'rate_limit': DEFAULT_RATE_LIMIT_GLOBAL}))

        with allure.step('Remove auto-techsupport for feature(docker)'):
            add_delete_auto_techsupport_feature(self.duthost, feature=self.test_docker, action='delete')
            cleanup_list.append((add_delete_auto_techsupport_feature,
                                 (self.duthost,),
                                 {'feature': self.test_docker, 'action': 'add'}))

        with allure.step('Validate that the docker was removed from "show auto-techsupport-feature"'):
            auto_techsupport_feature_dict = self.dut_cli.auto_techsupport.parse_show_auto_techsupport_feature()
            assert self.test_docker not in auto_techsupport_feature_dict, \
                'Docker {} is not expected to appear in "show auto-techsupport-feature", since it was' \
                ' removed from the configuration'.format(self.test_docker)

        with allure.step('Crete .core file in test docker and check that techsupport not generated'):
            trigger_auto_techsupport(self.duthost, self.test_docker)
            validate_techsupport_generation(self.duthost, self.dut_cli, is_techsupport_expected=False)

        with allure.step('Add auto-techsupport for feature(docker)'):
            add_delete_auto_techsupport_feature(self.duthost, feature=self.test_docker, action='add')
            cleanup_list.remove((add_delete_auto_techsupport_feature,
                                 (self.duthost,),
                                 {'feature': self.test_docker, 'action': 'add'}))

        with allure.step('Check in CLI that configuration available for feature: {}'.format(self.test_docker)):
            expected_status_dict = {self.test_docker: {'status': DEFAULT_STATE,
                                                       'rate_limit_interval': DEFAULT_RATE_LIMIT_FEATURE}}
            validate_auto_techsupport_feature_config(self.dut_cli, expected_status_dict)

        # Set test docker rate limit to 0 - allow us to check that only 1 tech-support generated in case of few cores
        update_auto_techsupport_feature(self.duthost, self.test_docker, rate_limit=0)
        cleanup_list.append((update_auto_techsupport_feature,
                             (self.duthost, self.test_docker,),
                             {'rate_limit': DEFAULT_RATE_LIMIT_FEATURE}))

        with allure.step('Set auto-techsupport global state to: disabled'):
            set_auto_techsupport_global(self.duthost, state='disabled')
            cleanup_list.append((set_auto_techsupport_global,
                                 (self.duthost,),
                                 {'state': DEFAULT_STATE}))

        with allure.step('Validate that auto-techsupport in global config is in disabled state'):
            validate_auto_techsupport_global_config(self.dut_cli, state='disabled')

        with allure.step('Create .core files in each test docker container and check techsupport was not generated'):
            for docker in self.dockers_list:
                trigger_auto_techsupport(self.duthost, docker)
            validate_techsupport_generation(self.duthost, self.dut_cli, is_techsupport_expected=False)

        with allure.step('Validate that feature configuration has default state: {}'.format(DEFAULT_STATE)):
            expected_status_dict = {}
            for docker in self.dockers_list:
                expected_status_dict[docker] = {'status': DEFAULT_STATE}
            validate_auto_techsupport_feature_config(self.dut_cli, expected_status_dict)

        with allure.step('Set auto-techsupport global state to: enabled'):
            set_auto_techsupport_global(self.duthost, state=DEFAULT_STATE)
            cleanup_list.remove((set_auto_techsupport_global,
                                 (self.duthost,),
                                 {'state': DEFAULT_STATE}))

        with allure.step('Set auto-techsupport for each feature to state: disabled'):
            expected_status_dict = {}
            for docker in self.dockers_list:
                update_auto_techsupport_feature(self.duthost, docker, state='disabled')
                cleanup_list.append((update_auto_techsupport_feature,
                                     (self.duthost, docker,),
                                     {'state': DEFAULT_STATE}))

                expected_status_dict[docker] = {'status': 'disabled'}

        with allure.step('Check that feature configuration for all dockers has state: disabled'):
            validate_auto_techsupport_feature_config(self.dut_cli, expected_status_dict)

        with allure.step('Validate that auto-techsupport in global config has enabled state'):
            validate_auto_techsupport_global_config(self.dut_cli, state=DEFAULT_STATE)

        with allure.step('Create .core files in each test docker container and check techsupport not generated'):
            for docker in self.dockers_list:
                trigger_auto_techsupport(self.duthost, docker)
            validate_techsupport_generation(self.duthost, self.dut_cli, is_techsupport_expected=False)

        dockers_list = copy.deepcopy(self.dockers_list)
        dockers_list.remove(self.test_docker)
        docker_with_disabled_state = random.choice(dockers_list)

        with allure.step('Enabled auto-techsupport for specific feature(docker)'):
            update_auto_techsupport_feature(self.duthost, self.test_docker, state=DEFAULT_STATE)

        with allure.step('Check that feature is in enabled state for specific docker'):
            expected_status_dict = {self.test_docker: {'status': DEFAULT_STATE},
                                    docker_with_disabled_state: {'status': 'disabled'}}

            validate_auto_techsupport_feature_config(self.dut_cli, expected_status_dict)

        with allure.step('Validate that auto-techsupport in global config has enabled state'):
            validate_auto_techsupport_global_config(self.dut_cli, state=DEFAULT_STATE)

        with allure.step('Create .core files in test docker container which has disabled feature and check '
                         'techsupport not generated'):
            create_core_file(self.duthost, docker_with_disabled_state)
            validate_techsupport_generation(self.duthost, self.dut_cli, is_techsupport_expected=False)

        current_time = self.duthost.shell('date +%s')['stdout']
        """ Dict below has since value as key and time from now till oldest timestamp in log
        For example: {'300 sec': 360} - means that we will configure since value to "300 sec ago" and will expect that
        after auto-techsupport generation we will have logs not older than 360 seconds
        since now(300 sec + 60 sec deviation)
        """
        test_parameters_dict = {'@{}'.format(current_time): 60, '5 minutes ago': 360, '300 sec ago': 360}
        since_value = random.choice(list(test_parameters_dict.keys()))

        # force log rotate - because in some cases, when there's no file older than since, there will be no syslog file in techsupport dump
        with allure.step('Rotate logs'):
            self.duthost.shell('/usr/sbin/logrotate -f /etc/logrotate.conf > /dev/null 2>&1')

        with allure.step('Validate since value: {}'.format(since_value)):
            with allure.step('Set since value to: {}'.format(since_value)):
                set_auto_techsupport_global(self.duthost, since=since_value)
                cleanup_list.append((set_auto_techsupport_global,
                                     (self.duthost,),
                                     {'since': DEFAULT_SINCE}))

        with allure.step('Create .core file in each test docker container and check that techsupport generated in '
                         'expected docker and logs in techsupport not older than expected'):
            expected_core_file = trigger_auto_techsupport(self.duthost, self.test_docker)
            # Here we trigger additional .core file in test_docker and additional .core file in each available docker
            for docker in self.dockers_list:
                trigger_auto_techsupport(self.duthost, docker)

            expected_oldest_timestamp_in_log = test_parameters_dict[since_value]
            validate_techsupport_generation(self.duthost, self.dut_cli, is_techsupport_expected=True,
                                            expected_core_file=expected_core_file,
                                            since_value_in_seconds=expected_oldest_timestamp_in_log)

    def test_rate_limit_interval(self, cleanup_list):
        """
        Validate rate limit - global and per feature
        Test logic is as follows:
        - Set global rate limit to 30
        - Set test docker rate limit to 60
        - Create core file in test docker
        - Create core files in all other dockers
        - Check that only 1 techsupport running
        - Wait until techsupport finished and wait until global rate limit expired
        - Create core file in test docker
        - Check that techsupport not started(per feature limit not match)
        - Wait 30 sec
        - Create core file in test docker
        - Create core files in all other dockers
        - Check that only 1 techsupport running
        :param cleanup_list: cleanup list
        :return: exception in case of fail
        """
        rate_limit_30 = 30
        rate_limit_60 = 60

        with allure.step('Set global rate_limit_interval to {}'.format(rate_limit_30)):
            set_auto_techsupport_global(self.duthost, rate_limit=rate_limit_30)
            cleanup_list.append((set_auto_techsupport_global,
                                 (self.duthost,),
                                 {'rate_limit': DEFAULT_RATE_LIMIT_GLOBAL}))

        with allure.step('Set rate limit for docker: {}'.format(self.test_docker)):
            update_auto_techsupport_feature(self.duthost, self.test_docker, rate_limit=rate_limit_60)
            cleanup_list.append((update_auto_techsupport_feature,
                                 (self.duthost, self.test_docker,),
                                 {'rate_limit': DEFAULT_RATE_LIMIT_FEATURE}))
            expected_status_dict = {self.test_docker: {'rate_limit_interval': '{}'.format(rate_limit_60)}}

        with allure.step('Validate global and rate limits values'):
            validate_auto_techsupport_feature_config(self.dut_cli, expected_status_dict)
            validate_auto_techsupport_global_config(self.dut_cli, rate_limit_interval=rate_limit_30)

        with allure.step('Create .core files in test docker: {}'.format(self.test_docker)):
            available_tech_support_files = get_available_tech_support_files(self.duthost)
            trigger_auto_techsupport(self.duthost, self.test_docker)

        with allure.step('Create .core files in all available dockers'):
            for docker in self.dockers_list:
                trigger_auto_techsupport(self.duthost, docker)

        with allure.step('Checking that only 1 techsupport process running'):
            validate_techsupport_generation(self.duthost, self.dut_cli, is_techsupport_expected=True,
                                            available_tech_support_files=available_tech_support_files)

        logger.info('Sleep until {} second pass since techsupport file created'.format(rate_limit_30))
        time.sleep(rate_limit_30)

        with allure.step('Create .core files in test docker: {}'.format(self.test_docker)):
            trigger_auto_techsupport(self.duthost, self.test_docker)

        with allure.step('Checking that only no techsupport processes running'):
            validate_techsupport_generation(self.duthost, self.dut_cli, is_techsupport_expected=False)

        logger.info('Sleep until {} second pass since techsupport file created'.format(rate_limit_60))
        time.sleep(rate_limit_60 - rate_limit_30)

        with allure.step('Create .core files in test docker: {}'.format(self.test_docker)):
            available_tech_support_files = get_available_tech_support_files(self.duthost)
            trigger_auto_techsupport(self.duthost, self.test_docker)

        with allure.step('Create .core files in all available dockers'):
            for docker in self.dockers_list:
                trigger_auto_techsupport(self.duthost, docker)

        with allure.step('Checking that only 1 techsupport process running'):
            validate_techsupport_generation(self.duthost, self.dut_cli, is_techsupport_expected=True,
                                            available_tech_support_files=available_tech_support_files)

    @pytest.mark.parametrize('test_mode', max_limit_test_modes_list)
    def test_max_limit(self, test_mode, global_rate_limit_zero, feature_rate_limit_zero, cleanup_list):
        """
        Validate max limit parameter for core/techsupport folder
        Test logic is as follows:
        - Create 5 core/techsupport dummy files(each file 5%) which will use 25% of space in test folder
        - Set core/techsupport max limit to 0
        - Trigger techsupport and check that dummy files + new created core/techsupport files available
        - Set core/techsupport max limit to 18
        - Trigger techsupport and check that 2 oldest dummy files removed, all other + new created core/techsupport
        files available
        :param test_mode: test mode - core or techsupport
        :param global_rate_limit_zero: fixture which disable global rate limit
        :param feature_rate_limit_zero: fixture which disable feature rate limit
        :param cleanup_list: cleanup list
        :return: exception in case of fail
        """
        test_mode_folder_dict = {'techsupport': '/var/dump/', 'core': '/var/core/'}
        validation_folder = test_mode_folder_dict[test_mode]

        with allure.step('Get used space in mount point: {}'.format(validation_folder)):
            total, used, avail, used_percent = get_partition_usage_info(self.duthost, validation_folder)

        if used_percent > 50:
            pytest.skip('System uses more than 50% of space. '
                        'Test required at least 50% of free space in {}'.format(validation_folder))

        with allure.step('Create 5 stub files(each file 5%) which will use 25% of space in test folder'):
            num_of_dummy_files = 5
            one_file_size_in_percent = 5
            one_percent_in_mb = total / 100
            expected_file_size_in_mb = one_percent_in_mb * one_file_size_in_percent
            dummy_file_generator = create_techsupport_stub_file if test_mode == 'techsupport' else create_core_stub_file
            dummy_files_list = []
            for stub_file in range(num_of_dummy_files):
                dummy_files_list.append(dummy_file_generator(self.duthost, size_in_mb=expected_file_size_in_mb))

        max_limit = 0
        with allure.step('Validate: {} limit(disabled): {}'.format(test_mode, max_limit)):
            with allure.step('Set {} limit to: {}'.format(test_mode, max_limit)):
                set_limit(self.duthost, test_mode, max_limit, cleanup_list)

            with allure.step('Create .core file in test docker and check techsupport generated'):
                expected_core_file = trigger_auto_techsupport(self.duthost, self.test_docker)
                validate_techsupport_generation(self.duthost, self.dut_cli, is_techsupport_expected=True,
                                                expected_core_file=expected_core_file)

            with allure.step('Check that all stub files exist'):
                validate_expected_stub_files(self.duthost, validation_folder, dummy_files_list,
                                             expected_number_of_additional_files=1)

        max_limit = 18
        with allure.step('Validate: {} limit: {}'.format(test_mode, max_limit)):
            with allure.step('Set {} limit to: {}'.format(test_mode, max_limit)):
                set_limit(self.duthost, test_mode, max_limit, cleanup_list=None)

            with allure.step('Create .core file in test docker and check techsupport generated'):
                expected_core_file = trigger_auto_techsupport(self.duthost, self.test_docker)
                validate_techsupport_generation(self.duthost, self.dut_cli, is_techsupport_expected=True,
                                                expected_core_file=expected_core_file)

            with allure.step('Check that all expected stub files exist and unexpected does not exist'):
                expected_max_usage = one_percent_in_mb * max_limit
                expected_stub_files = dummy_files_list[2:]
                not_expected_stub_files = dummy_files_list[:2]
                validate_expected_stub_files(self.duthost, validation_folder, expected_stub_files,
                                             expected_number_of_additional_files=2,
                                             not_expected_stub_files_list=not_expected_stub_files,
                                             expected_max_folder_size=expected_max_usage)


# Methods used by tests
def set_limit(duthost, mode, limit_size, cleanup_list=None):
    if mode == 'techsupport':
        set_auto_techsupport_global(duthost, techsupport_limit=limit_size)
        if isinstance(cleanup_list, list):
            cleanup_list.append((set_auto_techsupport_global,
                                 (duthost,),
                                 {'techsupport_limit': DEFAULT_MAX_TECHSUPPORT_LIMIT}))
    else:
        set_auto_techsupport_global(duthost, core_limit=limit_size)
        if isinstance(cleanup_list, list):
            cleanup_list.append((set_auto_techsupport_global,
                                 (duthost,),
                                 {'core_limit': DEFAULT_MAX_CORE_LIMIT}))


def set_auto_techsupport_global(duthost, state=None, rate_limit=None, techsupport_limit=None, core_limit=None,
                                since=None):
    """
    Do configuration using cmd: sudo config auto-techsupport global .....
    :param duthost: duthost object
    :param state: expected state value
    :param rate_limit: expected rate_limit value
    :param techsupport_limit: expected techsupport_limit value
    :param core_limit: expected core_limit value
    :param since: expected since value
    """
    commands_list = []
    base_cmd = 'sudo config auto-techsupport global '
    if state:
        command = '{} state {}'.format(base_cmd, state)
        commands_list.append(command)
    if rate_limit or rate_limit == 0:
        command = '{} rate-limit-interval {}'.format(base_cmd, rate_limit)
        commands_list.append(command)
    if techsupport_limit or techsupport_limit == 0:
        command = '{} max-techsupport-limit {}'.format(base_cmd, techsupport_limit)
        commands_list.append(command)
    if core_limit or core_limit == 0:
        command = '{} max-core-limit {}'.format(base_cmd, core_limit)
        commands_list.append(command)
    if since:
        command = '{} since "{}"'.format(base_cmd, since)
        commands_list.append(command)

    if not commands_list:
        pytest.fail('Provide at least one argument from list: state, rate_limit, techsupport_limit, core_limit, since')

    for cmd in commands_list:
        with allure.step('Setting global config: {}'.format(cmd)):
            duthost.shell(cmd)


def update_auto_techsupport_feature(duthost, feature, state=None, rate_limit=None):
    """
    Do configuration using cmd: sudo config auto-techsupport-feature update .....
    :param duthost: duthost object
    :param feature: feature - docker name which should be configured
    :param state: expected state value
    :param rate_limit: expected rate_limit value
    """
    commands_list = []
    base_cmd = 'sudo config auto-techsupport-feature update {} '.format(feature)
    if state or state == 0:
        command = '{} --state {}'.format(base_cmd, state)
        commands_list.append(command)
    if rate_limit or rate_limit == 0:
        command = '{} --rate-limit-interval {}'.format(base_cmd, rate_limit)
        commands_list.append(command)

    if not commands_list:
        pytest.fail('Provide at least one argument from list: state, rate_limit')

    for cmd in commands_list:
        with allure.step('Setting feature {} config: {}'.format(feature, cmd)):
            duthost.shell(cmd)


def add_delete_auto_techsupport_feature(duthost, feature, action=None, state=DEFAULT_STATE,
                                        rate_limit=DEFAULT_RATE_LIMIT_FEATURE):
    """
    Add or delete feature from auto-techsupport-feature
    :param duthost: duthost object
    :param feature: feature - docker name which should be added/removed in auto-techsupport-feature
    :param action: action which should be executed, allowed only: "add", "delete"
    :param state: expected state value
    :param rate_limit: expected rate_limit value
    """
    if not action or action not in ['add', 'delete']:
        pytest.fail('Please provide action which should be executed, allowed only: "add", "delete"')

    base_cmd = 'sudo config auto-techsupport-feature {} {} '.format(action, feature)

    command = base_cmd
    if action == 'add':
        command = '{}--state {} --rate-limit-interval {}'.format(base_cmd, state, rate_limit)

    with allure.step('Doing {} feature {} config: {}'.format(action, feature, command)):
        duthost.shell(command)


def create_core_file(duthost, docker_name=None):
    """
    Create .core file in SONiC or inside in docker container
    :param duthost: duthost object
    :param docker_name: docker name - in case when you need to create .core file inside in docker container
    """
    cmd = 'bash /etc/sonic/core_file_generator.sh'
    if docker_name:
        cmd = 'docker exec {} {}'.format(docker_name, cmd)

    available_core_files = duthost.shell('ls /var/core/')['stdout_lines']
    duthost.shell(cmd)
    new_available_core_files = duthost.shell('ls /var/core/')['stdout_lines']
    new_core_files = list(set(new_available_core_files) - set(available_core_files))
    num_of_new_core_files = len(new_core_files)
    expected_num_of_new_core_files = 1
    if not new_core_files:
        raise AssertionError('Core file was not generated')
    assert num_of_new_core_files == expected_num_of_new_core_files, 'More than expected number of core files generated'
    new_core_file_name = new_core_files[0]
    return new_core_file_name


def is_techsupport_generation_in_expected_state(duthost, expected_in_progress=True):
    """
    Check if techsupport generation in progress
    :param duthost: duthost object
    :return: True in case when techsupport generation in progress
    """
    with allure.step('Checking techsupport generation process'):
        techsupport_in_progress = False
        processes_to_be_ignored = 2
        get_running_tech_procs_cmd = 'ps -aux | grep "coredump_gen_handler"'
        # Need to ignore 2 lines: one line with "grep...", another line with ansible module which call "grep..."
        num_of_process = len(duthost.shell(get_running_tech_procs_cmd)['stdout_lines']) - processes_to_be_ignored
        logger.info('Number of running autotechsupport processes: {}'.format(num_of_process))

        if num_of_process == 1:
            techsupport_in_progress = True

        is_in_expected_state = False
        if expected_in_progress:
            if techsupport_in_progress:
                is_in_expected_state = True
        else:
            if not techsupport_in_progress:
                is_in_expected_state = True

        return is_in_expected_state


def validate_core_files_inside_techsupport(duthost, techsupport_folder, expected_core_files_list):
    """
    Validated that expected .core files available inside in techsupport dump file
    :param duthost: duthost object
    :param techsupport_folder: path to techsupport(extracted tar file) folder, example: /var/dump/sonic_dump_r-lionfish-16_20210901_22140
    :param expected_core_files_list: list with expected .core files which should be in techsupport dump
    :return: AssertionError in case when validation failed
    """
    with allure.step('Validate .core files inside in techsuport file'):
        core_files_inside_techsupport = duthost.shell('ls {}/core/'.format(techsupport_folder))['stdout_lines']
        for core_file in expected_core_files_list:
            with allure.step('Checking .core file: {} in {}'.format(core_file, techsupport_folder)):
                assert core_file in core_files_inside_techsupport, 'Core file: {} not found in techsupport core ' \
                                                                   'files: {}'.format(core_file,
                                                                                      core_files_inside_techsupport)


def validate_techsupport_since(duthost, techsupport_folder, expected_oldest_log_line_timestamps_list):
    """
    Validate that techsupport file does not have logs which are older than value provided in 'since_value_in_seconds'
    :param duthost: duthost object
    :param techsupport_folder: path to techsupport(extracted tar file) folder, example: /var/dump/sonic_dump_r-lionfish-16_20210901_22140
    :param expected_oldest_log_line_timestamps_list: list of expected(possible) oldest log timestamp in datetime format
    :return: pytest.fail - in case when validation failed
    """
    with allure.step('Checking techsupport logs since'):
        oldest_timestamp_datetime = get_oldest_syslog_timestamp(duthost, techsupport_folder)
        logger.debug('Oldest timestamp: {}'.format(oldest_timestamp_datetime))

        assert oldest_timestamp_datetime in expected_oldest_log_line_timestamps_list, \
            'Timestamp: {} not in expected list: {}. --since validation failed'.format(oldest_timestamp_datetime,
                                                                                       expected_oldest_log_line_timestamps_list)

        available_syslogs_list = duthost.shell('sudo ls -l {}/log/syslog*'.format(techsupport_folder))['stdout'].splitlines()
        assert len(available_syslogs_list) <= len(expected_oldest_log_line_timestamps_list), \
            'Number of syslog files in techsupport bigger than expected'


def get_oldest_syslog_timestamp(duthost, techsupport_folder):
    """
    Get oldest syslog timestamp
    :param duthost: duthost object
    :param techsupport_folder: path to techsupport(extracted tar file) folder, example: /var/dump/sonic_dump_r-lionfish-16_20210901_22140
    :return: date timestamp in format: 2021-11-17 16:42:19.629013
    """
    with allure.step('Getting syslog oldest timestamp'):
        syslog_files = get_all_syslog_files_from_techsupport(duthost, techsupport_folder)
        oldest_syslog_file = get_oldest_syslog_file_name(syslog_files)
        oldest_syslog_line = \
            duthost.shell('zcat {}/log/{} | head -1'.format(techsupport_folder, oldest_syslog_file))['stdout_lines'][0]
        oldest_timestamp_str = ' '.join(oldest_syslog_line.split()[:3])
        oldest_timestamp_datetime = dateutil.parser.parse(oldest_timestamp_str)

    return oldest_timestamp_datetime


def get_all_syslog_files_from_techsupport(duthost, techsupport_folder):
    """
    Get list of syslog files which are available in techsupport dump file
    :param duthost: duthost object
    :param techsupport_folder: path to techsupport(extracted tar file) folder, example: /var/dump/sonic_dump_r-lionfish-16_20210901_22140
    :return: list of files, example: ['syslog.gz', 'syslog.1.gz', 'syslog.2.gz', ...]
    """
    with allure.step('Getting all syslog files from techsupport'):
        syslog_files_inside_techsupport = []
        for file_name in duthost.shell('ls {}/log/'.format(techsupport_folder))['stdout_lines']:
            if file_name.startswith('syslog'):
                syslog_files_inside_techsupport.append(file_name)
    return syslog_files_inside_techsupport


def get_oldest_syslog_file_name(syslog_files):
    """
    Get oldest syslog file name
    :param syslog_files: list of files, example: ['syslog.gz', 'syslog.1.gz', 'syslog.2.gz', ...]
    :return: file name, example: 'syslog.2.gz'
    """
    with allure.step('Getting oldest syslog file name'):
        oldest_syslog_file = 'syslog.gz'
        if len(syslog_files) > 1:
            syslog_files_index_list = []
            for syslog_file in syslog_files:
                try:
                    syslog_files_index_list.append(int(syslog_file.split('.')[1]))
                except (IndexError, ValueError):
                    pass
            oldest_index = sorted(syslog_files_index_list)[-1]
            oldest_syslog_file = 'syslog.{}.gz'.format(oldest_index)
    return oldest_syslog_file


def extract_techsupport_tarball_file(duthost, tarball_name):
    """
    Extract techsupport tar file and return path to data extracted from archive
    :param duthost: duthost object
    :param tarball_name: path to tar file, example: /var/dump/sonic_dump_r-lionfish-16_20210901_22140.tar.gz
    :return: path to folder with techsupport data, example: /tmp/sonic_dump_r-lionfish-16_20210901_22140
    """
    with allure.step('Extracting techsupport file: {}'.format(tarball_name)):
        dst_folder = '/tmp/'
        duthost.shell('tar -xf {} -C {}'.format(tarball_name, dst_folder))
        techsupport_folder = tarball_name.split('.')[0].split('/var/dump/')[1]
        techsupport_folder_full_path = '{}{}'.format(dst_folder, techsupport_folder)
    return techsupport_folder_full_path


def validate_auto_techsupport_global_config(dut_cli, state=None, rate_limit_interval=None, max_techsupport_limit=None,
                                            max_core_size=None, since=None):
    """
    Validate configuration in output 'show auto-techsupport global'
    :param dut_cli: dut_cli object
    :param state: expected state
    :param rate_limit_interval: expected rate_limit_interval
    :param max_techsupport_limit: expected max_techsupport_limit
    :param max_core_size: expected max_core_size
    :param since: expected since
    :return: AssertionError in case when validation failed
    """

    auto_techsupport_global_dict = dut_cli.auto_techsupport.parse_show_auto_techsupport_global()
    current_state = auto_techsupport_global_dict['state']
    current_rate_limit_interval = auto_techsupport_global_dict['rate_limit_interval']
    current_max_techsupport_limit = auto_techsupport_global_dict['max_techsupport_limit']
    current_max_core_size = auto_techsupport_global_dict['max_core_size']
    current_since = auto_techsupport_global_dict['since']

    if state:
        with allure.step('Checking global state'):
            assert current_state == state, 'Wrong configuration for state: {} expected: {}'.format(current_state, state)
    if rate_limit_interval:
        with allure.step('Checking global rate limit interval'):
            assert str(current_rate_limit_interval) == str(rate_limit_interval), \
                'Wrong configuration for rate_limit_interval: {} expected: {}'.format(current_rate_limit_interval,
                                                                                      rate_limit_interval)
    if max_techsupport_limit:
        with allure.step('Checking global max techsupport limit'):
            assert str(current_max_techsupport_limit) == str(max_techsupport_limit), \
                'Wrong configuration for max_techsupport_limit: {} expected: {}'.format(current_max_techsupport_limit,
                                                                                        max_techsupport_limit)
    if max_core_size:
        with allure.step('Checking global max core size'):
            assert str(current_max_core_size) == str(max_core_size), \
                'Wrong configuration for max_core_size: {} expected: {}'.format(current_max_core_size, max_core_size)
    if since:
        with allure.step('Checking global since'):
            assert str(current_since) == str(since), \
                'Wrong configuration for since: {} expected: {}'.format(current_since, since)


def validate_auto_techsupport_feature_config(dut_cli, expected_status_dict=None):
    """
    Validate configuration in output 'show auto-techsupport-feature'
    :param dut_cli: dut_cli object
    :param expected_status_dict: example: {'bgp': {'status': 'enabled', 'rate_limit_interval': '600'}}
    :return: AssertionError in case when validation failed
    """
    auto_techsupport_feature_dict = dut_cli.auto_techsupport.parse_show_auto_techsupport_feature()

    for feature, configuration in auto_techsupport_feature_dict.items():
        if expected_status_dict:
            if feature not in expected_status_dict:
                continue
        else:
            expected_status_dict = {feature: {'status': 'enabled', 'rate_limit_interval': '600'}}

        status = configuration['status']
        rate_limit_interval = configuration['rate_limit_interval']

        with allure.step('Checking feature {} configuration'.format(feature)):
            if expected_status_dict[feature].get('status'):
                assert status == expected_status_dict[feature]['status'], \
                    'Wrong configuration status: {} for: {}'.format(status, feature)
            if expected_status_dict[feature].get('rate_limit_interval'):
                assert str(rate_limit_interval) == str(expected_status_dict[feature]['rate_limit_interval']), \
                    'Wrong configuration rate_limit_interval: {} for: {}'.format(rate_limit_interval, feature)



def validate_techsupport_generation(duthost, dut_cli, is_techsupport_expected, expected_core_file=None,
                                    since_value_in_seconds=None, available_tech_support_files=None):
    """
    Validated techsupport generation. Check if techsupport started or not. Check number of files created.
    Check history, check mapping between core files and techsupport files.
    :param duthost: duthost object
    :param dut_cli: dut_cli object
    :param is_techsupport_expected: True/False, if expect techsupport - then True
    :param expected_core_file: expected core file name which we will check in techsupport file
    :param since_value_in_seconds: int, value in seconds which used in validation for since parameter
    :return: AssertionError in case of failure
    """
    expected_oldest_log_line_timestamps_list = None
    if since_value_in_seconds:
        expected_oldest_log_line_timestamps_list = get_expected_oldest_timestamp_datetime(duthost,
                                                                                          since_value_in_seconds)

    if not available_tech_support_files:
        available_tech_support_files = get_available_tech_support_files(duthost)

    if is_techsupport_expected:
        expected_techsupport_files = True
        assert is_techsupport_generation_in_expected_state(duthost, expected_in_progress=True), \
            'Expected techsupport generation not started or expected number of processes does not match actual number'
        wait_until(300, 10, 0, is_techsupport_generation_in_expected_state, duthost, False)
    else:
        assert is_techsupport_generation_in_expected_state(duthost, expected_in_progress=False), \
            'Unexpected techsupport generation in progress'
        expected_techsupport_files = False

    if expected_techsupport_files:
        # techsupport file creation may took some time after generate dump process already finished
        assert wait_until(300, 10, 0, is_new_techsupport_file_generated, duthost, available_tech_support_files), \
            'New expected techsupport file was not generated'

    # Do validation for history
    if expected_core_file:
        new_techsupport_files_list = get_new_techsupport_files_list(duthost, available_tech_support_files)
        tech_support_file_path = new_techsupport_files_list[0]
        tech_support_name = tech_support_file_path.split('.')[0].lstrip('/var/dump/')
        logger.info('Doing validation for techsupport : {}'.format(tech_support_name))

        wait_until(120, 10, 0, check_that_techsupport_in_history, dut_cli, tech_support_name)

        auto_techsupport_history = dut_cli.auto_techsupport.parse_show_auto_techsupport_history()
        core_file_name = auto_techsupport_history[tech_support_name]['core_dump']

        logger.info('Checking that expected .core file available in techsupport history for specific docker')
        assert expected_core_file == core_file_name, \
            'Unexpected .core file: {}, expected in techsupport file'.format(expected_core_file)

        techsupport_folder_path = extract_techsupport_tarball_file(duthost, tech_support_file_path)
        try:
            logger.info('Checking that expected .core file available in techsupport file')
            validate_core_files_inside_techsupport(duthost, techsupport_folder_path,
                                                   expected_core_files_list=[expected_core_file])

            logger.info('Checking since value in techsupport file')
            if expected_oldest_log_line_timestamps_list:
                validate_techsupport_since(duthost, techsupport_folder_path, expected_oldest_log_line_timestamps_list)
        except Exception as err:
            raise AssertionError(err)
        finally:
            duthost.shell('sudo rm -rf {}'.format(techsupport_folder_path))


def is_new_techsupport_file_generated(duthost, available_tech_support_files):
    """
    Check if new techsupport dump created
    :param duthost: duthost object
    :param available_tech_support_files: list of already available techsupport files
    :return: True in case when new techsupport file created
    """
    logger.info('Checking that new techsupport file created')
    new_techsupport_files_list = get_new_techsupport_files_list(duthost, available_tech_support_files)
    new_techsupport_files_num = len(new_techsupport_files_list)

    if new_techsupport_files_num == 1:
        return True

    return False


def get_new_techsupport_files_list(duthost, available_tech_support_files):
    """
    Get list of new created techsupport files
    :param duthost: duthost object
    :param available_tech_support_files: list of already available techsupport files
    :return: list of new techsupport files
    """
    try:
        new_available_tech_support_files = duthost.shell('ls /var/dump/*.tar.gz')['stdout_lines']
    except RunAnsibleModuleFail:
        new_available_tech_support_files = []
    new_techsupport_files_list = list(set(new_available_tech_support_files) - set(available_tech_support_files))

    return new_techsupport_files_list


def get_expected_oldest_timestamp_datetime(duthost, since_value_in_seconds):
    """
    Get expected oldest timestamp log which should be included in the techsupport dump
    :param duthost: duthost object
    :param since_value_in_seconds: int, value in seconds which used in validation for since parameter
    :return: datetime timestamp
    """
    current_time_str = duthost.shell('date "+%b %d %H:%M"')['stdout']
    current_time = dateutil.parser.parse(current_time_str)

    syslog_file_list = duthost.shell('sudo ls -l /var/log/syslog*')['stdout'].splitlines()

    syslogs_creation_date_dict = {}
    syslog_file_name_index = 8
    for syslog_file_entry in syslog_file_list:
        splited_data = syslog_file_entry.split()
        file_timestamp = get_syslog_timestamp(splited_data)
        syslog_file_name = splited_data[syslog_file_name_index]
        if syslogs_creation_date_dict.get(file_timestamp):
            syslogs_creation_date_dict[file_timestamp].append(syslog_file_name)
        else:
            syslogs_creation_date_dict[file_timestamp] = [syslog_file_name]

    # Sorted from new to old
    syslogs_sorted = sorted(syslogs_creation_date_dict.keys(), reverse=True)
    expected_files_in_techsupport_list = []
    for date in syslogs_sorted:
        expected_files_in_techsupport_list.extend(syslogs_creation_date_dict[date])
        if (current_time - date).seconds > since_value_in_seconds and current_time > date:
            break

    expected_oldest_log_line_timestamps_list = []
    for syslog_file_path in expected_files_in_techsupport_list:
        expected_oldest_log_line_timestamps_list.append(get_first_line_timestamp(duthost, syslog_file_path))

    return expected_oldest_log_line_timestamps_list


def get_syslog_timestamp(splited_data):
    """
    Get timestamp when syslog file created
    :param splited_data: list with output of "ls -l" - splited by space
    :return: datetime timestamp
    """
    month, day, hours = splited_data[5:8]
    file_timestamp = dateutil.parser.parse('{} {} {}'.format(month, day, hours))
    return file_timestamp


def get_first_line_timestamp(duthost, syslog_file_name):
    """
    Get timestamp from first line in log
    :param duthost: duthost object
    :param syslog_file_name: syslog file name
    :return:
    """
    if syslog_file_name.endswith('.gz'):
        first_log_string = duthost.shell('sudo zcat {} | head -n 1'.format(syslog_file_name))['stdout']
    else:
        first_log_string = duthost.shell('sudo head -n 1 {}'.format(syslog_file_name))['stdout']
    expected_oldest_timestamp_str = ' '.join(first_log_string.split()[:3])
    expected_oldest_log_line_timestamp = dateutil.parser.parse(expected_oldest_timestamp_str)

    return expected_oldest_log_line_timestamp


def check_that_techsupport_in_history(dut_cli, tech_support_name):
    auto_techsupport_history = dut_cli.auto_techsupport.parse_show_auto_techsupport_history()
    is_techsupport_in_history = False
    if auto_techsupport_history.get(tech_support_name):
        is_techsupport_in_history = True

    return is_techsupport_in_history


def trigger_auto_techsupport(duthost, docker):
    """
    Trigger auto techsupport logic. Create core file inside in Docker container
    :param duthost: duthost object
    :param docker: name of docker in which we should generate .core file
    :return: name of core file which created, example: 'bash.1637328736.324129.core.gz'
    """

    with allure.step('Triggering auto-techsupport in docker: {}'.format(docker)):
        core_file_name = create_core_file(duthost, docker)

    return core_file_name


def get_partition_usage_info(duthost, partition='/'):
    """
    Get info about partition
    :param duthost: duthost object
    :param partition: partition, example: '/' or '/var/dump' or '/var/core'
    :return: total size in mb(int), used in mb(int), available in mb(int), used in percent(int)
    """
    with allure.step('Getting HDD partition {} usage'.format(partition)):
        output = duthost.shell('sudo df {}'.format(partition))['stdout_lines']
        kb = 1024
        _, total, used, avail, used_percent, _ = output[-1].split()
        total_mb = int(total) / kb
        used_mb = int(used) / kb
        avail_mb = int(avail) / kb
        used_percent = int(used_percent.strip('%'))

    return total_mb, used_mb, avail_mb, used_percent


def get_used_space(duthost, path_to_file_folder):
    """
    Get used space by file of folder
    :param duthost: duthost object
    :param path_to_file_folder: path to file of folder, example: '/var/dump'
    :return: size of folder in mb(int)
    """
    with allure.step('Getting used space by folder: {}'.format(path_to_file_folder)):
        du_output = duthost.shell('sudo du -s {}'.format(path_to_file_folder))['stdout_lines']
        directory_usage_line = -1
        memory_usage_line = 0
        used_by_folder = du_output[directory_usage_line].split()[memory_usage_line]
        kb = 1024
        used_by_folder_mb = int(used_by_folder) / kb

    return used_by_folder_mb


def create_techsupport_stub_file(duthost, size_in_mb):
    """
    Create stub file in /var/dump folder
    :param duthost: duthost object
    :param size_in_mb: size of file in mb
    :return: name of file
    """
    with allure.step('Create stub techsupport file'):
        hostname = duthost.shell('hostname')['stdout']
        current_time = duthost.shell('date +%Y%m%d_%H%M%S')['stdout']
        dump_folder_path = '/var/dump/'
        file_name = 'sonic_dump_{}_{}.tar.gz'.format(hostname, current_time)
        full_path_to_file = '{}{}'.format(dump_folder_path, file_name)
        create_stub_file(duthost, full_path_to_file, size_in_mb)

    return file_name


def create_core_stub_file(duthost, size_in_mb):
    """
    Create stub file in /var/core folder
    :param duthost: duthost object
    :param size_in_mb: size of file in mb
    :return: name of file
    """
    with allure.step('Create stub .core file'):
        current_time = int(time.time())
        random_pid = random.choice(range(100, 20000))  # Get random PID
        file_name = 'bash.{}.{}.core.gz'.format(current_time, random_pid)
        core_folder_path = '/var/core/'
        full_path_to_file = '{}{}'.format(core_folder_path, file_name)
        create_stub_file(duthost, full_path_to_file, size_in_mb)

    return file_name


def create_stub_file(duthost, path_to_file, size_in_mb):
    """
    Create file in filesystem with specific size
    :param duthost: duthost object
    :param path_to_file: full path to file which should be created
    :param size_in_mb: size of file in mb
    """
    cmd = 'sudo dd if=/dev/zero of={} bs=1M count={}'.format(path_to_file, size_in_mb)
    duthost.shell(cmd)


def validate_expected_stub_files(duthost, validation_folder, expected_stub_files_list,
                                 expected_number_of_additional_files=0, not_expected_stub_files_list=None,
                                 expected_max_folder_size=None):
    """
    Validated that expected files available in folder, validate that unexpected files not in folder,
    validate folder size
    :param duthost: duthost object
    :param validation_folder: path to folder in which we will do validation
    :param expected_stub_files_list: expected files list
    :param expected_number_of_additional_files: expected number of additonal files in folder
    :param not_expected_stub_files_list: not expected files list
    :param expected_max_folder_size: expected maximum folder size
    """
    validation_files_list = duthost.shell('sudo ls {}'.format(validation_folder))['stdout_lines']

    # Check that all expected stub files exist
    validate_files_in_folder(validation_files_list, expected_stub_files_list)

    if not_expected_stub_files_list:
        validate_files_in_folder(validation_files_list, not_expected_stub_files_list, expected_files=False)

    expected_validation_files_len = len(expected_stub_files_list) + expected_number_of_additional_files
    validate_number_of_files_in_folder(validation_files_list, expected_validation_files_len)

    if expected_max_folder_size:
        validate_folder_size_less_than_allowed(duthost, validation_folder, expected_max_folder_size)


def validate_number_of_files_in_folder(validation_files_list, expected_number_of_files):
    """
    Validate number of files in folder
    :param validation_files_list: actual number of files in folder(list)
    :param expected_number_of_files: expected number of files in folder
    """
    with allure.step('Validate number of files in folder'):
        validation_files_len = len(validation_files_list)
        err_mgs = 'Number of expected files: {} not equal to actual expected files: {}'.format(expected_number_of_files,
                                                                                               validation_files_len)
        assert validation_files_len == expected_number_of_files, err_mgs


def validate_files_in_folder(validation_files_list, files_list, expected_files=True):
    """
    Validated files in folder
    :param validation_files_list: actual number of files in folder(list)
    :param files_list: list of files which we will check in folder
    :param expected_files: if True - check that file in folder, if False - check that file not in folder
    """
    with allure.step('Validate files in folder'):
        for stub_file in files_list:
            if expected_files:
                err_mgs = 'Expected file: {} not found in available files list: {}'.format(stub_file,
                                                                                           validation_files_list)
                assert stub_file in validation_files_list, err_mgs
            else:
                err_msg = 'Unexpected file: {} found in available files list: {}'.format(stub_file,
                                                                                         validation_files_list)
                assert stub_file not in validation_files_list, err_msg


def validate_folder_size_less_than_allowed(duthost, folder, expected_max_folder_size):
    """
    Validate folder size less than expected_max_folder_size
    :param duthost: duthost obj
    :param folder: path to folder
    :param expected_max_folder_size: maximum expected size of folder
    """
    with allure.step('Validate folder: {} size less than: {}'.format(folder, expected_max_folder_size)):
        used_by_folder = get_used_space(duthost, folder)
        err_msg = 'Folder {} has size: {}Mb more than expected: {}Mb'.format(folder, used_by_folder,
                                                                             expected_max_folder_size)
        assert used_by_folder < expected_max_folder_size, err_msg


def is_docker_enabled(system_features_status, docker):
    docker_enabled = False
    if system_features_status[0].get(docker) in ['enabled', 'always_enabled']:
        docker_enabled = True
    return docker_enabled


def clear_auto_techsupport_history(duthost):
    auto_tech_history_entries = duthost.shell(CMD_GET_AUTO_TECH_SUPPORT_HISTORY_REDIS_KEYS)['stdout_lines']
    for entry in auto_tech_history_entries:
        duthost.shell('sudo redis-cli -n 6 DEL "{}"'.format(entry))


def clear_folders(duthost):
    duthost.shell('sudo rm -rf /var/core/*')
    duthost.shell('sudo rm -rf /var/dump/*')


def create_core_file_generator_script(duthost):
    duthost.shell('sudo echo \'sleep 10 & kill -6 $!\' > /etc/sonic/core_file_generator.sh')
    duthost.shell('sudo echo \'echo $?\' >> /etc/sonic/core_file_generator.sh')


def get_available_tech_support_files(duthost):
    try:
        available_tech_support_files = duthost.shell('ls /var/dump/*.tar.gz')['stdout_lines']
    except RunAnsibleModuleFail:
        available_tech_support_files = []
    return available_tech_support_files
