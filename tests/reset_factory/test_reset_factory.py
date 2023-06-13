import logging
import pytest
import paramiko
from retry import retry
from datetime import datetime
from tests.common.helpers.assertions import pytest_assert
from tests.common.reboot import perform_reboot
from multiprocessing.pool import ThreadPool

# topology
pytestmark = [
    pytest.mark.topology('any')
]

only_config_tested_directories = ["/etc/sonic", "/host/warmboot", "/var/dump", "/var/log", "/host/reboot-cause"]
keep_basic_test_directories = ["/home"]
TEST_FILE_NAME = "test_file"
KEEP_ALL_CONFIG = "keep-all-config"
ONLY_CONFIG = "only-config"
KEEP_BASIC = "keep-basic"
TEST_USER_NAME = "new_test_user"
TEST_USER_PASS = "test_user123"


def test_reset_factory_without_params(duthosts, localhost):
    """
    Test reset factory without providing any param
    This reset factory option will reset configurations to factory default. Logs and files will be deleted.
    """
    reset_factory(duthosts, localhost)


def test_reset_factory_keep_all_config(duthosts, localhost):
    """
    Test reset factory using keep-all-config option
    keep-all-config - preserves all configurations after boot. Logs and files will be deleted.
    """
    reset_factory(duthosts, localhost, KEEP_ALL_CONFIG)


def test_reset_factory_only_config(duthosts, localhost):
    """
    Test reset factory using only-config option
    only-config - Reset configurations to factory default. Logs and files will be preserved.
    """
    reset_factory(duthosts, localhost, ONLY_CONFIG)


def test_reset_factory_keep_basic(duthosts, localhost):
    """
    Test reset factory using keep-basic option
    keep-basic - Preserves basic configurations only after boot. Logs and files will be deleted.
    """
    reset_factory(duthosts, localhost, KEEP_BASIC)


def reset_factory(duthost, localhost, flag=""):
    """
    Execute reset factory according to provided params

    If not keep-all-config:
        1.1 config-setup factory <None/keep-basic/only-config>

    If not (only-config or keep-basic):
        2.1 Delete all non-default users and restore default passwords of default users.
        2.2 Delete bash, vim and python history files under "/home".
        2.3 Delete any non-dotfiles in the home directories.

    If not only-config:
        3.1 Remove all docker containers
        3.2 Restore "/etc/sonic" directory to factory folder (Clear the directory in overlayfs upperdir)
        3.3 Delete all files under "/host/warmboot"
        3.4 Delete tech-support files under "/var/dump/"
        4.5 Delete all files under "/var/log"
        3.6 Delete all files and symlinks under "/host/reboot-cause/"
    """
    logging.info("Dut host: {}".format(duthost[0].hostname))

    keep_all_config, only_config, keep_basic = get_flags(flag)
    logging.info("Flag '{}' will be used".format(flag))

    try:
        logging.info("Create data for the test")
        running_dockers = create_test_data(duthost, duthost[0].hostname)

        date_time_str = duthost.command("date")[duthost[0].hostname]["stdout"]
        logging.info("date: {}".format(date_time_str))
        reset_factory_start_time = datetime.strptime(date_time_str.split(" ", 1)[1], '%d %b %Y %H:%M:%S %p %Z')
        logging.info("Reset factory start time: " + str(reset_factory_start_time))

        logging.info("Execute reset factory, the dut will reboot")
        execute_reset_factory(duthost, localhost, flag, duthost[0].hostname)

        logging.info("Verify reset factory done as expected")
        verify_reset_factory(duthost, keep_all_config, only_config, keep_basic, running_dockers, duthost[0].hostname)

    finally:
        clear_test_created_data(duthost, duthost[0].hostname)


def create_test_data(duthost, dut_hostname):
    """
    Add test data - create file and users
    """
    logging.info("Create new user - {}".format(TEST_USER_NAME))
    run_command(duthost, "sudo useradd -m {} -p {}".format(TEST_USER_NAME, TEST_USER_PASS), dut_hostname)

    logging.info("Create test files")
    create_test_files(duthost, only_config_tested_directories, dut_hostname)
    create_test_files(duthost, keep_basic_test_directories, dut_hostname)

    logging.info("Update running dockers")
    return get_running_dockers(duthost, dut_hostname)


def execute_reset_factory(duthost, localhost, flag, dut_hostname):
    cmd = "sudo reset-factory {}".format(flag)
    logging.info("Command that will be executed: '{}'".format(cmd))

    logging.info("Execute reset factory, the dut will reboot")
    pool = ThreadPool()
    perform_reboot(duthost, pool, cmd)

    logging.info("Wait for the dut to complete the reset factory flow")
    localhost.wait_for(host=dut_hostname, port=22, state='stopped', delay=10, timeout=300)
    localhost.wait_for(host=dut_hostname, port=22, state='started', delay=10, timeout=300)


def verify_reset_factory(duthost, keep_all_config, only_config, keep_basic, running_dockers, dut_hostname):
    """
    Verify reset factory done as expected according to provided flag
    """
    failure_info = ""

    verify_keep_all_config(duthost, keep_all_config, failure_info)
    verify_keep_basic(duthost, only_config, keep_basic, failure_info)
    verify_only_config(duthost, only_config, failure_info, running_dockers, dut_hostname)

    pytest_assert(not failure_info, failure_info)


def verify_keep_all_config(duthost, keep_all_config, failure_info):
    config_db_path = "/etc/sonic/config_db.json"

    if keep_all_config and not check_if_dir_or_file_exist(duthost, config_db_path):
        failure_info += "{} not found".format(config_db_path)


def verify_keep_basic(duthost, only_config, keep_basic, failure_info):
    info = ""

    logging.info("Check keep-basic files")
    info += check_files(duthost, keep_basic_test_directories, (only_config or keep_basic))

    logging.info("Check users")
    file_exists = check_if_dir_or_file_exist(duthost, "/home/{}".format(TEST_USER_NAME))
    if file_exists and not (only_config or keep_basic):
        info = "\ntests user was not deleted"
        logging.warning(info)
    elif not file_exists and (only_config or keep_basic):
        info = "\ntest user was deleted while it should not for only-config/keep-basic flag"
        logging.warning(info)

    failure_info += info


def verify_only_config(duthost, only_config, failure_info, running_dockers, dut_hostname):
    logging.info("Check running dockers")
    info = check_running_dockers_after_reset_factory(duthost, only_config, running_dockers, dut_hostname)

    logging.info("Check only-config files")
    info += check_files(duthost, only_config_tested_directories, only_config)

    failure_info += info


def run_command(duthost, cmd, dut_hostname):
    output = duthost.command(cmd)
    res = output and "failed" in output[dut_hostname].keys() and not output[dut_hostname]["failed"]
    pytest_assert(res, "Failed to execute cmd:" + cmd)
    return output[dut_hostname]["stdout_lines"]


def create_test_files(duthost, directories, dut_hostname):
    for directory in directories:
        logging.info("Add test file to {}".format(directory))
        if not check_if_dir_or_file_exist(duthost, directory, dut_hostname):
            logging.info("Create dir {}".format(directory))
            run_command(duthost, "sudo mkdir {}".format(directory), dut_hostname)
        logging.info("Create test file")
        run_command(duthost, "sudo touch {}/{}".format(directory, TEST_FILE_NAME), dut_hostname)


def get_running_dockers(duthost, dut_hostname):
    running_dockers = {}
    output = run_command(duthost, "docker container list", dut_hostname)[1:]
    for line in output:
        line = line.split()
        docker_name = line[len(line) - 1]
        start_time = run_command(duthost, r"docker inspect -f \{\{'.Created'\}\} " + docker_name, dut_hostname)
        start_time = create_date_time_obj(start_time[0].split(".")[0])
        logging.info("Running docker: {}, {}".format(docker_name, str(start_time)))
        running_dockers[docker_name] = start_time
    return running_dockers


def get_flags(str_flag):
    keep_basic = False
    only_config = False
    keep_all_config = False
    if str_flag == KEEP_BASIC:
        keep_basic = True
    elif str_flag == ONLY_CONFIG:
        only_config = True
    elif str_flag == KEEP_ALL_CONFIG:
        keep_all_config = True
    return keep_basic, only_config, keep_all_config


def create_date_time_obj(str_info):
    datetime_object = datetime.strptime(str_info, '%Y-%m-%dT%H:%M:%S')
    return datetime_object


def ssh_client(host, user, passwd):
    dut_client = paramiko.SSHClient()
    dut_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    dut_client.connect(host, 22, user, passwd, allow_agent=False)
    return dut_client


def check_if_dir_or_file_exist(duthost, path, dut_hostname):
    try:
        logging.info("Check if {} exists".format(path))
        output = duthost.command("ls {}".format(path))
        if output and "failed" in output[dut_hostname].keys() and not output[dut_hostname]["failed"]:
            return True
        return False
    except Exception:
        return False


def check_files(duthost, directories, should_exist):
    info = ""
    for directory in directories:
        new_err = ""
        file_exists = check_if_dir_or_file_exist(duthost, "{}/{}".format(directory, TEST_FILE_NAME))
        if file_exists and not should_exist:
            new_err = "\nfile {}/{} was not deleted during reset factory".format(directory, TEST_FILE_NAME)
        elif not file_exists and should_exist:
            new_err = "\nfile {}/{} was deleted while it should not".format(directory, TEST_FILE_NAME)

        if new_err:
            info += new_err
            logging.warning(new_err)

    return info


def check_running_dockers_after_reset_factory(duthost, only_config, running_dockers, dut_hostname):
    info = ""
    for docker_name, org_start_time in running_dockers.items():
        new_err = ""
        try:
            logging.info("Checking docker: {}".format(docker_name))
            create_time = get_docker_start_time(duthost, docker_name, dut_hostname)

            if docker_name == "database":
                if org_start_time != create_time:
                    new_err = "\nreset factory should not restart database docker"
            else:
                if only_config and org_start_time < create_time:
                    new_err = "\n'{}' was stopped during reset factory, while it should not for only-config " \
                              "flag".format(docker_name)
                elif not only_config and org_start_time == create_time:
                    new_err = "\n'{}' was not stopped during reset factory".format(docker_name)
        except Exception:
            new_err = "\n'{}' is not running after reset factory".format(docker_name)

        if new_err:
            info += new_err
            logging.warning(new_err)

    return info


@retry(Exception, delay=10, tries=18)
def get_docker_start_time(duthost, docker_name, dut_hostname):
    output = run_command(duthost, r"docker inspect -f \{\{'.Created'\}\} " + docker_name, dut_hostname)
    create_time = create_date_time_obj(output[0].split(".")[0])
    logging.info("{} - {}".format(docker_name, str(create_time)))
    return create_time


def clear_test_created_data(duthost, dut_hostname):
    logging.info("Cleanup")
    try:
        for directory in keep_basic_test_directories:
            if check_if_dir_or_file_exist(duthost, "{}/{}".format(directory, TEST_FILE_NAME), dut_hostname):
                run_command(duthost, "sudo rm {}/{}".format(directory, TEST_FILE_NAME), dut_hostname)

        for directory in keep_basic_test_directories:
            if check_if_dir_or_file_exist(duthost, "{}/{}".format(directory, TEST_FILE_NAME), dut_hostname):
                run_command(duthost, "sudo rm {}/{}".format(directory, TEST_FILE_NAME), dut_hostname)

        file_exists = check_if_dir_or_file_exist(duthost, "/home/{}".format(TEST_USER_NAME), dut_hostname)
        if file_exists:
            run_command(duthost, "sudo userdel {}".format(TEST_USER_NAME), dut_hostname)

    except Exception as err:
        logging.warning("Test cleanup failed - " + str(err))
