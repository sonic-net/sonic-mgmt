import logging
import time
import os

import pytest

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.config_reload import config_reload
from tests.common.devices.sonic import SonicHost
from tests.common.helpers.sensor_control_test_helper import BaseMocker

DUT_THERMAL_POLICY_FILE = '/usr/share/sonic/device/{}/thermal_policy.json'
DUT_THERMAL_POLICY_BACKUP_FILE = '/usr/share/sonic/device/{}/thermal_policy.json.bak'
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
FILES_DIR = os.path.join(BASE_DIR, 'files')

daemon_name = "thermalctld"

expected_running_status = "RUNNING"
expected_stopped_status = "STOPPED"


class FanStatusMocker(BaseMocker):
    """
    Fan status mocker. Vendor should implement this class to provide a FAN mocker.
    This class could mock speed, presence/absence and so on for all FANs and check
    the actual data equal to the mocked data.
    """

    def check_all_fan_speed(self, expected_speed):
        """
        Check all fan speed with a given expect value.
        :param expected_speed: Expect FAN speed percentage.
        :return: True if match else False.
        """
        pass


class SingleFanMocker(BaseMocker):
    """
    Single FAN mocker. Vendor should implement this class to provide a FAN mocker.
    This class could mock speed, presence/absence for one FAN, check LED color and
    other information.
    """

    def is_fan_removable(self):
        """
        :return: True if FAN is removable else False
        """
        pass

    def mock_normal(self):
        """
        Change the mocked FAN status to 'Present' and normal speed.
        :return:
        """
        pass

    def mock_absence(self):
        """
        Change the mocked FAN status to 'Not Present'.
        :return:
        """
        pass

    def mock_presence(self):
        """
        Change the mocked FAN status to 'Present'
        :return:
        """
        pass

    def mock_status(self, status):
        """
        Change the mocked FAN status to good or bad
        :param status: bool value indicate the target status of the FAN.
        :return:
        """
        pass

    def mock_normal_speed(self):
        """
        Change the mocked FAN speed to a normal value.
        :return:
        """
        pass

    def mock_under_speed(self):
        """
        Change the mocked FAN speed to slower than target speed and exceed speed tolerance.
        :return:
        """
        pass

    def mock_over_speed(self):
        """
        Change the mocked FAN speed to faster than target speed and exceed speed tolerance.
        :return:
        """
        pass


class ThermalStatusMocker(BaseMocker):
    """
    Thermal status mocker. Vendor should implement this class to provide a Thermal data mocker.
    This class could mock temperature, high threshold, high critical threshold and so on for all
    FANs and check the actual data equal to the mocked data.
    """

    def check_thermal_algorithm_status(self, expected_status):
        """
        Check thermal control algorithm status equal to the given value.
        :param expected_status: Expected thermal control status. True means enable, false means disable.
        :return: True if match else False.
        """
        pass


def check_cli_output_with_mocker(dut, mocker_object, command, max_wait_time, key_index=0):
    """
    Check the command line output matches the mocked data.
    :param dut: DUT object representing a SONiC switch under test.
    :param mocker_object: A mocker instance.
    :param command: The command to be executed. E.g, 'show platform fan'
    :param max_wait_time: Max wait time.
    :return: True if the actual data matches the mocked data.
    """
    time.sleep(max_wait_time)

    parsed_output = dut.show_and_parse(command)
    assert len(
        parsed_output) > 0, "Run and parse output of command '{}' failed".format(command)
    result = mocker_object.check_result(parsed_output)
    pytest_assert(
        result, 'mock data and command \"{}\" output are mismatched'.format(command))


def check_thermal_algorithm_status(dut, mocker_factory, expected_status):
    """
    Check thermal control algorithm status.
    :param dut: DUT object representing a SONiC switch under test.
    :param mocker_factory: Mocker factory.
    :param expected_status: Expect thermal control algorithm status.
    :return: True if actual thermal control status match expect value.
    """
    thermal_mocker = mocker_factory(dut, 'ThermalStatusMocker')
    if thermal_mocker is not None:
        return thermal_mocker.check_thermal_algorithm_status(expected_status)
    # if vendor doesn't provide a thermal mocker, ignore this check by return True.
    return True


def check_expected_daemon_status(duthost, expected_daemon_status):
    daemon_status, _ = duthost.get_pmon_daemon_status(daemon_name)
    return daemon_status == expected_daemon_status


def restart_thermal_control_daemon(dut):
    """
    Restart thermal control daemon by killing it and waiting supervisord to restart
    it automatically.
    :param dut: DUT object representing a SONiC switch under test.
    :return:
    """
    if dut.is_multi_asic and dut.sonic_release in ["201911"]:
        logging.info("thermalctl daemon is not present")
        return
    logging.info(
        'Restarting thermal control daemon on {}...'.format(dut.hostname))
    find_thermalctld_pid_cmd = 'docker exec -i pmon bash -c \'pgrep -f thermalctld\' | sort'
    output = dut.shell(find_thermalctld_pid_cmd)

    assert output["rc"] == 0, "Run command '{}' failed".format(find_thermalctld_pid_cmd)
    # it only has one thermalctld process
    # For kvm, there is no thermalctld process
    if dut.facts["asic_type"] == "vs":
        assert len(output["stdout_lines"]) == 0, "There should be 0 thermalctld process"
    else:
        assert len(output["stdout_lines"]
                   ) >= 1, "There should be at least 1 thermalctld process"

    restart_thermalctl_cmd = "docker exec -i pmon bash -c 'supervisorctl restart thermalctld'"
    output = dut.shell(restart_thermalctl_cmd, module_ignore_errors=True)
    if output["rc"] == 0:
        output = dut.shell(find_thermalctld_pid_cmd)
        assert output["rc"] == 0, "Run command '{}' failed after restart of thermalctld on {}".format(
            find_thermalctld_pid_cmd, dut.hostname)
        assert len(
            output["stdout_lines"]) >= 1, "There should be at least 1 thermalctld process"
        logging.info(
            "thermalctld processes restarted successfully on {}".format(dut.hostname))
        return
    if output["rc"] == 1 and dut.facts["asic_type"] == "vs":
        return
    # try restore by config reload...
    config_reload(dut)
    assert 0, 'Wait thermal control daemon restart failed'


def start_thermal_control_daemon(dut):
    daemon_status, _ = dut.get_pmon_daemon_status(daemon_name)
    if daemon_status != expected_running_status:
        dut.start_pmon_daemon(daemon_name)
        wait_until(10, 2, 0, check_expected_daemon_status,
                   dut, expected_running_status)
    running_daemon_status, _ = dut.get_pmon_daemon_status(daemon_name)
    assert running_daemon_status == expected_running_status,\
        "Run command '{}' failed after starting of thermalctld on {}"\
        .format(SonicHost.start_pmon_daemon, dut.hostname)
    logging.info("thermalctld processes started successfully on {}".format(dut.hostname))


def stop_thermal_control_daemon(dut):
    daemon_status, _ = dut.get_pmon_daemon_status(daemon_name)
    if daemon_status == expected_running_status:
        dut.stop_pmon_daemon(daemon_name)
        wait_until(10, 2, 0, check_expected_daemon_status,
                   dut, expected_stopped_status)
    stopped_daemon_status, _ = dut.get_pmon_daemon_status(daemon_name)
    assert stopped_daemon_status == expected_stopped_status,\
        "Run command '{}' failed after stopping of thermalctld on {}"\
        .format(SonicHost.stop_pmon_daemon, dut.hostname)
    logging.info("thermalctld processes stopped successfully on {}".format(dut.hostname))


class ThermalPolicyFileContext:
    """
    Context class to help replace thermal control policy file and restore it automatically.
    """

    def __init__(self, dut, src):
        """
        Constructor of ThermalPolicyFileContext.
        :param dut: DUT object representing a SONiC switch under test.
        :param src: Local policy file path.
        """
        self.dut = dut
        self.src = src
        platform_str = dut.facts['platform']
        self.thermal_policy_file_path = DUT_THERMAL_POLICY_FILE.format(
            platform_str)
        self.thermal_policy_file_backup_path = DUT_THERMAL_POLICY_BACKUP_FILE.format(
            platform_str)

    def __enter__(self):
        """
        Back up original thermal control policy file and replace it with the given one. Restart
        thermal control daemon to make it effect.
        :return:
        """
        out = self.dut.stat(path=self.thermal_policy_file_path)
        if out['stat']['exists']:
            self.dut.command(
                'mv -f {} {}'.format(self.thermal_policy_file_path, self.thermal_policy_file_backup_path))
        else:
            logging.warning("Thermal Policy file {} not found".format(
                self.thermal_policy_file_path))
        self.dut.copy(src=os.path.join(FILES_DIR, self.src),
                      dest=self.thermal_policy_file_path)
        restart_thermal_control_daemon(self.dut)

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Restore original thermal control policy file. Restart thermal control daemon to make it effect.
        :param exc_type: Not used.
        :param exc_val: Not used.
        :param exc_tb: Not used.
        :return:
        """
        out = self.dut.stat(path=self.thermal_policy_file_backup_path)
        if out['stat']['exists']:
            self.dut.command(
                'mv -f {} {}'.format(self.thermal_policy_file_backup_path, self.thermal_policy_file_path))
            restart_thermal_control_daemon(self.dut)


@pytest.fixture
def disable_thermal_policy(duthosts, enum_rand_one_per_hwsku_hostname):
    """Fixture to help disable thermal policy during the test. After test, it will
       automatically re-enable thermal policy. The idea here is to make thermalctld
       load a invalid policy file. To use this fixture, the test case will probably
       marked as @pytest.mark.disable_loganalyzer.

    Args:
        duthosts DUT object representing a SONiC switch under test
        enum_rand_one_per_hwsku_hostname random DUT hostname
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    invalid_policy_file = os.path.join(FILES_DIR, 'invalid_format_policy.json')
    with ThermalPolicyFileContext(duthost, invalid_policy_file):
        yield
