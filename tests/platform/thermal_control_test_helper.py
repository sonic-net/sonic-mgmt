import logging
import time
import os
import sys
import pytest

from common.utilities import wait_until

DUT_THERMAL_POLICY_FILE = '/usr/share/sonic/device/{}/thermal_policy.json'
DUT_THERMAL_POLICY_BACKUP_FILE = '/usr/share/sonic/device/{}/thermal_policy.json.bak'
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
FILES_DIR = os.path.join(BASE_DIR, 'files')


class BaseMocker:
    _mocker_type_dict = {}

    def __init__(self, dut):
        self.dut = dut

    def mock_data(self):
        pass

    def check_result(self, actual_data):
        pass

    def deinit(self):
        pass

    @classmethod
    def register_mocker_type(cls, name, mocker_type):
        cls._mocker_type_dict[name] = mocker_type

    @classmethod
    def get_mocker_type(cls, name):
        return cls._mocker_type_dict[name] if name in cls._mocker_type_dict else None


def mocker(type_name):
    def wrapper(object_type):
       BaseMocker.register_mocker_type(type_name, object_type)
       return object_type
    return wrapper


@pytest.fixture
def mocker_factory():
    mockers = []

    def _create_mocker(asic_type, mocker_name):
        mocker = None

        if asic_type == "mellanox":
            current_file_dir = os.path.dirname(os.path.realpath(__file__))
            if current_file_dir not in sys.path:
                sys.path.append(current_file_dir)
            sub_folder_dir = os.path.join(current_file_dir, "mellanox")
            if sub_folder_dir not in sys.path:
                sys.path.append(sub_folder_dir)
            import mellanox_thermal_control_test_helper
            mocker_type = BaseMocker.get_mocker_type(mocker_name)
            if mocker_type:
                mocker = mocker_type(dut)
                mockers.append(mocker)
        return mocker

    yield _create_mocker

    for mocker in mockers:
        mocker.deinit()


class FanStatusMocker(BaseMocker):
    def check_all_fan_speed(self, expected_speed):
        pass


class SingleFanMocker(BaseMocker):
    def mock_normal(self):
        pass

    def mock_absence(self):
        pass

    def mock_presence(self):
        pass

    def mock_normal_speed(self):
        pass

    def mock_under_speed(self):
        pass

    def mock_over_speed(self):
        pass


class ThermalStatusMocker(BaseMocker):
    @classmethod
    def check_thermal_algorithm_status(cls, expected_status):
        pass


def get_field_range(second_line):
    """
    @summary: Utility function to help get field range from a simple tabulate output line.
    Simple tabulate output looks like:

    Head1   Head2       H3 H4
    -----  ------  ------- --
       V1      V2       V3 V4

    @return: Returned a list of field range. E.g. [(0,4), (6, 10)] means there are two fields for
    each line, the first field is between position 0 and position 4, the second field is between
    position 6 and position 10.
    """
    field_ranges = []
    begin = 0
    while 1:
        end = second_line.find(' ', begin)
        if end == -1:
            field_ranges.append((begin, len(second_line)))
            break

        field_ranges.append((begin, end))
        begin = second_line.find('-', end)
        if begin == -1:
            break

    return field_ranges


def get_fields(line, field_ranges):
    """
    @summary: Utility function to help extract all fields from a simple tabulate output line
    based on field ranges got from function get_field_range.
    @return: A list of fields.
    """
    fields = []
    for field_range in field_ranges:
        field = line[field_range[0]:field_range[1]]
        fields.append(field.strip())

    return fields


def check_cli_output_with_mocker(dut, mocker, command, max_wait_time):
    time.sleep(max_wait_time)

    cli_thermal_status = dut.command(command)
    assert cli_thermal_status["rc"] == 0, "Run command '%s' failed" % command
    second_line = cli_thermal_status["stdout_lines"][1]
    field_ranges = get_field_range(second_line)

    actual_data = {}
    for line in cli_thermal_status["stdout_lines"][2:]:
        fields = get_fields(line, field_ranges)
        actual_data[fields[0]] = fields
    
    return mocker.check(actual_data)


def check_thermal_algorithm_status(dut, mocker_factory, expected_status):
    thermal_mocker = mocker_factory(dut.facts['asic_type'], 'ThermalStatusMocker')
    if thermal_mocker is not None:
        return thermal_mocker.check_thermal_algorithm_status(False)
    return True


def restart_thermal_control_daemon(dut):
    logging.info('Restarting thermal control daemon...')
    find_thermalctld_pid_cmd = 'docker exec -i pmon bash -c \'pgrep thermalctld | sort\''
    output = dut.command(find_thermalctld_pid_cmd)
    assert output["rc"] == 0, "Run command '%s' failed" % find_thermalctld_pid_cmd
    assert len(output["stdout_lines"]) == 2, "There should be 2 thermalctld process"
    pid_0 = int(output["stdout_lines"][0].strip())
    pid_1 = int(output["stdout_lines"][1].strip())
    # find and kill the parent process
    pid_to_kill = pid_0 if pid_0 < pid_1 else pid_1
    logging.info('Killing old thermal control daemon with pid: {}'.format(pid_to_kill))
    kill_thermalctld_cmd = 'docker exec -i pmon bash -c \'kill {}\''.format(pid_to_kill)
    output = dut.command(kill_thermalctld_cmd)  # kill thermalctld and wait supervisord auto reboot thermalctld
    assert output["rc"] == 0, "Run command '%s' failed" % kill_thermalctld_cmd
    
    # make sure thermalctld has restarted
    max_wait_time = 5
    while max_wait_time > 0:
        max_wait_time -= 1
        output = dut.command(find_thermalctld_pid_cmd)
        assert output["rc"] == 0, "Run command '%s' failed" % find_thermalctld_pid_cmd
        if len(output["stdout_lines"]) != 2:
            time.sleep(1)
            continue
        
        new_pid_0 = int(output["stdout_lines"][0].strip())
        new_pid_1 = int(output["stdout_lines"][1].strip())
        parent_pid = new_pid_0 if new_pid_0 < new_pid_1 else new_pid_1
        
        if parent_pid == pid_to_kill:
            logging.info('Old thermal control daemon is still alive, waiting...')
            time.sleep(1)
            continue
        else:
            logging.info('New pid of thermal control daemon is {}'.format(parent_pid))
            return

    assert 0, 'Wait thermal control daemon restart failed'


class ThermalPolicyFileContext:
    def __init__(self, dut, src):
        self.dut = dut
        self.src = src
        platform_str = dut.facts['platform']
        self.thermal_policy_file_path = DUT_THERMAL_POLICY_FILE.format(platform_str)
        self.thermal_policy_file_backup_path = DUT_THERMAL_POLICY_BACKUP_FILE.format(platform_str)

    def __enter__(self):
        self.dut.command('mv -f {} {}'.format(self.thermal_policy_file_path, self.thermal_policy_file_backup_path))
        self.dut.copy(src=os.path.join(FILES_DIR, self.src), dest=self.thermal_policy_file_path)
        restart_thermal_control_daemon(self.dut)

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.dut.command('mv -f {} {}'.format(self.thermal_policy_file_backup_path, self.thermal_policy_file_path))
        restart_thermal_control_daemon(self.dut)