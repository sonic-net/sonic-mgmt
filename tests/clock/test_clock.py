import logging
import random
import string
import pytest
import time
import allure
import datetime as dt

from contextlib import contextmanager
from tests.common.errors import RunAnsibleModuleFail

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health,
    pytest.mark.clock
]


@contextmanager
def allure_step(step_msg):
    """
    @summary:
        Context manager that wraps allure step context and a log with the same message
    @param step_msg: The desired step message
    """
    with allure.step(step_msg) as allure_step_context:
        logging.info('Step start: {}'.format(step_msg))
        try:
            yield allure_step_context
        finally:
            logging.info('Step end: {}'.format(step_msg))


class ClockConsts:
    STDOUT = "stdout"
    STDERR = "stderr"

    DATE = "date"
    TIME = "time"
    TIMEZONE = "timezone"

    TEST_TIMEZONE = "Asia/Jerusalem"
    TIME_MARGIN = 6
    RANDOM_NUM = 6

    # sonic commands
    CMD_SHOW_CLOCK = "show clock"
    CMD_SHOW_CLOCK_TIMEZONES = "show clock timezones"
    CMD_CONFIG_CLOCK_TIMEZONE = "config clock timezone"
    CMD_CONFIG_CLOCK_DATE = "config clock date"

    # expected outputs
    OUTPUT_CMD_SUCCESS = ''

    # expected errors
    ERR_BAD_TIMEZONE = 'Timezone {} does not conform format'
    ERR_MISSING_DATE = 'Error: Missing argument "<YYYY-MM-DD>"'
    ERR_MISSING_TIME = 'Error: Missing argument "<HH:MM:SS>"'
    ERR_BAD_DATE = 'Date {} does not conform format YYYY-MM-DD'
    ERR_BAD_TIME = 'Time {} does not conform format HH:MM:SS'

    # timedatectl
    CMD_TIMEDATECTL = "timedatectl"
    TIME_ZONE = "Time zone"

    MIN_SYSTEM_DATE = "1970-01-01"
    MAX_SYSTEM_DATE = "2231-12-31"

    # ntp
    CMD_SHOW_NTP = "show ntp"
    CMD_CONFIG_NTP_ADD = "config ntp add"
    CMD_CONFIG_NTP_DEL = "config ntp del"
    OUTPUT_CMD_NTP_ADD_SUCCESS = 'NTP server {} added to configuration\nRestarting ntp-config service...'
    OUTPUT_CMD_NTP_DEL_SUCCESS = 'NTP server {} removed from configuration\nRestarting ntp-config service...'
    REGEX_NTP_POLLING_TIME = r'polling server every (\d+)'


class ClockUtils:
    @staticmethod
    def run_cmd(duthosts, cmd, param=''):
        """
        @summary:
            Run a given command and return its output.
            * A successful command returns an empty output (except for show commands),
                while failure returns an error message
        @return: commands output (str)
        """
        with allure_step('Run command: "{}" with param "{}"'.format(cmd, param)):
            dut_hostname = duthosts[0].hostname

            cmd_to_run = cmd if param == '' else cmd + ' ' + param
            logging.info('Actual command to run: "{}"'.format(cmd_to_run))

            try:
                cmd_output = duthosts.command(cmd_to_run)[dut_hostname][ClockConsts.STDOUT]
            except RunAnsibleModuleFail as cmd_err:
                output = cmd_err.results[ClockConsts.STDOUT]
                err = cmd_err.results[ClockConsts.STDERR]
                cmd_output = output if output else err
                logging.info('Command Error!\nError message: "{}"'.format(cmd_output))

            cmd_output = str(cmd_output)
            logging.info('Output: {}'.format(cmd_output))

        return cmd_output

    @staticmethod
    def verify_and_parse_show_clock_output(show_clock_output):
        """
        @summary:
            Verify, and then split output of show clock into date, time and timezone strings

            Exapmple:
            "Mon 03 Apr 2023 11:29:46 PM UTC" -> {"date": "2023-04-03", "time": "23:29:46", "timezone": "+0000"}
        @param show_clock_output: the given show clock output
        @return: The splited output as a dict
        """
        with allure_step('Verify output of show clock'):
            try:
                timezone_str = show_clock_output.split()[-1].strip()
                logging.info('Timezone str: "{}"'.format(timezone_str))

                date_time_to_parse = show_clock_output.replace(timezone_str, '').strip()
                logging.info('Time and date to parse: "{}"'.format(date_time_to_parse))

                datetime_obj = dt.datetime.strptime(date_time_to_parse, '%a %d %b %Y %I:%M:%S %p')
                logging.info('Datetime object: "{}"\t|\tType: {}'.format(datetime_obj, type(datetime_obj)))
            except ValueError:
                logging.info('Show clock output is not valid.\nOutput: "{}"'.format(show_clock_output))
                pytest.fail('Show clock output is not valid.\nOutput: "{}"'.format(show_clock_output))

        with allure_step('Split output of show clock'):
            res = {
                ClockConsts.DATE: datetime_obj.strftime("%Y-%m-%d"),
                ClockConsts.TIME: datetime_obj.strftime("%H:%M:%S"),
                ClockConsts.TIMEZONE: timezone_str
            }
            logging.info('res dict: {}'.format(res))

            return res

    @staticmethod
    def parse_linux_cmd_output(linux_cmd_output):
        """
        @summary:
            Parse output of a linux command.

            Example:
                timedatectl's output:
                            "Local time: Tue 2023-04-04 08:22:01 MDT
                           Universal time: Tue 2023-04-04 14:22:01 UTC
                                 RTC time: Tue 2023-04-04 14:22:01
                                Time zone: America/Inuvik (MDT, -0600)
                System clock synchronized: no
                              NTP service: n/a
                          RTC in local TZ: no"

                will become:
                {
                    "Local time": "Tue 2023-04-04 08:22:01 MDT",
                    "Universal time": "Tue 2023-04-04 14:22:01 UTC",
                    ...
                }
        @param linux_cmd_output: given output of a linux command (str)
        @return: dictionary as mentioned in the example
        """
        with allure_step('Parse linux command output into dictionary'):
            rows = [row.strip() for row in linux_cmd_output.split('\n')]  # split by rows
            logging.info('rows: {}'.format(rows))
            res_dict = {}
            for row in rows:
                logging.debug('row: "{}"'.format(row))
                row_split = row.split(':', 1)
                res_dict[row_split[0]] = row_split[1].strip()
            logging.info('Result dict:\n{}'.format(res_dict))
            return res_dict

    @staticmethod
    def get_valid_timezones(duthosts):
        """
        @summary:
            Get the list of valid timezones from 'show clock timezones' command
        @param duthosts: duthosts object
        @return: list of timezones (strings)
        """
        with allure_step('Get list of valid timezones from show clock timezones command'):
            return ClockUtils.run_cmd(duthosts=duthosts, cmd=ClockConsts.CMD_SHOW_CLOCK_TIMEZONES).split()

    @staticmethod
    def verify_timezone_value(duthosts, expected_tz_name):
        """
        @summary:
            Verify that current system timezone is as expected.
            * Assume that expected timezone should be given as a complete timezone name (ETC/UTC, Asia/Jerusalem, etc.)
        @param duthosts: duthosts object
        @param expected_tz_name: The expected timezone name
        """
        with allure_step('Verify that current system timezone is as expected ({})'.format(expected_tz_name)):
            with allure_step('Get timezone details from show clock and timedatectl commands'):
                show_clock_output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_SHOW_CLOCK)
                show_clock_tz_abbr = ClockUtils.verify_and_parse_show_clock_output(
                    show_clock_output)[ClockConsts.TIMEZONE]
                timedatectl_tz = ClockUtils.parse_linux_cmd_output(
                    ClockUtils.run_cmd(duthosts, ClockConsts.CMD_TIMEDATECTL))[ClockConsts.TIME_ZONE]
                timedatectl_tz_split = timedatectl_tz.split(' ', 1)
                timedatectl_tz_name = timedatectl_tz_split[0].strip()
                timedatectl_tz_abbr = timedatectl_tz_split[1].split(',', 1)[0].replace('(', '').strip()

            with allure_step('Compare timezone abbreviations of show clock ({}) and timedatectl ({})'.format(
                    show_clock_tz_abbr, timedatectl_tz_abbr)):
                assert timedatectl_tz_abbr == show_clock_tz_abbr, 'Expected: {} == {}' \
                    .format(timedatectl_tz_abbr, show_clock_tz_abbr)

            with allure_step('Compare timezone name from timedatectl ({}) to the expected ({})'.format(
                    timedatectl_tz_name, expected_tz_name)):
                assert timedatectl_tz_name == expected_tz_name, 'Expected: {} == {}' \
                    .format(timedatectl_tz_name, expected_tz_name)

    @staticmethod
    def select_random_date():
        """
        @summary:
            Select a random date
        @return: a random date as string in the format "YYYY-MM-DD"
        """
        with allure_step('Select a random date'):
            start_date = dt.date.fromisoformat(ClockConsts.MIN_SYSTEM_DATE)
            end_date = dt.date.fromisoformat(ClockConsts.MAX_SYSTEM_DATE)

            diff_days = (end_date - start_date).days

            rand_num_of_days = random.randint(0, diff_days)

            rand_date = start_date + dt.timedelta(days=rand_num_of_days)

            rand_date_str = rand_date.strftime('%Y-%m-%d')

            logging.info('Selected random date: "{}"'.format(rand_date_str))
            return rand_date_str

    @staticmethod
    def select_random_time():
        """
        @summary:
            Select a random time
        @return: a random date as string in the format "hh:mm:ss"
        """
        with allure_step('Select a random time in a day'):
            rand_num_of_seconds_since_00 = random.randint(0, 24 * 60 * 60 - 1)

            rand_time_obj = time.gmtime(rand_num_of_seconds_since_00)

            rand_time_str = time.strftime("%H:%M:%S", rand_time_obj)

            logging.info('Selected random time: "{}"'.format(rand_time_str))
            return rand_time_str

    @staticmethod
    def verify_datetime(expected, actual, allowed_margin=ClockConsts.TIME_MARGIN):
        """
        @summary:
            Asserts a given date-time value is as expected
            * expected and actual date-time values are strings in the format "YYYY-MM-DD HH:MM:SS"
        @param expected: expected date-time value
        @param actual: actual given date-time value
        @param allowed_margin: allowed margin between two times (in seconds)
        """
        with allure_step(
                'Verify that diff between "{}" and "{}" (in seconds) is no longer than {}'.format(expected, actual,
                                                                                                  allowed_margin)):
            with allure_step('Calculate diff between "{}" and "{}" in seconds'.format(expected, actual)):
                datetime_obj1 = dt.datetime.strptime(expected, "%Y-%m-%d %H:%M:%S")
                datetime_obj2 = dt.datetime.strptime(actual, "%Y-%m-%d %H:%M:%S")

                diff_seconds = abs((datetime_obj2 - datetime_obj1).total_seconds())

            with allure_step('Verify that actual diff {} is not larger than {}'.format(diff_seconds, allowed_margin)):
                assert diff_seconds <= allowed_margin, 'Expected: {} <= {}'.format(diff_seconds, allowed_margin)


def test_show_clock(duthosts, init_timezone):
    """
    @summary:
        Test that show clock output is correct

        Steps:
        1. Run show clock
        2. Validate info
    """
    with allure_step('Run show clock command'):
        show_clock_output = ClockUtils.run_cmd(duthosts=duthosts, cmd=ClockConsts.CMD_SHOW_CLOCK)

    with allure_step('Verify info is valid'):
        ClockUtils.verify_and_parse_show_clock_output(show_clock_output)


def test_config_clock_timezone(duthosts, init_timezone):
    """
    @summary:
        Check that 'config clock timezone' command works correctly

        Steps:
        1. Set a new valid timezone
        2. Verify timezone changed
        3. Set invalid timezone
        4. Verify timezone hasn't changed
    """
    valid_timezones = ClockUtils.get_valid_timezones(duthosts)
    orig_timezone = ClockUtils.verify_and_parse_show_clock_output(
        ClockUtils.run_cmd(duthosts, ClockConsts.CMD_SHOW_CLOCK))[ClockConsts.TIMEZONE]

    with allure_step('Select a random new valid timezone'):
        new_timezone = random.choice(valid_timezones)
        while new_timezone == orig_timezone:
            new_timezone = random.choice(valid_timezones)

    with allure_step('Set the new timezone "{}"'.format(new_timezone)):
        output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_CLOCK_TIMEZONE, new_timezone)

    with allure_step('Verify command success'):
        assert output == ClockConsts.OUTPUT_CMD_SUCCESS, 'Expected: "{}" == "{}"'.format(output,
                                                                                         ClockConsts.OUTPUT_CMD_SUCCESS)

    with allure_step('Verify timezone changed to "{}"'.format(new_timezone)):
        ClockUtils.verify_timezone_value(duthosts, expected_tz_name=new_timezone)

    with allure_step('Select a random string as invalid timezone'):
        invalid_timezone = ''.join(random.choice(string.ascii_lowercase) for _ in range(random.randint(1, 10)))
        while invalid_timezone in valid_timezones:
            invalid_timezone = ''.join(random.choice(string.ascii_lowercase) for _ in range(random.randint(1, 10)))
        logging.info('Selected invalid timezone: "{}"'.format(invalid_timezone))

    with allure_step('Try to set the invalid timezone "{}"'.format(invalid_timezone)):
        output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_CLOCK_TIMEZONE, invalid_timezone)

    with allure_step('Verify command failure'):
        expected_err = ClockConsts.ERR_BAD_TIMEZONE.format(invalid_timezone)
        assert expected_err in output, \
            'Error: The given string does not contain the expected substring.\nExpected substring: "{}"\n' \
            'Given (whole) string: "{}"'.format(expected_err, output)

    with allure_step('Verify timezone has not changed'):
        ClockUtils.verify_timezone_value(duthosts, expected_tz_name=new_timezone)


def test_config_clock_date(duthosts, init_timezone, restore_time):
    """
    @summary:
        Check that 'config clock date' command works correctly

        Steps:
        1. Set a new valid date and time using the command
        2. Verify date and time changed
        3. Try to set invalid date and time
        4. Verify error and that time hasn't changed
    """
    with allure_step('Select valid date and time to set'):
        new_date = ClockUtils.select_random_date()
        new_time = ClockUtils.select_random_time()
        new_datetime = new_date + ' ' + new_time

    with allure_step('Set new date and time "{}"'.format(new_datetime)):
        output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_CLOCK_DATE, new_datetime)

    with allure_step('Verify command success'):
        assert output == ClockConsts.OUTPUT_CMD_SUCCESS, 'Expected: "{}" == "{}"'.format(output,
                                                                                         ClockConsts.OUTPUT_CMD_SUCCESS)

    with allure_step('Verify date and time changed to "{}"'.format(new_datetime)):
        with allure_step('Get datetime from show clock'):
            show_clock_output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_SHOW_CLOCK)
            show_clock_dict = ClockUtils.verify_and_parse_show_clock_output(show_clock_output)

        with allure_step('Verify date-time'):
            cur_date = show_clock_dict[ClockConsts.DATE]
            cur_time = show_clock_dict[ClockConsts.TIME]
            cur_datetime = '{} {}'.format(cur_date, cur_time)

            ClockUtils.verify_datetime(expected=new_datetime, actual=cur_datetime)

    with allure_step('Select random string as invalid input'):
        rand_str = ''.join(random.choice(string.ascii_lowercase) for _ in range(ClockConsts.RANDOM_NUM))
        logging.info('Selected random string: "{}"'.format(rand_str))

    with allure_step('Try to set invalid inputs'):
        errors = {
            '': ClockConsts.ERR_MISSING_DATE,
            rand_str: ClockConsts.ERR_MISSING_TIME,
            '{} {}'.format(rand_str, rand_str): '{}\n{}'.format(ClockConsts.ERR_BAD_DATE.format(rand_str),
                                                                ClockConsts.ERR_BAD_TIME.format(rand_str)),
            '{} {}'.format(rand_str, new_time): ClockConsts.ERR_BAD_DATE.format(rand_str),
            '{} {}'.format(new_date, rand_str): ClockConsts.ERR_BAD_TIME.format(rand_str)
        }

        for invalid_input, err_msg in errors.items():
            logging.info('Invalid input: "{}"\nExpected error:\n{}'.format(invalid_input, err_msg))

            with allure_step('Get show clock output before running the config command'):
                show_clock_output_before = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_SHOW_CLOCK)

            with allure_step('Try to set "{}"'.format(invalid_input)):
                output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_CLOCK_DATE, invalid_input)

            with allure_step('Get show clock output after running the config command'):
                show_clock_output_after = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_SHOW_CLOCK)

            with allure_step('Verify command failure'):
                assert err_msg in output, \
                    'Error: The given string does not contain the expected substring.\nExpected substring: "{}"\n' \
                    'Given (whole) string: "{}"'.format(err_msg, output)

            with allure_step('Verify date and time have not changed (still "{}")'.format(new_datetime)):
                show_clock_dict_before = ClockUtils.verify_and_parse_show_clock_output(show_clock_output_before)
                show_clock_dict_after = ClockUtils.verify_and_parse_show_clock_output(show_clock_output_after)

                with allure_step('Verify date-time'):
                    date_before = show_clock_dict_before[ClockConsts.DATE]
                    time_before = show_clock_dict_before[ClockConsts.TIME]
                    datetime_before = '{} {}'.format(date_before, time_before)

                    date_after = show_clock_dict_after[ClockConsts.DATE]
                    time_after = show_clock_dict_after[ClockConsts.TIME]
                    datetime_after = '{} {}'.format(date_after, time_after)

                    ClockUtils.verify_datetime(expected=datetime_before, actual=datetime_after)
