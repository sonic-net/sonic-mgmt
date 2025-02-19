import logging
import random
import string
import pytest
import time
import datetime as dt

from tests.common.errors import RunAnsibleModuleFail
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health,
    pytest.mark.clock
]


class ClockConsts:
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
    CMD_NTP_STOP = 'service ntp stop'
    CMD_NTP_START = 'service ntp start'
    CMD_NTPDATE = 'ntpdate'

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
    def run_cmd(duthosts, cmd, param='', raise_err=False):
        """
        @summary:
            Run a given command and return its output.
            * A successful command returns an empty output (except for show commands),
                while failure returns an error message
        @return: commands output (str)
        """
        with allure.step(f'Run command: "{cmd}" with param "{param}"'):
            dut_hostname = duthosts[0].hostname

            cmd_to_run = cmd if param == '' else cmd + ' ' + param
            logging.info(f'Actual command to run: "{cmd_to_run}"')

            try:
                cmd_output = duthosts.command(cmd_to_run)[dut_hostname]["stdout"]
            except RunAnsibleModuleFail as cmd_err:
                output = cmd_err.results["stdout"]
                err = cmd_err.results["stderr"]
                cmd_output = output if output else err
                logging.info(f'Command Error!\nError message: "{cmd_output}"')
                if raise_err:
                    raise Exception(cmd_output)

            cmd_output = str(cmd_output)
            logging.info(f'Output: {cmd_output}')

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
        with allure.step('Verify output of show clock'):
            try:
                timezone_str = show_clock_output.split()[-2].strip()
                logging.info(f'Timezone str: "{timezone_str}"')

                date_time_to_parse = show_clock_output.replace(timezone_str, '').strip()
                logging.info(f'Time and date to parse: "{date_time_to_parse}"')

                datetime_obj = dt.datetime.strptime(date_time_to_parse, '%a %b %d %H:%M:%S %p %Y')
                logging.info(f'Datetime object: "{datetime_obj}"\t|\tType: {type(datetime_obj)}')
            except ValueError:
                pytest.fail(f'Show clock output is not valid.\nOutput: "{show_clock_output}"')

        with allure.step('Split output of show clock'):
            res = {
                ClockConsts.DATE: datetime_obj.strftime("%Y-%m-%d"),
                ClockConsts.TIME: datetime_obj.strftime("%H:%M:%S"),
                ClockConsts.TIMEZONE: timezone_str
            }
            logging.info(f'res dict: {res}')

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
        with allure.step('Parse linux command output into dictionary'):
            rows = [row.strip() for row in linux_cmd_output.split('\n')]  # split by rows
            logging.info(f'rows: {rows}')
            res_dict = {}
            for row in rows:
                logging.debug(f'row: "{row}"')
                row_split = row.split(':', 1)
                res_dict[row_split[0]] = row_split[1].strip()
            logging.info(f'Result dict:\n{res_dict}')
            return res_dict

    @staticmethod
    def get_valid_timezones(duthosts):
        """
        @summary:
            Get the list of valid timezones from 'show clock timezones' command
        @param duthosts: duthosts object
        @return: list of timezones (strings)
        """
        with allure.step('Get list of valid timezones from show clock timezones command'):
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
        with allure.step(f'Verify that current system timezone is as expected ({expected_tz_name})'):
            with allure.step('Get timezone details from show clock and timedatectl commands'):
                show_clock_output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_SHOW_CLOCK)
                show_clock_tz_abbr = ClockUtils.verify_and_parse_show_clock_output(
                    show_clock_output)[ClockConsts.TIMEZONE]
                timedatectl_tz = ClockUtils.parse_linux_cmd_output(
                    ClockUtils.run_cmd(duthosts, ClockConsts.CMD_TIMEDATECTL))[ClockConsts.TIME_ZONE]
                timedatectl_tz_split = timedatectl_tz.split(' ', 1)
                timedatectl_tz_name = timedatectl_tz_split[0].strip()
                timedatectl_tz_abbr = timedatectl_tz_split[1].split(',', 1)[0].replace('(', '').strip()

            with allure.step(f'Compare timezone abbreviations of show clock ({show_clock_tz_abbr}) '
                             f'and timedatectl ({timedatectl_tz_abbr})'):
                assert timedatectl_tz_abbr == show_clock_tz_abbr, \
                    'Expected: {timedatectl_tz_abbr} == {show_clock_tz_abbr}'

            with allure.step(f'Compare timezone name from timedatectl ({timedatectl_tz_name}) '
                             f'to the expected ({expected_tz_name})'):
                assert timedatectl_tz_name == expected_tz_name, f'Expected: {timedatectl_tz_name} == {expected_tz_name}'

    @staticmethod
    def select_random_date():
        """
        @summary:
            Select a random date
        @return: a random date as string in the format "YYYY-MM-DD"
        """
        with allure.step('Select a random date'):
            start_date = dt.date.fromisoformat(ClockConsts.MIN_SYSTEM_DATE)
            end_date = dt.date.fromisoformat(ClockConsts.MAX_SYSTEM_DATE)
            diff_days = (end_date - start_date).days
            rand_num_of_days = random.randint(0, diff_days)
            rand_date = start_date + dt.timedelta(days=rand_num_of_days)
            rand_date_str = rand_date.strftime('%Y-%m-%d')
            logging.info(f'Selected random date: "{rand_date_str}"')
            return rand_date_str

    @staticmethod
    def select_random_time():
        """
        @summary:
            Select a random time
        @return: a random date as string in the format "hh:mm:ss"
        """
        with allure.step('Select a random time in a day'):
            rand_num_of_seconds_since_00 = random.randint(0, 24 * 60 * 60 - 1)

            rand_time_obj = time.gmtime(rand_num_of_seconds_since_00)

            rand_time_str = time.strftime("%H:%M:%S", rand_time_obj)

            logging.info(f'Selected random time: "{rand_time_str}"')
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
        with allure.step(
                f'Verify that diff between "{expected}" and "{actual}" (in seconds) is '
                f'no longer than {allowed_margin}'):
            with allure.step(f'Calculate diff between "{expected}" and "{actual}" in seconds'):
                datetime_obj1 = dt.datetime.strptime(expected, "%Y-%m-%d %H:%M:%S")
                datetime_obj2 = dt.datetime.strptime(actual, "%Y-%m-%d %H:%M:%S")

                diff_seconds = abs((datetime_obj2 - datetime_obj1).total_seconds())

            with allure.step(f'Verify that actual diff {diff_seconds} is not larger than {allowed_margin}'):
                assert diff_seconds <= allowed_margin, f'Expected: {diff_seconds} <= {allowed_margin}'


def test_show_clock(duthosts, init_timezone):
    """
    @summary:
        Test that show clock output is correct

        Steps:
        1. Run show clock
        2. Validate info
    """
    with allure.step('Run show clock command'):
        show_clock_output = ClockUtils.run_cmd(duthosts=duthosts, cmd=ClockConsts.CMD_SHOW_CLOCK)

    with allure.step('Verify info is valid'):
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

    with allure.step('Select a random new valid timezone'):
        new_timezone = random.choice(valid_timezones)
        while new_timezone == orig_timezone:
            new_timezone = random.choice(valid_timezones)

    with allure.step(f'Set the new timezone "{new_timezone}"'):
        output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_CLOCK_TIMEZONE, new_timezone)
        with allure.step('Verify command success'):
            assert output == ClockConsts.OUTPUT_CMD_SUCCESS, \
                f'Expected: "{output}" == "{ClockConsts.OUTPUT_CMD_SUCCESS}"'

    with allure.step(f'Verify timezone changed to "{new_timezone}"'):
        ClockUtils.verify_timezone_value(duthosts, expected_tz_name=new_timezone)

    with allure.step('Select a random string as invalid timezone'):
        invalid_timezone = ''.join(random.choice(string.ascii_lowercase) for _ in range(random.randint(1, 10)))
        while invalid_timezone in valid_timezones:
            invalid_timezone = ''.join(random.choice(string.ascii_lowercase) for _ in range(random.randint(1, 10)))
        logging.info(f'Selected invalid timezone: "{invalid_timezone}"')

    with allure.step(f'Try to set the invalid timezone "{invalid_timezone}"'):
        output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_CLOCK_TIMEZONE, invalid_timezone)

    with allure.step('Verify command failure'):
        expected_err = ClockConsts.ERR_BAD_TIMEZONE.format(invalid_timezone)
        assert expected_err in output, \
            f'Error: The given string does not contain the expected substring.\n' \
            f'Expected substring: "{expected_err}"\n' \
            f'Given (whole) string: "{output}"'

    with allure.step('Verify timezone has not changed'):
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
    with allure.step('Select valid date and time to set'):
        new_date = ClockUtils.select_random_date()
        new_time = ClockUtils.select_random_time()
        new_datetime = new_date + ' ' + new_time

    with allure.step(f'Set new date and time "{new_datetime}"'):
        output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_CLOCK_DATE, new_datetime)

    with allure.step('Verify command success'):
        assert output == ClockConsts.OUTPUT_CMD_SUCCESS, f'Expected: "{output}" == "{ClockConsts.OUTPUT_CMD_SUCCESS}"'

    with allure.step(f'Verify date and time changed to "{new_datetime}"'):
        with allure.step('Get datetime from show clock'):
            show_clock_output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_SHOW_CLOCK)
            show_clock_dict = ClockUtils.verify_and_parse_show_clock_output(show_clock_output)

        with allure.step('Verify date-time'):
            cur_date = show_clock_dict[ClockConsts.DATE]
            cur_time = show_clock_dict[ClockConsts.TIME]
            cur_datetime = f'{cur_date} {cur_time}'

            ClockUtils.verify_datetime(expected=new_datetime, actual=cur_datetime)

    with allure.step('Select random string as invalid input'):
        rand_str = ''.join(random.choice(string.ascii_lowercase) for _ in range(ClockConsts.RANDOM_NUM))
        logging.info(f'Selected random string: "{rand_str}"')

    with allure.step('Try to set invalid inputs'):
        errors = {
            '': ClockConsts.ERR_MISSING_DATE,
            rand_str: ClockConsts.ERR_MISSING_TIME,
            f'{rand_str} {rand_str}': f'{ClockConsts.ERR_BAD_DATE.format(rand_str)}\n'
                                      f'{ClockConsts.ERR_BAD_TIME.format(rand_str)}',
            f'{rand_str} {new_time}': ClockConsts.ERR_BAD_DATE.format(rand_str),
            f'{new_date} {rand_str}': ClockConsts.ERR_BAD_TIME.format(rand_str)
        }

        for invalid_input, err_msg in errors.items():
            logging.info(f'Invalid input: "{invalid_input}"\nExpected error:\n{err_msg}')

            with allure.step('Get show clock output before running the config command'):
                show_clock_output_before = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_SHOW_CLOCK)

            with allure.step(f'Try to set "{invalid_input}"'):
                output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_CLOCK_DATE, invalid_input)

            with allure.step('Get show clock output after running the config command'):
                show_clock_output_after = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_SHOW_CLOCK)

            with allure.step('Verify command failure'):
                assert err_msg in output, \
                    f'Error: The given string does not contain the expected substring.\n' \
                    f'Expected substring: "{err_msg}"\n' \
                    f'Given (whole) string: "{output}"'

            with allure.step(f'Verify date and time have not changed (still "{new_datetime}")'):
                show_clock_dict_before = ClockUtils.verify_and_parse_show_clock_output(show_clock_output_before)
                show_clock_dict_after = ClockUtils.verify_and_parse_show_clock_output(show_clock_output_after)

                with allure.step('Verify date-time'):
                    date_before = show_clock_dict_before[ClockConsts.DATE]
                    time_before = show_clock_dict_before[ClockConsts.TIME]
                    datetime_before = f'{date_before} {time_before}'

                    date_after = show_clock_dict_after[ClockConsts.DATE]
                    time_after = show_clock_dict_after[ClockConsts.TIME]
                    datetime_after = f'{date_after} {time_after}'

                    ClockUtils.verify_datetime(expected=datetime_before, actual=datetime_after)
