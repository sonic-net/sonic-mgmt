import logging
import random
import time
import datetime as dt
import pytest
import allure

from contextlib import contextmanager
from tests.clock.ClockConsts import ClockConsts
from tests.common.errors import RunAnsibleModuleFail


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
            DUT_HOSTNAME = duthosts[0].hostname

            cmd_to_run = cmd if param == '' else cmd + ' ' + param
            logging.info('Actual command to run: "{}"'.format(cmd_to_run))

            try:
                cmd_output = duthosts.command(cmd_to_run)[DUT_HOSTNAME][ClockConsts.STDOUT]
            except RunAnsibleModuleFail as cmd_err:
                output = cmd_err.results[ClockConsts.STDOUT]
                err = cmd_err.results[ClockConsts.STDERR]
                cmd_output = output if output else err
                logging.info('Command Error!\nError message: "{}"'.format(cmd_output))

            logging.info('Convert output to string')
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

            with allure_step('Compare timezone abbreviations of show clock ({}) and timedatectl ({})'
                             .format(show_clock_tz_abbr, timedatectl_tz_abbr)):
                assert timedatectl_tz_abbr == show_clock_tz_abbr, \
                    'Expected: {} == {}'.format(timedatectl_tz_abbr, show_clock_tz_abbr)

            with allure_step('Compare timezone name from timedatectl ({}) to the expected ({})'.format(timedatectl_tz_name, expected_tz_name)):
                assert timedatectl_tz_name == expected_tz_name, 'Expected: {} == {}'.format(timedatectl_tz_name, expected_tz_name)

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
        with allure_step('Verify that diff between "{}" and "{}" (in seconds) is no longer than {}'
                         .format(expected, actual, allowed_margin)):
            with allure_step('Calculate diff between "{}" and "{}" in seconds'.format(expected, actual)):
                datetime_obj1 = dt.datetime.strptime(expected, "%Y-%m-%d %H:%M:%S")
                datetime_obj2 = dt.datetime.strptime(actual, "%Y-%m-%d %H:%M:%S")

                diff_seconds = abs((datetime_obj2 - datetime_obj1).total_seconds())

            with allure_step('Verify that actual diff {} is not larger than {}'.format(diff_seconds, allowed_margin)):
                assert diff_seconds <= allowed_margin, 'Expected: {} <= {}'.format(diff_seconds, allowed_margin)
