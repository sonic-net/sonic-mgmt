import logging
import random
import datetime
import allure
import time

from tests.common.helpers.assertions import pytest_assert
from tests.clock.ClockConsts import ClockConsts
from tests.common.errors import RunAnsibleModuleFail


class ClockUtils:
    @staticmethod
    def run_cmd(duthosts, cmd, param=''):
        """
        @summary:
            Run a given command and return it's output.
            * a successful command returns empty output (''), while failure returns error message
        @return: commands output (str)
        """
        with allure.step('Run command: "{}" with param "{}"'.format(cmd, param)):
            logging.info('Run command: "{}" with param "{}"'.format(cmd, param))
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
            logging.info('Output type: {}'.format(type(cmd_output)))
            logging.info('Output: {}'.format(cmd_output))

        with allure.step('Convert output to string'):
            logging.info('Convert output to string')
            cmd_output = str(cmd_output)
            logging.info('Output type: {}'.format(type(cmd_output)))
            logging.info('Output: {}'.format(cmd_output))
        return cmd_output

    @staticmethod
    def parse_show_clock_output(show_clock_output):
        """
        @summary:
            Split output of show clock into date, time and timezone strings

            Exapmple:
            "Mon 03 Apr 2023 11:29:46 AM UTC" -> {"date": "Mon 03 Apr 2023", "time": "11:29:46 AM", "timezone": "UTC"}
        @param show_clock_output: the given show clock output
        @return: The splited output as a dict
        """
        with allure.step('Split output of show clock'):
            logging.info('Split output of show clock')
            output_list = show_clock_output.split(' ')
            date = ' '.join(output_list[0:4])
            time = ' '.join(output_list[4:6])
            timezone = ' '.join(output_list[6:])
            logging.info('Splited output:\ndate: "{}"\ntime: "{}"\ntimezone: "{}"'.format(date, time, timezone))

            res = {
                ClockConsts.DATE: date,
                ClockConsts.TIME: time,
                ClockConsts.TIMEZONE: timezone
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
        with allure.step('Parse linux command output into dictionary'):
            logging.info('Parse linux command output into dictionary')
            rows = [row.strip() for row in linux_cmd_output.split('\n')]  # split by rows
            logging.info('rows: {}'.format(rows))
            res_dict = {}
            for row in rows:
                logging.info('row: "{}"'.format(row))
                idx = row.index(':')
                k, v = row[0: idx], row[idx + 2:]
                res_dict[k] = v
            logging.info('Result dict:\n{}'.format(res_dict))
            return res_dict

    @staticmethod
    def validate_date(date_str):
        """
        @summary:
            Verify that given string is in a good date format: "Mon 03 Apr 2023"
        @param date_str: the given string
        """
        with allure.step('Validate date for: "{}"'.format(date_str)):
            logging.info('Validate date for: "{}"'.format(date_str))
            try:
                datetime.datetime.strptime(date_str, "%a %d %b %Y")
                logging.info('Validate date success')
            except ValueError:
                logging.info('Validate date fail')
                pytest_assert(False, 'Given string "{}" is not a valid date'.format(date_str))

    @staticmethod
    def validate_time(time_str):
        """
        @summary:
            Verify that given string is in a good time format: "11:29:46 AM" (or PM)
        @param time_str: the given string
        """
        with allure.step('Validate time for: "{}"'.format(time_str)):
            logging.info('Validate time for: "{}"'.format(time_str))
            try:
                datetime.datetime.strptime(time_str, "%I:%M:%S %p")
                logging.info('Validate time success')
            except ValueError:
                logging.info('Validate time fail')
                pytest_assert(False, 'Given string "{}" is not a valid time'.format(time_str))

    @staticmethod
    def get_valid_timezones(duthosts):
        """
        @summary:
            Get the list of valid timezones from 'show clock timezones' command
        @param duthosts: duthosts object
        @return: list of timezones (strings)
        """
        with allure.step('Get list of valid timezones from show clock timezones command'):
            logging.info('Get list of valid timezones from show clock timezones command')
            return ClockUtils.run_cmd(duthosts=duthosts, cmd=ClockConsts.CMD_SHOW_CLOCK_TIMEZONES).split()

    @staticmethod
    def validate_timezone(timezone_str, duthosts):
        """
        @summary:
            Verify that the given string is an abbreviation of a valid timezone
        @param timezone_str: the given string
        @param duthosts: duthosts
        """
        with allure.step('Verify that given string "{}" is a valid timezone'.format(timezone_str)):
            logging.info('Verify that given string "{}" is a valid timezone'.format(timezone_str))

            with allure.step('Get timezone from timedatectl linux command'):
                logging.info('Get timezone from timedatectl linux command')
                timedatectl_output = \
                    ClockUtils.parse_linux_cmd_output(ClockUtils.run_cmd(duthosts, ClockConsts.CMD_TIMEDATECTL))
                timedatectl_timezone = timedatectl_output[ClockConsts.TIME_ZONE]
                timedatectl_tz_name = timedatectl_timezone.split()[0]
                timedatectl_tz_abbreviation = timedatectl_timezone.split(' ')[1].split(',')[0].replace('(', '')
                logging.info('Timezone in timedatectl: "{}"\nTimezone name: "{}"\nTimezone abbreviation: "{}"'
                             .format(timedatectl_timezone, timedatectl_tz_name, timedatectl_tz_abbreviation))

            with allure.step('Verify timezone name "{}" from timedatectl is in valid timezones'
                             .format(timedatectl_tz_name)):
                logging.info('Verify timezone name "{}" from timedatectl is in valid timezones'
                             .format(timedatectl_tz_name))
                valid_timezones = ClockUtils.get_valid_timezones(duthosts)
                pytest_assert(timedatectl_tz_name in valid_timezones,
                              'Error: string "{}" is not in the valid timezones list'.format(timezone_str))

            with allure.step('Verify that the given timezone "{}" equals to timezone abbreviation in timedatectl "{}"'
                             .format(timezone_str, timedatectl_tz_abbreviation)):
                logging.info('Verify that the given timezone "{}" equals to timezone abbreviation in timedatectl "{}"'
                             .format(timezone_str, timedatectl_tz_abbreviation))
                ClockUtils.verify_value(expected=timedatectl_tz_abbreviation, actual=timezone_str)

    @staticmethod
    def verify_value(expected, actual, should_be_equal=True):
        """
        @summary:
            Asserts a given value is as expected
        @param expected: expected value
        @param actual: actual given value
        """
        expected_to_print = "''" if expected == '' else expected
        actual_to_print = "''" if actual == '' else actual

        if should_be_equal:
            with allure.step('Verify that actual value - {} is as expected - {}'
                             .format(expected_to_print, actual_to_print)):
                logging.info('Verify that actual value - {} is as expected - {}'
                             .format(expected_to_print, actual_to_print))
                pytest_assert(actual == expected, 'Error: Values are not equal.\nExpected: {}\t{}\nActual: {}\t{}'
                              .format(expected_to_print, type(expected), actual_to_print, type(actual)))
        else:
            with allure.step('Verify that actual value - {} is different than expected - {}'
                             .format(expected_to_print, actual_to_print)):
                logging.info('Verify that actual value - {} is different than expected - {}'
                             .format(expected_to_print, actual_to_print))
                pytest_assert(actual != expected, 'Error: Values are equal.\nExpected: {}\t{}\nActual: {}\t{}'
                              .format(expected_to_print, type(expected), actual_to_print, type(actual)))

    @staticmethod
    def verify_substring(expected_substr, whole_str):
        """
        @summary:
            Asserts that a given string contains an expected substring
        @param expected_substr: expected substring
        @param whole_str: the whole string
        """
        with allure.step('Verify that string "{}" contains the substring "{}"'.format(whole_str, expected_substr)):
            logging.info('Verify that string "{}" contains the substring "{}"'.format(whole_str, expected_substr))
            pytest_assert(expected_substr in whole_str,
                          'Error: The given string does not contain the expected substring.\n'
                          'Expected substring: "{}"\n'
                          'Given (whole) string: "{}"'.format(expected_substr, whole_str))

    @ staticmethod
    def verify_command(cmd_output, should_succeed=True, expected_err=''):
        """
        @summary:
            Verify command success/failure
            * doesn't apply on show command
            * in case of failure, user can specify an expected error message to be contained in the output
        @param cmd_output: the command's output
        @param should_succeed: whether the command should succeed or not
        @param expected_err: expected error message
        """
        if should_succeed:
            with allure.step('Verify that command succeeded'):
                logging.info('Verify that command succeeded')
                ClockUtils.verify_value(expected=ClockConsts.OUTPUT_CMD_SUCCESS, actual=cmd_output)
        else:
            with allure.step('Verify that command failed and output contains "{}"'.format(expected_err)):
                logging.info('Verify that command failed and output contains "{}"'.format(expected_err))
                ClockUtils.verify_substring(expected_substr=expected_err, whole_str=cmd_output)

    @ staticmethod
    def verify_timezone_value(duthosts, tz_name, tz_abbreviation):
        """
        @summary:
            Verify that a given timezone abbreviation matches the expected timezone.
            * Given timezone abbreviation from show clock command (ETC, IDT, etc.)
            * Assume that expected timezone should be given as a complete timezone name (ETC/UTC, Asia/Jerusalem, etc.)
        @param duthosts: duthosts object
        @param tz_name: The expected timezone
        @param tz_abbreviation: The actual given timezone abbreviation
        """
        with allure.step('Verify that given timezone abbreviation "{}" matches to expected timezone "{}"'
                         .format(tz_abbreviation, tz_name)):
            logging.info('Verify that given timezone abbreviation "{}" matches to expected timezone "{}"'
                         .format(tz_abbreviation, tz_name))

            with allure.step('Get timezone details from timedatectl command'):
                logging.info('Get timezone details from timedatectl command')
                timedatectl_output = \
                    ClockUtils.parse_linux_cmd_output(ClockUtils.run_cmd(duthosts, ClockConsts.CMD_TIMEDATECTL))
                timedatectl_timezone = timedatectl_output[ClockConsts.TIME_ZONE]
                timedatectl_tz_name = timedatectl_timezone.split()[0]
                timedatectl_tz_abbreviation = timedatectl_timezone.split(' ')[1].split(',')[0].replace('(', '')
                logging.info('Timezone in timedatectl: "{}"\nTimezone name: "{}"\nTimezone abbreviation: "{}"'
                             .format(timedatectl_timezone, timedatectl_tz_name, timedatectl_tz_abbreviation))

            with allure.step('Check that given timezone "{}" equals to timezone in timedatectl "{}"'
                             .format(tz_name, timedatectl_tz_name)):
                logging.info('Check that given timezone "{}" equals to timezone in timedatectl "{}"'
                             .format(tz_name, timedatectl_tz_name))
                ClockUtils.verify_value(expected=timedatectl_tz_name, actual=tz_name)

            with allure.step('Check that given timezone abbreviation "{}" matches the expected timezone "{}"'
                             .format(tz_abbreviation, tz_name)):
                logging.info('Check that given timezone abbreviation "{}" matches the expected timezone "{}"'
                             .format(tz_abbreviation, tz_name))
                ClockUtils.verify_value(expected=timedatectl_tz_abbreviation, actual=tz_abbreviation)

    @ staticmethod
    def select_random_date():
        """
        @summary:
            Select a random date
        @return: a random date as string in the format "YYYY-MM-DD"
        """
        with allure.step('Select a random date'):
            logging.info('Select a random date')
            start_date = datetime.date.fromisoformat(ClockConsts.MIN_SYSTEM_DATE)
            end_date = datetime.date.fromisoformat(ClockConsts.MAX_SYSTEM_DATE)

            diff_days = (end_date - start_date).days

            rand_num_of_days = random.randint(0, diff_days)

            rand_date = start_date + datetime.timedelta(days=rand_num_of_days)

            rand_date_str = rand_date.strftime('%Y-%m-%d')

            logging.info('Selected random date: "{}"'.format(rand_date_str))
            return rand_date_str

    @ staticmethod
    def select_random_time():
        """
        @summary:
            Select a random time
        @return: a random date as string in the format "hh:mm:ss"
        """
        with allure.step('Select a random time in a day'):
            logging.info('Select a random time in a day')
            rand_num_of_seconds_since_00 = random.randint(0, 24 * 60 * 60 - 1)

            rand_time_obj = time.gmtime(rand_num_of_seconds_since_00)

            rand_time_str = time.strftime("%H:%M:%S", rand_time_obj)

            logging.info('Selected random time: "{}"'.format(rand_time_str))
            return rand_time_str

    @ staticmethod
    def convert_show_clock_date(show_clock_date):
        """
        @summary:
            Convert date from show clock to format "YYYY-MM-DD"
            e.g. "Wed 12 Apr 2023" --> "2023-04-12"
        @param show_clock_date: given date from show clock
        @return: converted date
        """
        with allure.step('Convert date "{}" to format "YYYY-MM-DD"'.format(show_clock_date)):
            logging.info('Convert date "{}" to format "YYYY-MM-DD"'.format(show_clock_date))
            converted_date = datetime.datetime.strptime(show_clock_date, "%a %d %b %Y").strftime("%Y-%m-%d")
            logging.info('Converted date: "{}"'.format(converted_date))
            return converted_date

    @ staticmethod
    def convert_show_clock_time(show_clock_time):
        """
        @summary:
            Convert time from show clock to format "hh:mm:ss"
            e.g. "02:14:28 PM" --> "14:14:28"
        @param show_clock_time: given time from show clock
        @return: converted me
        """
        with allure.step('Convert time "{}" to format "hh:mm:ss"'.format(show_clock_time)):
            logging.info('Convert time "{}" to format "hh:mm:ss"'.format(show_clock_time))
            converted_time = datetime.datetime.strptime(show_clock_time, "%I:%M:%S %p").strftime("%H:%M:%S")
            logging.info('Converted time: "{}"'.format(converted_time))
            return converted_time

    @ staticmethod
    def verify_time(expected, actual, allowed_margin=ClockConsts.TIME_MARGIN):
        """
        @summary:
            Asserts a given time value is as expected
            * expected and actual time values are strings in the format "HH:MM:SS"
        @param expected: expected time value
        @param actual: actual given time value
        @param allowed_margin: allowed margin between two times (in seconds)
        """
        with allure.step('Verify that diff between "{}" and "{}" (in seconds) is no longer than {}'
                         .format(expected, actual, allowed_margin)):
            logging.info('Verify that diff between "{}" and "{}" (in seconds) is no longer than {}'
                         .format(expected, actual, allowed_margin))

            with allure.step('Calculate diff between "{}" and "{}" in seconds'.format(expected, actual)):
                logging.info('Calculate diff between "{}" and "{}" in seconds'.format(expected, actual))
                time_obj1 = datetime.datetime.strptime(expected, "%H:%M:%S")
                time_obj2 = datetime.datetime.strptime(actual, "%H:%M:%S")

                diff_seconds = abs((time_obj2 - time_obj1).total_seconds())

            with allure.step('Verify that actual diff {} is not larger than {}'.format(diff_seconds, allowed_margin)):
                logging.info('Verify that actual diff {} is not larger than {}'.format(diff_seconds, allowed_margin))
                ClockUtils.verify_value(True, diff_seconds <= allowed_margin)
