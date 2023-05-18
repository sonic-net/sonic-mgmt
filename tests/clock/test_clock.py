import logging
import random
import string
import pytest

from tests.clock.ClockUtils import ClockUtils, allure_step
from tests.clock.ClockConsts import ClockConsts

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health,
    pytest.mark.clock
]


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

    with allure_step(f'Set the new timezone "{new_timezone}"'):
        output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_CLOCK_TIMEZONE, new_timezone)

    with allure_step('Verify command success'):
        ClockUtils.verify_command(cmd_output=output, should_succeed=True)

    with allure_step(f'Verify timezone changed to "{new_timezone}"'):
        ClockUtils.verify_timezone_value(duthosts, expected_tz_name=new_timezone)

    with allure_step('Select a random string as invalid timezone'):
        invalid_timezone = ''.join(random.choice(string.ascii_lowercase) for _ in range(random.randint(1, 10)))
        while invalid_timezone in valid_timezones:
            invalid_timezone = ''.join(random.choice(string.ascii_lowercase) for _ in range(random.randint(1, 10)))
        logging.info(f'Selected invalid timezone: "{invalid_timezone}"')

    with allure_step(f'Try to set the invalid timezone "{invalid_timezone}"'):
        output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_CLOCK_TIMEZONE, invalid_timezone)

    with allure_step('Verify command failure'):
        ClockUtils.verify_command(cmd_output=output, should_succeed=False, expected_err=ClockConsts.ERR_BAD_TIMEZONE
                                  .format(invalid_timezone))

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

    with allure_step(f'Set new date and time "{new_datetime}"'):
        output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_CLOCK_DATE, new_datetime)

    with allure_step('Verify command success'):
        ClockUtils.verify_command(cmd_output=output, should_succeed=True)

    with allure_step(f'Verify date and time changed to "{new_datetime}"'):
        with allure_step('Get datetime from show clock'):
            show_clock_output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_SHOW_CLOCK)
            show_clock_dict = ClockUtils.verify_and_parse_show_clock_output(show_clock_output)

        with allure_step('Verify date-time'):
            cur_date = show_clock_dict[ClockConsts.DATE]
            cur_time = show_clock_dict[ClockConsts.TIME]
            cur_datetime = f'{cur_date} {cur_time}'

            ClockUtils.verify_datetime(expected=new_datetime, actual=cur_datetime)

    with allure_step('Select random string as invalid input'):
        rand_str = ''.join(random.choice(string.ascii_lowercase) for _ in range(ClockConsts.RANDOM_NUM))
        logging.info(f'Selected random string: "{rand_str}"')

    with allure_step('Try to set invalid inputs'):
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

            with allure_step('Get show clock output before running the config command'):
                show_clock_output_before = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_SHOW_CLOCK)

            with allure_step(f'Try to set "{invalid_input}"'):
                output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_CLOCK_DATE, invalid_input)

            with allure_step('Get show clock output after running the config command'):
                show_clock_output_after = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_SHOW_CLOCK)

            with allure_step('Verify command failure'):
                ClockUtils.verify_command(cmd_output=output, should_succeed=False, expected_err=err_msg)

            with allure_step(f'Verify date and time have not changed (still "{new_datetime}")'):
                show_clock_dict_before = ClockUtils.verify_and_parse_show_clock_output(show_clock_output_before)
                show_clock_dict_after = ClockUtils.verify_and_parse_show_clock_output(show_clock_output_after)

                with allure_step('Verify date-time'):
                    date_before = show_clock_dict_before[ClockConsts.DATE]
                    time_before = show_clock_dict_before[ClockConsts.TIME]
                    datetime_before = f'{date_before} {time_before}'

                    date_after = show_clock_dict_after[ClockConsts.DATE]
                    time_after = show_clock_dict_after[ClockConsts.TIME]
                    datetime_after = f'{date_after} {time_after}'

                    ClockUtils.verify_datetime(expected=datetime_before, actual=datetime_after)
