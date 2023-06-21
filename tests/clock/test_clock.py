import logging
import random
import string
import pytest
import allure

from tests.clock.ClockUtils import ClockUtils
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
    with allure.step('Run show clock command'):
        logging.info('Run show clock command')
        show_clock_output = ClockUtils.run_cmd(duthosts=duthosts, cmd=ClockConsts.CMD_SHOW_CLOCK)

    with allure.step('Verify info is valid'):
        logging.info('Verify info is valid')
        output_dict = ClockUtils.parse_show_clock_output(show_clock_output)
        ClockUtils.validate_date(output_dict[ClockConsts.DATE])
        ClockUtils.validate_time(output_dict[ClockConsts.TIME])
        ClockUtils.validate_timezone(output_dict[ClockConsts.TIMEZONE], duthosts)


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
    orig_timezone = ClockUtils \
        .parse_show_clock_output(ClockUtils.run_cmd(duthosts, ClockConsts.CMD_SHOW_CLOCK))[ClockConsts.TIMEZONE]

    with allure.step('Select a random new valid timezone'):
        logging.info('Select a random new valid timezone')
        new_timezone = random.choice(valid_timezones)
        while new_timezone == orig_timezone:
            new_timezone = random.choice(valid_timezones)

    with allure.step('Set the new timezone "{}"'.format(new_timezone)):
        logging.info('Set the new timezone "{}"'.format(new_timezone))
        output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_CLOCK_TIMEZONE, new_timezone)

    with allure.step('Verify command success'):
        logging.info('Verify command success')
        ClockUtils.verify_command(cmd_output=output, should_succeed=True)

    with allure.step('Verify timezone changed to "{}"'.format(new_timezone)):
        logging.info('Verify timezone changed to "{}"'.format(new_timezone))
        cur_timezone = ClockUtils \
            .parse_show_clock_output(ClockUtils.run_cmd(duthosts, ClockConsts.CMD_SHOW_CLOCK))[ClockConsts.TIMEZONE]
        ClockUtils.verify_timezone_value(duthosts, tz_name=new_timezone, tz_abbreviation=cur_timezone)

    with allure.step('Select a random string as invalid timezone'):
        logging.info('Select a random string as invalid timezone')
        invalid_timezone = ''.join(random.choice(string.ascii_lowercase) for _ in range(random.randint(1, 10)))
        while invalid_timezone in valid_timezones:
            invalid_timezone = ''.join(random.choice(string.ascii_lowercase) for _ in range(random.randint(1, 10)))
        logging.info('Selected invalid timezone: "{}"'.format(invalid_timezone))

    with allure.step('Try to set the invalid timezone "{}"'.format(invalid_timezone)):
        logging.info('Try to set the invalid timezone "{}"'.format(invalid_timezone))
        output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_CLOCK_TIMEZONE, invalid_timezone)

    with allure.step('Verify command failure'):
        logging.info('Verify command failure')
        ClockUtils.verify_command(cmd_output=output, should_succeed=False, expected_err=ClockConsts.ERR_BAD_TIMEZONE
                                  .format(invalid_timezone))

    with allure.step('Verify timezone has not changed'):
        logging.info('Verify timezone has not changed')
        cur_timezone = ClockUtils \
            .parse_show_clock_output(ClockUtils.run_cmd(duthosts, ClockConsts.CMD_SHOW_CLOCK))[ClockConsts.TIMEZONE]
        ClockUtils.verify_timezone_value(duthosts, tz_name=new_timezone, tz_abbreviation=cur_timezone)


def test_config_clock_date(duthosts, init_timezone, restore_time):
    """
    @summary:
        Check that 'config clock ate' command works correctly

        Steps:
        1. Set a new valid date and time using the command
        2. Verify date and time changed
        3. Try to set invalid date and time
        4. Verify error and that time hasn't changed
    """
    with allure.step('Select valid date and time to set'):
        logging.info('Select valid date and time to set')
        new_date = ClockUtils.select_random_date()
        new_time = ClockUtils.select_random_time()
        new_datetime = new_date + ' ' + new_time

    with allure.step('Set new date and time "{}"'.format(new_datetime)):
        logging.info('Set new date and time "{}"'.format(new_datetime))
        output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_CLOCK_DATE, new_datetime)

    with allure.step('Verify command success'):
        logging.info('Verify command success')
        ClockUtils.verify_command(cmd_output=output, should_succeed=True)

    with allure.step('Verify date and time changed to "{}"'.format(new_datetime)):
        logging.info('Verify date and time changed to "{}"'.format(new_datetime))
        with allure.step('Get datetime from show clock'):
            logging.info('Get datetime from show clock')
            show_clock_output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_SHOW_CLOCK)
            show_clock_dict = ClockUtils.parse_show_clock_output(show_clock_output)

        with allure.step('Verify date'):
            logging.info('Verify date')
            cur_date = ClockUtils.convert_show_clock_date(show_clock_dict[ClockConsts.DATE])
            ClockUtils.verify_value(expected=new_date, actual=cur_date)

        with allure.step('Verify time'):
            logging.info('Verify time')
            cur_time = ClockUtils.convert_show_clock_time(show_clock_dict[ClockConsts.TIME])
            ClockUtils.verify_time(expected=new_time, actual=cur_time)

    with allure.step('Select random string as invalid input'):
        logging.info('Select random string as invalid input')
        rand_str = ''.join(random.choice(string.ascii_lowercase) for i in range(ClockConsts.RANDOM_NUM))
        logging.info('Selected random string: "{}"'.format(rand_str))

    with allure.step('Try to set invalid inputs'):
        logging.info('Try to set invalid inputs')
        errors = {
            '': ClockConsts.ERR_MISSING_DATE,
            rand_str: ClockConsts.ERR_MISSING_TIME,
            rand_str + ' ' + rand_str: ClockConsts.ERR_BAD_DATE.format(rand_str) + '\n' + ClockConsts.ERR_BAD_TIME
            .format(rand_str),
            rand_str + ' ' + new_time: ClockConsts.ERR_BAD_DATE.format(rand_str),
            new_date + ' ' + rand_str: ClockConsts.ERR_BAD_TIME.format(rand_str)
        }

        i = 0
        for invalid_input, err_msg in errors.items():
            logging.info('Invalid input #{}: "{}"\nExpected error:\n{}'.format(i, invalid_input, err_msg))

            with allure.step('Get show clock output before running the config command'):
                logging.info('Get show clock output before running the config command')
                show_clock_output_before = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_SHOW_CLOCK)

            with allure.step('Try to set "{}"'.format(invalid_input)):
                logging.info('Try to set "{}"'.format(invalid_input))
                output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_CLOCK_DATE, invalid_input)

            with allure.step('Get show clock output after running the config command'):
                logging.info('Get show clock output after running the config command')
                show_clock_output_after = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_SHOW_CLOCK)

            with allure.step('Verify command failure'):
                logging.info('Verify command failure')
                ClockUtils.verify_command(cmd_output=output, should_succeed=False, expected_err=err_msg)

            with allure.step('Verify date and time have not changed (still "{}")'.format(new_datetime)):
                logging.info('Verify date and time have not changed (still "{}")'.format(new_datetime))
                show_clock_dict_before = ClockUtils.parse_show_clock_output(show_clock_output_before)
                show_clock_dict_after = ClockUtils.parse_show_clock_output(show_clock_output_after)

                with allure.step('Verify date'):
                    logging.info('Verify date')
                    ClockUtils.verify_value(expected=show_clock_dict_before[ClockConsts.DATE],
                                            actual=show_clock_dict_after[ClockConsts.DATE])

                with allure.step('Verify time'):
                    logging.info('Verify time')
                    time_before = ClockUtils.convert_show_clock_time(show_clock_dict_before[ClockConsts.TIME])
                    time_after = ClockUtils.convert_show_clock_time(show_clock_dict_after[ClockConsts.TIME])
                    ClockUtils.verify_time(expected=time_before, actual=time_after)

            i += 1
