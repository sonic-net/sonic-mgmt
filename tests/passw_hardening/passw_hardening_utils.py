import logging
import os
import difflib
import operator
import six
from tests.common.helpers.assertions import pytest_assert

CURR_DIR = os.path.dirname(os.path.abspath(__file__))

# Sample/Expected files
PAM_PASSWORD_CONF_DEFAULT_EXPECTED = CURR_DIR + '/sample/passw_hardening_default/common-password'
PAM_PASSWORD_CONF_EXPECTED = CURR_DIR + '/sample/passw_hardening_enable/common-password'
PAM_PASSWORD_CONF_HISTORY_ONLY_EXPECTED = CURR_DIR + '/sample/passw_hardening_history/common-password'
PAM_PASSWORD_CONF_REJECT_USER_PASSW_MATCH_EXPECTED = \
    CURR_DIR + '/sample/passw_hardening_reject_user_passw_match/common-password'
PAM_PASSWORD_CONF_DIGITS_ONLY_EXPECTED = CURR_DIR + '/sample/passw_hardening_digits/common-password'
PAM_PASSWORD_CONF_LOWER_LETTER_ONLY_EXPECTED = CURR_DIR + '/sample/passw_hardening_lower_letter/common-password'
PAM_PASSWORD_CONF_UPPER_LETTER_ONLY_EXPECTED = CURR_DIR + '/sample/passw_hardening_upper_letter/common-password'
PAM_PASSWORD_CONF_SPECIAL_LETTER_ONLY_EXPECTED = CURR_DIR + '/sample/passw_hardening_special_letter/common-password'
PAM_PASSWORD_CONF_LEN_MIN_ONLY_EXPECTED = CURR_DIR + '/sample/passw_hardening_min_len/common-password'
PAM_PASSWORD_CONF_OUTPUT = CURR_DIR + '/output/login.def'
PAM_PASSWORD_CONF = "/etc/pam.d/common-password"

# users
USERNAME_STRONG = 'user_strong_test'
USERNAME_SIMPLE_0 = 'user_simple_0_test'
USERNAME_SIMPLE_1 = 'user_simple_1_test'
USERNAME_SIMPLE_2 = 'user_simple_2_test'
USERNAME_ONE_POLICY = 'user_one_policy_test'
USERNAME_AGE = 'user_test'
USERNAME_HISTORY = 'user_history_test'
USERNAME_LEN_MIN = 'user_test'


class PasswHardening:
    def __init__(self, state='disabled', expiration='100', expiration_warning='15', history='12',
                 len_min='8', reject_user_passw_match='true', lower_class='true',
                 upper_class='true', digit_class='true', special_class='true'):
        self.policies = {
            "state": state,
            "expiration": expiration,
            "expiration-warning": expiration_warning,
            "history-cnt": history,
            "len-min": len_min,
            "reject-user-passw-match": reject_user_passw_match,
            "lower-class": lower_class,
            "upper-class": upper_class,
            "digits-class": digit_class,
            "special-class": special_class
        }


def config_user(duthost, username, mode='add'):
    """ Function add or rm users using useradd/userdel tool. """

    username = username.strip()
    command = "user{} {}".format(mode, username)
    user_cmd = duthost.shell(command, module_ignore_errors=True)
    return user_cmd


def configure_passw_policies(duthost, passw_hardening_ob):
    for key, value in list(passw_hardening_ob.policies.items()):
        logging.debug("configuration to be set: key={}, value={}".format(key, value))
        # cmd_config = 'sudo config passw-hardening policies ' + key + ' ' + value

        cmd_config = 'sudo config passw-hardening policies {} {}'.format(key, value)

        duthost.command(cmd_config)
    return True


def compare_passw_policies_in_linux(duthost, pam_file_expected=PAM_PASSWORD_CONF_EXPECTED):
    """Compare DUT common-password with the expected one."""

    command_password_stdout = ''
    read_command_password = 'cat {}'.format(PAM_PASSWORD_CONF)

    logging.debug('DUT command = {}'.format(read_command_password))
    read_command_password_cmd = duthost.command(read_command_password)
    command_password_stdout = read_command_password_cmd["stdout_lines"]
    command_password_stdout = [six.ensure_str(line) for line in command_password_stdout]

    common_password_expected = []
    with open(pam_file_expected, 'r') as expected_common_password_file:
        for line in expected_common_password_file:
            line = line.strip()
            line = line.strip('\n')
            line = line.strip('\t')
            common_password_expected.append(line)

    common_password_diff = [li for li in difflib.ndiff(command_password_stdout, common_password_expected) if
                            li[0] != ' ']
    error_message = 'password diff: ' + '; '.join(common_password_diff)
    pytest_assert(len(common_password_diff) == 0, error_message)


def config_and_review_policies(duthost, passw_hardening_ob, pam_file_expected):
    """
    1. Config passw hardening policies
    2. Show passw hardening policies
    3. Compare passw hardening polices from show cli to the expected (configured)
    4. Verify polices in PAM files was set according the configured
    """
    FIRST_LINE = 0
    configure_passw_policies(duthost, passw_hardening_ob)

    curr_show_policies = duthost.show_and_parse('show passw-hardening policies')[FIRST_LINE]
    exp_show_policies = dict((k.replace('-', ' '), v) for k, v in list(passw_hardening_ob.policies.items()))

    # ~~ test passw policies in show CLI ~~
    cli_passw_policies_cmp = operator.eq(exp_show_policies, curr_show_policies)
    pytest_assert(cli_passw_policies_cmp is True, "Fail: exp_show_policies='{}',not equal to curr_show_policies='{}'"
                  .format(exp_show_policies, curr_show_policies))

    # ~~ test passw policies in PAM files ~~
    compare_passw_policies_in_linux(duthost, pam_file_expected)
