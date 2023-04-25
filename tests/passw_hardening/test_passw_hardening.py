"""
Tests Password Hardening Feature:
- test all posibles policies configuration.
- test 'show password policies' command.
- test end to end by adding new user and set passwords according passw policies configured in the different tests.
"""

import logging
import re
import pytest
import datetime
import six
from tests.common.helpers.assertions import pytest_assert
from . import passw_hardening_utils

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('any')
]

AGE_DICT = {'MAX_DAYS': {'REGEX_DAYS': 'grep \'^PASS_MAX_DAYS[ \\t]*\'', 'DAYS': 'max_days', 'CHAGE_FLAG': '-M '},
            'WARN_DAYS': {'REGEX_DAYS': 'grep \'^PASS_WARN_AGE[ \\t]*\'', 'DAYS': 'warn_days', 'CHAGE_FLAG': '-W '}
            }

SUCCESS_CODE = 0


def config_user_and_passw(duthost, username, password):
    """ Config users and set password. """

    username = username.strip()
    passw_hardening_utils.config_user(duthost, username)
    chpasswd_cmd = change_password(duthost, password, username)
    return chpasswd_cmd


def change_password(duthost, password, username):
    cmd = 'echo {}:{} | chpasswd'.format(username, password)
    chpasswd_cmd = duthost.shell(cmd, module_ignore_errors=True)
    return chpasswd_cmd


def get_user_expire_time_global(duthost, age_type):
    """ Function get the expire/expire warning days from linux filename login.def
        according the age_type.
    """

    FIRST_LINE = 0
    DAY_INDEX = 1
    days_num = -1

    regex_days = AGE_DICT[age_type]['REGEX_DAYS']
    command = '{} /etc/login.defs'.format(regex_days)

    grep_max_days_out = six.ensure_str(duthost.command(command)["stdout_lines"][FIRST_LINE])

    days_num = grep_max_days_out.split()[DAY_INDEX]
    logging.debug('command output lines = {}'.format(grep_max_days_out))

    return days_num


def modify_last_password_change_user(duthost, normal_account):
    "Modify the passw change day of a user (subtract 100 days)."

    days_to_subtract = 100
    old_date = datetime.date.today() - datetime.timedelta(days=days_to_subtract)
    command = 'chage {} -i --lastday {}'.format(normal_account, str(old_date.isoformat()))

    duthost.command(command)
    return


def get_passw_expire_time_existing_user(duthost, normal_account):
    last_passw_change = ''
    REGEX_MAX_PASSW_CHANGE = r'^Maximum number of days between password change[ \t]*:[ \t]*(?P<max_passw_change>.*)'

    command = 'chage -l {}'.format(normal_account)
    chage_stdout = duthost.command(command)["stdout_lines"]

    for line in chage_stdout:
        m1 = re.match(REGEX_MAX_PASSW_CHANGE, six.ensure_text(line))
        if m1:
            last_passw_change = six.ensure_text(m1.group("max_passw_change"))
            break

    return last_passw_change


def check_expiration_value(duthost, expiration_value):
    """
    Determine whether last password change date will be expired compared
    to expiration value to be set
    Args:
        duthost: duthost object
        expiration_value: expiration value to be checked
    Return:
        expiration: Expiration value to be set
    """
    msg = "Expiration diff is {}; Expected expiration to set {}; expiration used {}"
    last_passw_change = duthost.shell('chage -l `echo "$USER"` | head -1')['stdout']
    date = ' '.join(last_passw_change.split()[-3:])
    exp_diff = datetime.datetime.today() - datetime.datetime.strptime(date, "%b %d, %Y")
    expiration = exp_diff.days + 2 if exp_diff.days > expiration_value else expiration_value
    logging.info(msg.format(exp_diff.days, expiration_value, expiration))
    return str(expiration)


def compare_passw_age_in_pam_dir(duthost, passw_hardening_ob, username=None):
    '''
    This function testing age passw.
    1. test new user passw age support by parsing login.def file
    2. test existsting user by using chage tool.
    '''
    # compare global age (from login.def file)
    passw_max_days_global = get_user_expire_time_global(duthost, 'MAX_DAYS')
    passw_warn_days_global = get_user_expire_time_global(duthost, 'WARN_DAYS')

    pytest_assert(passw_max_days_global == passw_hardening_ob.policies['expiration'],
                  "Fail: expected max days exp='{}' ! current max days exp='{}' was not set, "
                  "even though, matching policy configured"
                  .format(passw_hardening_ob.policies['expiration'], passw_max_days_global))

    pytest_assert(passw_hardening_ob.policies['expiration-warning'] == passw_warn_days_global,
                  "Fail: expected max days exp='{}' ! current max days exp='{}' was not set, "
                  "even though, matching policy configured"
                  .format(passw_hardening_ob.policies['expiration-warning'], passw_warn_days_global))

    # --- compare exist user age ---
    if username:
        passw_max_days_exist_username = get_passw_expire_time_existing_user(duthost, username)

        pytest_assert(passw_max_days_exist_username == passw_hardening_ob.policies['expiration'],
                      "Fail: expected max days exp='{}' ! current max days exp='{}'".format(
                          passw_hardening_ob.policies['expiration'], passw_max_days_exist_username))


def review_one_policy_with_user(duthost, passw_hardening_ob, passw_test, passw_bad_test, passw_exp_error,
                                pam_file_expected=passw_hardening_utils.PAM_PASSWORD_CONF_EXPECTED):
    """
    Funtion desc:
    1. config one policy, check show CLI, test policy configured in switch
    2. test good flow - create new user with good passw
    3. test user created succefully.
    4. test bad flow - create new user with bad passw
    5. test user was not created succefully.
    """

    # 1. config one policy, check show CLI, test policy configured in switch
    passw_hardening_utils.config_and_review_policies(duthost, passw_hardening_ob, pam_file_expected)

    # 2. test good flow - create new user with good passw
    chpasswd_cmd = config_user_and_passw(duthost, passw_hardening_utils.USERNAME_ONE_POLICY, passw_test)

    # 3. test user created succefully.
    pytest_assert(chpasswd_cmd['rc'] == SUCCESS_CODE, "Fail creating user: username={} with strong password={}"
                  .format(passw_hardening_utils.USERNAME_ONE_POLICY, passw_test))

    # 4. test bad flow - create new user with bad passw
    if passw_bad_test:
        chpasswd_cmd = change_password(duthost, passw_bad_test, passw_hardening_utils.USERNAME_ONE_POLICY)

        # 5. test user was not change passw succefully.
        pytest_assert(passw_exp_error in chpasswd_cmd['stderr'],
                      "Fail: username='{}' with password='{}' was set, "
                      "even though, strong policy configured, passw_exp_error = '{}'"
                      .format(passw_hardening_utils.USERNAME_ONE_POLICY, passw_bad_test, passw_exp_error))


def verify_age_flow(duthost, passw_hardening_ob, expected_login_error):
    login_response = ''

    # config one policy, check show CLI, test policy configured in switch
    passw_hardening_utils.config_and_review_policies(duthost, passw_hardening_ob,
                                                     passw_hardening_utils.PAM_PASSWORD_CONF_LEN_MIN_ONLY_EXPECTED)

    # create user
    passw_test = 'a_n_y_1989_2022'
    chpasswd_cmd = config_user_and_passw(duthost, passw_hardening_utils.USERNAME_AGE, passw_test)

    pytest_assert(chpasswd_cmd['rc'] == SUCCESS_CODE,
                  "Fail creating user: username='{}' with strong password='{}'"
                  .format(passw_hardening_utils.USERNAME_AGE, passw_test))

    # (mimic passw is old by rest 100 days)
    modify_last_password_change_user(duthost, passw_hardening_utils.USERNAME_AGE)

    # verify Age configuration in Linux files
    compare_passw_age_in_pam_dir(duthost, passw_hardening_ob, passw_hardening_utils.USERNAME_AGE)

    # login expecting to require passw change
    user_age_cmd = 'echo {} | sudo -S su {}'.format(passw_test, passw_hardening_utils.USERNAME_AGE)
    login_cmd = duthost.shell(user_age_cmd, module_ignore_errors=True)

    # test login results
    if 'Warning' in expected_login_error:  # expiration warning time case, the cmd is not failing
        login_response = login_cmd['stdout']
    else:  # expiration time case the cmd is failing
        login_response = login_cmd['stderr']
    pytest_assert(expected_login_error in login_response,
                  "Fail: the username='{}' could login by error, expected_login_error={} , but got this msg={}".format(
                      passw_hardening_utils.USERNAME_AGE, expected_login_error, login_response))


def test_passw_hardening_en_dis_policies(duthosts, enum_rand_one_per_hwsku_hostname, clean_passw_policies,
                                         clean_passw_en_dis_policies):
    """
        Test password hardening policies default.
        Test passw policies configured in CLI (Verify output of `show passw-hardening policies`)
        Test passw policies configured in Linux system (PAM)
        Test passw 'enabled/disable' by disabled and enable the passw and creating users between with strong/weak passw
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # create user with weak passw when passw policies are disable.
    passw_hardening_ob_pre = passw_hardening_utils.PasswHardening(state='disabled')

    # config one policy, check show CLI, test policy configured in switch
    passw_hardening_utils.config_and_review_policies(duthost, passw_hardening_ob_pre,
                                                     passw_hardening_utils.PAM_PASSWORD_CONF_DEFAULT_EXPECTED)

    simple_passw_0 = '12345678'
    chpasswd_cmd = config_user_and_passw(duthost, passw_hardening_utils.USERNAME_SIMPLE_0, simple_passw_0)

    pytest_assert(chpasswd_cmd['rc'] == SUCCESS_CODE,
                  "Fail: expected: username={} to be added with weak passw={}, because passw hardening disabled"
                  .format(passw_hardening_utils.USERNAME_SIMPLE_0, simple_passw_0))

    passw_hardening_ob = passw_hardening_utils.PasswHardening(state='enabled')

    # config one policy, check show CLI, test policy configured in switch
    passw_hardening_utils.config_and_review_policies(duthost, passw_hardening_ob,
                                                     passw_hardening_utils.PAM_PASSWORD_CONF_EXPECTED)

    # ~~ test user with weak passw (only digits) expecting to fail (bad flow) ~~
    simple_passw_1 = '12345678'
    chpasswd_cmd = config_user_and_passw(duthost, passw_hardening_utils.USERNAME_SIMPLE_1, simple_passw_1)

    pytest_assert("BAD PASSWORD: it is too simplistic/systematic" in chpasswd_cmd['stderr'],
                  "Fail: username='{}' with simple password='{}' was set, even though, strong policy configured"
                  .format(passw_hardening_utils.USERNAME_SIMPLE_1, simple_passw_1))

    # ~~ test user with strong password (digits, lower class, upper class, special class) ~~
    strong_passw = 'Nvi_d_ia_2020'
    strong_chpasswd_cmd = config_user_and_passw(duthost, passw_hardening_utils.USERNAME_STRONG, strong_passw)

    pytest_assert(strong_chpasswd_cmd['rc'] == SUCCESS_CODE,
                  "Fail creating user: username='{}' with strong password='{}'"
                  .format(passw_hardening_utils.USERNAME_STRONG, strong_passw))

    # clean new users
    userdel_cmd = passw_hardening_utils.config_user(duthost=duthost,
                                                    username=passw_hardening_utils.USERNAME_SIMPLE_1, mode='del')

    pytest_assert(userdel_cmd['rc'] == SUCCESS_CODE,
                  "Fail: users: '{}'  was not deleted correctly".format(userdel_cmd['stderr']))

    # disable feature
    passw_hardening_dis_ob = passw_hardening_utils.PasswHardening(state='disabled')
    passw_hardening_utils.config_and_review_policies(duthost, passw_hardening_dis_ob,
                                                     passw_hardening_utils.PAM_PASSWORD_CONF_DEFAULT_EXPECTED)

    # ~~ test feature disabled: by trying to create a new user with a weak passw
    # after feature disabled expecting to success.
    chpasswd_cmd = config_user_and_passw(duthost, passw_hardening_utils.USERNAME_SIMPLE_1, simple_passw_1)

    pytest_assert(chpasswd_cmd['rc'] == SUCCESS_CODE,
                  "Fail: expected: username={} to be added with weak passw={}, because passw hardening disabled"
                  .format(passw_hardening_utils.USERNAME_SIMPLE_1, simple_passw_1))


def test_passw_hardening_history(duthosts, enum_rand_one_per_hwsku_hostname, clean_passw_policies, clean_passw_history):
    """ Test password hardening history, flow:
        1. set new policies for history passw support
        2. create user
        3. set passw
        4. set other passw
        5. try to set the first passw
        6. expected "fail" because the firsts passw was already used.
     """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    expiration = check_expiration_value(duthost, 10)

    # 1. set new policies for history passw support
    passw_hardening_ob = passw_hardening_utils.PasswHardening(state='enabled',
                                                              expiration=expiration,
                                                              expiration_warning='10',
                                                              history='10',
                                                              len_min='8',
                                                              reject_user_passw_match='false',
                                                              lower_class='false',
                                                              upper_class='false',
                                                              digit_class="true",
                                                              special_class='false')

    passw_hardening_utils.config_and_review_policies(
        duthost, passw_hardening_ob, pam_file_expected=passw_hardening_utils.PAM_PASSWORD_CONF_HISTORY_ONLY_EXPECTED)

    # 2. create user + 3. set passw
    first_passw = 'Nvidia_2020'
    strong_chpasswd_cmd = config_user_and_passw(duthost, passw_hardening_utils.USERNAME_HISTORY, first_passw)

    pytest_assert(strong_chpasswd_cmd['rc'] == SUCCESS_CODE,
                  "Fail creating user: username='{}' with strong password='{}'"
                  .format(passw_hardening_utils.USERNAME_HISTORY, first_passw))

    # 4. set other passw
    second_passw = 'So_nic_p1'
    chpasswd_cmd = change_password(duthost, second_passw, passw_hardening_utils.USERNAME_HISTORY)

    pytest_assert(chpasswd_cmd['rc'] == SUCCESS_CODE,
                  "Fail changing passw with: username='{}' with strong password='{}'"
                  .format(passw_hardening_utils.USERNAME_HISTORY, second_passw))

    # 5. try to set the first passw
    chpasswd_cmd = change_password(duthost, first_passw, passw_hardening_utils.USERNAME_HISTORY)

    # 6. expected "fail" because the firsts passw was already used.
    pytest_assert(
        'Password has been already used. Choose another.' in chpasswd_cmd['stderr'],
        "Fail : username='{}' with strong password='{}' was set with an old passw, even though, history was configured"
        .format(passw_hardening_utils.USERNAME_HISTORY, first_passw))


def test_passw_hardening_age_expiration(duthosts, enum_rand_one_per_hwsku_hostname, clean_passw_policies,
                                        clean_passw_age):
    """
        Test password hardening age expiration, by change the last passw change of the user to a date old by 100 days
        then the test will try to login and its expected a failure beacause the passw is expered,
        other the test will fail.
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    expiration = check_expiration_value(duthost, 30)

    # set new passw hardening policies values
    passw_hardening_ob = passw_hardening_utils.PasswHardening(state='enabled',
                                                              expiration=expiration,
                                                              expiration_warning='15',
                                                              history='10',
                                                              len_min='8',
                                                              reject_user_passw_match='false',
                                                              lower_class='false',
                                                              upper_class='false',
                                                              digit_class="true",
                                                              special_class='false')

    expected_login_error = 'You are required to change your password immediately (password expired).'
    verify_age_flow(duthost, passw_hardening_ob, expected_login_error)


def test_passw_hardening_age_expiration_warning(duthosts, enum_rand_one_per_hwsku_hostname, clean_passw_policies,
                                                clean_passw_age):
    """
        Test password hardening age expiration, by change the last passw change of the user to a date old by 100 days
        then the test will try to login and its expected a failure beacause the passw is expered,
        other the test will fail.
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    expiration = check_expiration_value(duthost, 120)

    # set new passw hardening policies values
    passw_hardening_ob = passw_hardening_utils.PasswHardening(state='enabled',
                                                              expiration=expiration,
                                                              expiration_warning='30',
                                                              history='10',
                                                              len_min='8',
                                                              reject_user_passw_match='false',
                                                              lower_class='false',
                                                              upper_class='false',
                                                              digit_class="true",
                                                              special_class='false')

    # warning msg is expected because in the flow the function modify_last_password_change_user
    # mimic that the passw should be change in 20 days time and the warning is higher than that.
    expected_login_error = 'Warning: your password will expire'
    verify_age_flow(duthost, passw_hardening_ob, expected_login_error)


def test_passw_hardening_len_min(duthosts, enum_rand_one_per_hwsku_hostname,
                                 clean_passw_policies, clean_passw_len_min):
    """ Test password hardening len min
        1. good flow: set min len and password according
        2. bad flow: set longer len min, and set small passw"""

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    expiration = check_expiration_value(duthost, 10)

    # set new passw hardening policies values
    passw_hardening_ob = passw_hardening_utils.PasswHardening(state='enabled',
                                                              expiration=expiration,
                                                              expiration_warning='10',
                                                              history='10',
                                                              len_min='8',
                                                              reject_user_passw_match='false',
                                                              lower_class='false',
                                                              upper_class='false',
                                                              digit_class="true",
                                                              special_class='false')

    # config one policy, check show CLI, test policy configured in switch
    passw_hardening_utils.config_and_review_policies(duthost, passw_hardening_ob,
                                                     passw_hardening_utils.PAM_PASSWORD_CONF_LEN_MIN_ONLY_EXPECTED)

    passw_test = '19892022'
    chpasswd_cmd = config_user_and_passw(duthost, passw_hardening_utils.USERNAME_LEN_MIN, passw_test)

    pytest_assert(chpasswd_cmd['rc'] == SUCCESS_CODE, "Fail creating user: username='{}' with strong password='{}'"
                  .format(passw_hardening_utils.USERNAME_LEN_MIN, passw_test))

    # --- Bad Flow ---
    # set new passw hardening policies values
    passw_hardening_ob_len_min_big = passw_hardening_utils.PasswHardening(state='enabled',
                                                                          expiration=expiration,
                                                                          expiration_warning='10',
                                                                          history='10',
                                                                          len_min='10',
                                                                          reject_user_passw_match='false',
                                                                          lower_class='false',
                                                                          upper_class='false',
                                                                          digit_class="true",
                                                                          special_class='false')

    passw_hardening_utils.configure_passw_policies(duthost, passw_hardening_ob_len_min_big)

    # test user with len min small than config
    passw_bad_test = 'asDD@@12'

    # test settig smaller passw than config
    chpasswd_cmd = change_password(duthost, passw_bad_test, passw_hardening_utils.USERNAME_LEN_MIN)

    pytest_assert('BAD PASSWORD: is too simple' in chpasswd_cmd['stderr'],
                  "Fail : password='{}' was set with an small len than the policy, even though, it was configured"
                  .format(passw_bad_test))


def test_passw_hardening_policies_digits(duthosts, enum_rand_one_per_hwsku_hostname, clean_passw_policies,
                                         clean_passw_one_policy_user):
    """
        Test password hardening digits class
        Good flow - set passw according the policy
        Bad flow - set passw not according the policy and expecting to get an error
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    expiration = check_expiration_value(duthost, 100)
    passw_test = '19892022'
    passw_bad_test = 'b_a_d_passw_no_digs'
    passw_exp_error = 'BAD PASSWORD: is too simple'

    # set new passw hardening policies values
    passw_hardening_ob = passw_hardening_utils.PasswHardening(state='enabled',
                                                              expiration=expiration,
                                                              expiration_warning='15',
                                                              history='12',
                                                              len_min='1',
                                                              reject_user_passw_match='false',
                                                              lower_class='false',
                                                              upper_class='false',
                                                              digit_class="true",
                                                              special_class='false')

    review_one_policy_with_user(duthost, passw_hardening_ob, passw_test, passw_bad_test, passw_exp_error,
                                passw_hardening_utils.PAM_PASSWORD_CONF_DIGITS_ONLY_EXPECTED)


def test_passw_hardening_policies_lower_class(duthosts, enum_rand_one_per_hwsku_hostname, clean_passw_policies,
                                              clean_passw_one_policy_user):
    """
        Test password hardening lower class
        Good flow - set passw according the policy
        Bad flow - set passw not according the policy and expecting to get an error
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    expiration = check_expiration_value(duthost, 10)
    passw_test = 'n_v_d_i_a'
    passw_bad_test = 'BADFLOWNOLOWERLETTERS'
    passw_exp_error = 'BAD PASSWORD: is too simple'

    # set new passw hardening policies values
    passw_hardening_ob = passw_hardening_utils.PasswHardening(state='enabled',
                                                              expiration=expiration,
                                                              expiration_warning='10',
                                                              history='10',
                                                              len_min='1',
                                                              reject_user_passw_match='false',
                                                              lower_class='true',
                                                              upper_class='false',
                                                              digit_class="false",
                                                              special_class='false')

    review_one_policy_with_user(duthost, passw_hardening_ob, passw_test, passw_bad_test, passw_exp_error,
                                passw_hardening_utils.PAM_PASSWORD_CONF_LOWER_LETTER_ONLY_EXPECTED)


def test_passw_hardening_policies_upper_class(duthosts, enum_rand_one_per_hwsku_hostname, clean_passw_policies,
                                              clean_passw_one_policy_user):
    """
        Test password hardening upper class
        Good flow - set passw according the policy
        Bad flow - set passw not according the policy and expecting to get an error
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    expiration = check_expiration_value(duthost, 10)
    passw_test = 'NVI_DI_A_UP#'
    passw_bad_test = 'l_o_w_l_#_e#t1'
    passw_exp_error = 'BAD PASSWORD: is too simple'

    # set new passw hardening policies values
    passw_hardening_ob = passw_hardening_utils.PasswHardening(state='enabled',
                                                              expiration=expiration,
                                                              expiration_warning='10',
                                                              history='10',
                                                              len_min='1',
                                                              reject_user_passw_match='false',
                                                              lower_class='false',
                                                              upper_class='true',
                                                              digit_class="false",
                                                              special_class='false')

    review_one_policy_with_user(duthost, passw_hardening_ob, passw_test, passw_bad_test, passw_exp_error,
                                passw_hardening_utils.PAM_PASSWORD_CONF_UPPER_LETTER_ONLY_EXPECTED)


def test_passw_hardening_policies_special_class(duthosts, enum_rand_one_per_hwsku_hostname, clean_passw_policies,
                                                clean_passw_one_policy_user):
    """
        Test password hardening special class
        Good flow - set passw according the policy
        Bad flow - set passw not according the policy and expecting to get an error
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    expiration = check_expiration_value(duthost, 10)
    passw_test = 'nvipashar_'
    passw_bad_test = 'no11spec'
    passw_exp_error = 'BAD PASSWORD: is too simple'

    # set new passw hardening policies values
    passw_hardening_ob = passw_hardening_utils.PasswHardening(state='enabled',
                                                              expiration=expiration,
                                                              expiration_warning='10',
                                                              history='10',
                                                              len_min='1',
                                                              reject_user_passw_match='false',
                                                              lower_class='false',
                                                              upper_class='false',
                                                              digit_class="false",
                                                              special_class='true')

    review_one_policy_with_user(duthost, passw_hardening_ob, passw_test, passw_bad_test, passw_exp_error,
                                passw_hardening_utils.PAM_PASSWORD_CONF_SPECIAL_LETTER_ONLY_EXPECTED)


def test_passw_hardening_policy_reject_user_passw_match(duthosts, enum_rand_one_per_hwsku_hostname,
                                                        clean_passw_policies, clean_passw_one_policy_user):
    """
        Test password hardening reject user passw match
        Bad flow - set passw not according the policy and expecting to get an error
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    expiration = check_expiration_value(duthost, 10)
    passw_test = '19892022'
    passw_bad_test = passw_hardening_utils.USERNAME_ONE_POLICY
    passw_exp_error = 'BAD PASSWORD: contains the user name in some form'

    # set new passw hardening policies values
    passw_hardening_ob = passw_hardening_utils.PasswHardening(state='enabled',
                                                              expiration=expiration,
                                                              expiration_warning='10',
                                                              history='10',
                                                              len_min='1',
                                                              reject_user_passw_match='true',
                                                              lower_class='false',
                                                              upper_class='false',
                                                              digit_class="false",
                                                              special_class='false')

    review_one_policy_with_user(duthost, passw_hardening_ob, passw_test, passw_bad_test, passw_exp_error,
                                passw_hardening_utils.PAM_PASSWORD_CONF_REJECT_USER_PASSW_MATCH_EXPECTED)
