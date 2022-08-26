"""
Tests Password Hardening Feature:
- test all posibles policies configuration.
- test 'show password policies' command.
- test end to end by adding new user and set passwords according passw policies configured in the different tests.
"""


import logging
import re
import pytest
import os
import sys
import datetime
import difflib
from tests.common.helpers.assertions import pytest_assert


pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('any')
]

CURR_DIR = os.path.dirname(os.path.abspath(__file__))
CWD = os.path.abspath(os.getcwd())

ETC_LOGIN_DEF = "/etc/login.defs"
PAM_PASSWORD_CONF = "/etc/pam.d/common-password"

# Sample/Expected files
PAM_PASSWORD_CONF_DEFAULT_EXPECTED = CURR_DIR+'/sample/passw_hardening_default/common-password'
PAM_PASSWORD_CONF_EXPECTED = CURR_DIR+'/sample/passw_hardening_enable/common-password'
PAM_PASSWORD_CONF_HISTORY_ONLY_EXPECTED =  CURR_DIR+'/sample/passw_hardening_history/common-password' 
PAM_PASSWORD_CONF_REJECT_USER_PASSW_MATCH_EXPECTED = CURR_DIR+'/sample/passw_hardening_reject_user_passw_match/common-password'
PAM_PASSWORD_CONF_DIGITS_ONLY_EXPECTED = CURR_DIR+'/sample/passw_hardening_digits/common-password'
PAM_PASSWORD_CONF_LOWER_LETTER_ONLY_EXPECTED = CURR_DIR+'/sample/passw_hardening_lower_letter/common-password'
PAM_PASSWORD_CONF_UPPER_LETTER_ONLY_EXPECTED = CURR_DIR+'/sample/passw_hardening_upper_letter/common-password'
PAM_PASSWORD_CONF_SPECIAL_LETTER_ONLY_EXPECTED = CURR_DIR+'/sample/passw_hardening_special_letter/common-password'
PAM_PASSWORD_CONF_LEN_MIN_ONLY_EXPECTED = CURR_DIR+'/sample/passw_hardening_min_len/common-password'
PAM_PASSWORD_CONF_OUTPUT = CURR_DIR+'/output/login.def'

# Linux login.def default values (password hardening disable)
LINUX_DEFAULT_PASS_MAX_DAYS = 99999
LINUX_DEFAULT_PASS_WARN_AGE = 7


AGE_DICT = { 'MAX_DAYS': {'REGEX_DAYS': 'grep \'^PASS_MAX_DAYS[ \\t]*\'', 'DAYS': 'max_days', 'CHAGE_FLAG': '-M '},
            'WARN_DAYS': {'REGEX_DAYS': 'grep \'^PASS_WARN_AGE[ \\t]*\'', 'DAYS': 'warn_days', 'CHAGE_FLAG': '-W '}
            }

# users
USERNAME_STRONG = 'user_strong_test'
USERNAME_SIMPLE_0 = 'user_simple_0_test'
USERNAME_SIMPLE_1 = 'user_simple_1_test'
USERNAME_ONE_POLICY = 'user_one_policy_test'
USERNAME_AGE = 'user_test'
USERNAME_HISTORY = 'user_history_test'
USERNAME_LEN_MIN = 'user_test'

FAIL_CODE = -1 # custom error code
SUCCESS_CODE = 0
FIRST_LINE = 0

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

def config_user_and_passw(duthost, username, password):
    """ Config users and set password. """
    
    username = username.strip()
    config_user(duthost, username)
    chpasswd_cmd = change_password(duthost, password, username)
    return chpasswd_cmd

def change_password(duthost, password, username):
    chpasswd_cmd = duthost.shell('echo '+username+':'+password+' | chpasswd', module_ignore_errors=True) 
    return chpasswd_cmd

def get_user_expire_time_global(duthost, age_type):
    """ Function get the expire/expire warning days from linux filename login.def
        according the age_type.
    """

    DAY_INDEX = 1
    days_num = -1

    regex_days = AGE_DICT[age_type]['REGEX_DAYS']
    days_type = AGE_DICT[age_type]['DAYS']
    command = regex_days+ ' /etc/login.defs'

    grep_max_days_out = duthost.command(command)["stdout_lines"][FIRST_LINE].encode()
    
    days_num = grep_max_days_out.split()[DAY_INDEX]
    logging.debug('command output lines = {}'.format(grep_max_days_out))

    return days_num

def modify_last_password_change_user(duthost, normal_account):
    "Modify the passw change day of a user (subtract 100 days)."

    days_to_subtract = 100
    old_date = datetime.date.today() - datetime.timedelta(days=days_to_subtract)
    
    command = 'chage '+ normal_account + ' -i --lastday ' + str(old_date.isoformat())
    chage_cmd = duthost.command(command)
    return

def get_passw_expire_time_existing_user(duthost, normal_account):
    last_passw_change = ''
    REGEX_MAX_PASSW_CHANGE = r'^Maximum number of days between password change[ \t]*:[ \t]*(?P<max_passw_change>.*)'

    command = 'chage -l '+ normal_account
    chage_stdout = duthost.command(command)["stdout_lines"]

    for line in chage_stdout:
        m1 = re.match(REGEX_MAX_PASSW_CHANGE, line.decode('utf-8'))
        if m1:
            last_passw_change = m1.group("max_passw_change").decode('utf-8')
            break

    return last_passw_change

def configure_passw_policies(duthost, passw_hardening_ob):
    for key, value in passw_hardening_ob.policies.items():
        logging.debug("configuration to be set: key={}, value={}".format(key, value))
        cmd_config = 'sudo config passw-hardening policies ' + key + ' ' + value
        passw_policies_config_res = duthost.command(cmd_config)
    return True

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
                  "Fail: expected max days exp='{}' ! current max days exp='{}' was not set, even though, matching policy configured".format(
                      passw_hardening_ob.policies['expiration'], passw_max_days_global))

    pytest_assert(passw_hardening_ob.policies['expiration-warning'] == passw_warn_days_global,
                  "Fail: expected max days exp='{}' ! current max days exp='{}' was not set, even though, matching policy configured".format(
                      passw_hardening_ob.policies['expiration-warning'], passw_warn_days_global))

    # --- compare exist user age ---
    if username:
        passw_max_days_exist_username = get_passw_expire_time_existing_user(duthost, username)

        pytest_assert(passw_max_days_exist_username == passw_hardening_ob.policies['expiration'],
                    "Fail: expected max days exp='{}' ! current max days exp='{}'".format(
                        passw_hardening_ob.policies['expiration'], passw_max_days_exist_username))

def compare_passw_policies_in_linux(duthost, pam_file_expected=PAM_PASSWORD_CONF_EXPECTED):
    """Compare DUT common-password with the expected one."""

    command_password_stdout = ''
    read_command_password = 'cat ' + PAM_PASSWORD_CONF

    logging.debug('DUT command = {}'.format(read_command_password))
    read_command_password_cmd = duthost.command(read_command_password)
    command_password_stdout = read_command_password_cmd["stdout_lines"]
    command_password_stdout = [line.encode('utf-8') for line in command_password_stdout]

    common_password_expected = []
    with open(pam_file_expected, 'r') as expected_common_password_file:
        for line in expected_common_password_file:
            line = line.strip()
            line = line.strip('\n')
            line = line.strip('\t')
            common_password_expected.append(line)

    common_password_diff = [li for li in difflib.ndiff(command_password_stdout, common_password_expected) if li[0] != ' ']
    pytest_assert(len(common_password_diff) == 0, common_password_diff)

def config_and_review_policies(duthost, passw_hardening_ob, pam_file_expected):
    """
    1. Config passw hardening policies
    2. Show passw hardening policies
    3. Compare passw hardening polices from show cli to the expected (configured)
    4. Verify polices in PAM files was set according the configured
    """
    configure_passw_policies(duthost, passw_hardening_ob)
    
    curr_show_policies = duthost.show_and_parse('show passw-hardening policies')[FIRST_LINE]
    exp_show_policies = dict((k.replace('-', ' '), v) for k, v in passw_hardening_ob.policies.items())
    
    # ~~ test passw policies in show CLI ~~
    cli_passw_policies_cmp = cmp(exp_show_policies, curr_show_policies)
    pytest_assert(cli_passw_policies_cmp == 0, "Fail: exp_show_policies='{}',not equal to curr_show_policies='{}'"
                                                .format(exp_show_policies, curr_show_policies))

    # ~~ test passw policies in PAM files ~~
    compare_passw_policies_in_linux(duthost, pam_file_expected)


def review_one_policy_with_user(duthost, passw_hardening_ob, passw_test, passw_bad_test, passw_exp_error, pam_file_expected=PAM_PASSWORD_CONF_EXPECTED):
    """
    Funtion desc:
    1. config one policy, check show CLI, test policy configured in switch
    2. test good flow - create new user with good passw
    3. test user created succefully.
    4. test bad flow - create new user with bad passw
    5. test user was not created succefully.
    """

    # 1. config one policy, check show CLI, test policy configured in switch
    config_and_review_policies(duthost, passw_hardening_ob, pam_file_expected)
    
    # 2. test good flow - create new user with good passw
    chpasswd_cmd = config_user_and_passw(duthost, USERNAME_ONE_POLICY, passw_test)

    # 3. test user created succefully.
    pytest_assert(chpasswd_cmd['rc'] == SUCCESS_CODE , "Fail creating user: username={} with strong password={}"
                                                                            .format(USERNAME_ONE_POLICY, passw_test))

    # 4. test bad flow - create new user with bad passw
    if passw_bad_test:
        chpasswd_cmd = change_password(duthost, passw_bad_test, USERNAME_ONE_POLICY)

        # 5. test user was not change passw succefully.
        pytest_assert(passw_exp_error in chpasswd_cmd['stderr'],"Fail: username='{}' with password='{}' was set, even though,\
                    strong policy configured, passw_exp_error = '{}'".format(USERNAME_ONE_POLICY, passw_bad_test, passw_exp_error))
    
def verify_age_flow(duthost, passw_hardening_ob, expected_login_error):
    login_response = ''

    # config one policy, check show CLI, test policy configured in switch
    config_and_review_policies(duthost, passw_hardening_ob, PAM_PASSWORD_CONF_LEN_MIN_ONLY_EXPECTED)
    
    # create user
    passw_test = 'a_n_y_1989_2022'
    chpasswd_cmd = config_user_and_passw(duthost, USERNAME_AGE, passw_test)

    pytest_assert(chpasswd_cmd['rc'] == SUCCESS_CODE, "Fail creating user: username='{}' with strong password='{}'".format(USERNAME_AGE, passw_test))

    # (mimic passw is old by rest 100 days)
    modify_last_password_change_user(duthost, USERNAME_AGE)

    # verify Age configuration in Linux files
    compare_passw_age_in_pam_dir(duthost, passw_hardening_ob, USERNAME_AGE)

    # login expecting to require passw change
    login_cmd =  duthost.shell('echo '+passw_test+' | sudo -S su '+USERNAME_AGE, module_ignore_errors=True)

    # test login results
    if 'Warning' in expected_login_error: # expiration warning time case, the cmd is not failing
        login_response = login_cmd['stdout']
    else: # expiration time case the cmd is failing
        login_response = login_cmd['stderr']
    pytest_assert(expected_login_error in login_response, "Fail: the username='{}' could login by error, expected_login_error={} , but got this msg={}".format(USERNAME_AGE, expected_login_error, login_response))

def test_passw_hardening_en_dis_policies(duthosts, enum_rand_one_per_hwsku_hostname, clean_passw_policies, clean_passw_en_dis_policies):
    """
        Test password hardening policies default.
        Test passw policies configured in CLI (Verify output of `show passw-hardening policies`)
        Test passw policies configured in Linux system (PAM)
        Test passw 'enabled/disable' by disabled and enable the passw and creating users between with strong/weak passw
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # create user with weak passw when passw policies are disable (feature is disabled by default). 
    simple_passw_0 = '12345678'
    chpasswd_cmd = config_user_and_passw(duthost, USERNAME_SIMPLE_0, simple_passw_0)

    pytest_assert(chpasswd_cmd['rc']==SUCCESS_CODE, "Fail: expected: username={} to be added with weak passw={},\
                                            because passw hardening disabled".format(USERNAME_SIMPLE_0, simple_passw_0))

    passw_hardening_ob = PasswHardening(state='enabled')

    # config one policy, check show CLI, test policy configured in switch
    config_and_review_policies(duthost, passw_hardening_ob, PAM_PASSWORD_CONF_EXPECTED)

    # ~~ test user with weak passw (only digits) expecting to fail (bad flow) ~~
    simple_passw_1 = '12345678'
    chpasswd_cmd = config_user_and_passw(duthost, USERNAME_SIMPLE_1, simple_passw_1)

    pytest_assert("BAD PASSWORD: it is too simplistic/systematic" in chpasswd_cmd['stderr'],"Fail: username='{}'\
                         with simple password='{}' was set, even though, strong policy configured".format(USERNAME_SIMPLE_1, simple_passw_1))

    # ~~ test user with strong password (digits, lower class, upper class, special class) ~~
    strong_passw = 'Nvi_d_ia_2020'
    strong_chpasswd_cmd = config_user_and_passw(duthost, USERNAME_STRONG, strong_passw)

    pytest_assert(strong_chpasswd_cmd['rc']==SUCCESS_CODE, "Fail creating user: username='{}' with strong password='{}'".format(USERNAME_STRONG, strong_passw))

    # clean new users
    userdel_cmd = config_user(duthost=duthost, username=USERNAME_SIMPLE_1, mode='del')

    pytest_assert(userdel_cmd['rc']==SUCCESS_CODE, "Fail: users: '{}'  was not deleted correctly".format(userdel_cmd['stderr']))

    # disable feature 
    passw_hardening_dis_ob = PasswHardening(state='disabled')
    config_and_review_policies(duthost, passw_hardening_dis_ob, PAM_PASSWORD_CONF_DEFAULT_EXPECTED)

    # ~~ test feature disabled: by trying to create a new user with a weak passw after feature disabled expecting to success.
    chpasswd_cmd = config_user_and_passw(duthost, USERNAME_SIMPLE_1, simple_passw_1)

    pytest_assert(chpasswd_cmd['rc']==SUCCESS_CODE, "Fail: expected: username={} to be added with weak passw={}, \
                                            because passw hardening disabled".format(USERNAME_SIMPLE_1, simple_passw_1))


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

    # 1. set new policies for history passw support
    passw_hardening_ob = PasswHardening(state='enabled',
                                        expiration='0',
                                        expiration_warning='0',
                                        history='10',
                                        len_min='1',
                                        reject_user_passw_match='false',
                                        lower_class='false',
                                        upper_class='false',
                                        digit_class="true",
                                        special_class='false')
    
    config_and_review_policies(duthost, passw_hardening_ob, pam_file_expected=PAM_PASSWORD_CONF_HISTORY_ONLY_EXPECTED)

    # 2. create user + 3. set passw
    first_passw = 'Nvidia_2020'
    strong_chpasswd_cmd = config_user_and_passw(duthost, USERNAME_HISTORY, first_passw)

    pytest_assert(strong_chpasswd_cmd['rc']==SUCCESS_CODE, "Fail creating user: username='{}' with strong password='{}'".format(USERNAME_HISTORY, first_passw))

    # 4. set other passw
    second_passw = 'So_nic_p1'
    chpasswd_cmd = change_password(duthost, second_passw, USERNAME_HISTORY)

    pytest_assert(chpasswd_cmd['rc']==SUCCESS_CODE, "Fail changing passw with: username='{}' with strong password='{}'".format(USERNAME_HISTORY, second_passw))

    # 5. try to set the first passw
    chpasswd_cmd = change_password(duthost, first_passw, USERNAME_HISTORY)

    # 6. expected "fail" because the firsts passw was already used.
    pytest_assert('Password has been already used. Choose another.' in chpasswd_cmd['stderr'], "Fail : username='{}' with strong password='{}' was set with an old passw, even though, history was configured".format(USERNAME_HISTORY, first_passw))


def test_passw_hardening_age_expiration(duthosts, enum_rand_one_per_hwsku_hostname, clean_passw_policies, clean_passw_age):
    """ 
        Test password hardening age expiration, by change the last passw change of the user to a date old by 100 days
        then the test will try to login and its expected a failure beacause the passw is expered, other the test will fail.
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # set new passw hardening policies values
    passw_hardening_ob = PasswHardening(state='enabled',
                                        expiration='30',
                                        expiration_warning='15',
                                        history='1',
                                        len_min='8',
                                        reject_user_passw_match='false',
                                        lower_class='false',
                                        upper_class='false',
                                        digit_class="true",
                                        special_class='false')

    expected_login_error = 'You are required to change your password immediately (password expired).'
    verify_age_flow(duthost, passw_hardening_ob, expected_login_error)

    
def test_passw_hardening_age_expiration_warning(duthosts, enum_rand_one_per_hwsku_hostname, clean_passw_policies, clean_passw_age):
    """ 
        Test password hardening age expiration, by change the last passw change of the user to a date old by 100 days
        then the test will try to login and its expected a failure beacause the passw is expered, other the test will fail.
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # set new passw hardening policies values
    passw_hardening_ob = PasswHardening(state='enabled',
                                        expiration='140',
                                        expiration_warning='120',
                                        history='1',
                                        len_min='8',
                                        reject_user_passw_match='false',
                                        lower_class='false',
                                        upper_class='false',
                                        digit_class="true",
                                        special_class='false')
    
    
    # warning expected because the passw chage is 100 days old and the warning should be after 140-120=20 days
    expected_login_error = 'Warning: your password will expire in 40 days.'
    verify_age_flow(duthost, passw_hardening_ob, expected_login_error)

def test_passw_hardening_len_min(duthosts, enum_rand_one_per_hwsku_hostname, clean_passw_policies, clean_passw_len_min):
    """ Test password hardening len min
        1. good flow: set min len and password according
        2. bad flow: set longer len min, and set small passw"""

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # set new passw hardening policies values
    passw_hardening_ob = PasswHardening(state='enabled',
                                        expiration='0',
                                        expiration_warning='0',
                                        history='1',
                                        len_min='8',
                                        reject_user_passw_match='false',
                                        lower_class='false',
                                        upper_class='false',
                                        digit_class="true",
                                        special_class='false')
    
    # config one policy, check show CLI, test policy configured in switch
    config_and_review_policies(duthost, passw_hardening_ob, PAM_PASSWORD_CONF_LEN_MIN_ONLY_EXPECTED)
    
    passw_test = '19892022'
    chpasswd_cmd = config_user_and_passw(duthost, USERNAME_LEN_MIN, passw_test)
    
    pytest_assert(chpasswd_cmd['rc'] == SUCCESS_CODE, "Fail creating user: username='{}' with strong password='{}'"
                                                                                    .format(USERNAME_LEN_MIN, passw_test))

    # --- Bad Flow ---
    # set new passw hardening policies values
    passw_hardening_ob_len_min_big = PasswHardening(state='enabled',
                                        expiration='0',
                                        expiration_warning='0',
                                        history='1',
                                        len_min='10',
                                        reject_user_passw_match='false',
                                        lower_class='false',
                                        upper_class='false',
                                        digit_class="true",
                                        special_class='false')

    configure_passw_policies(duthost, passw_hardening_ob_len_min_big)

    # test user with len min small than config
    passw_bad_test = 'asDD@@12'

    # test settig smaller passw than config
    chpasswd_cmd = change_password(duthost, passw_bad_test, USERNAME_LEN_MIN)
 
    pytest_assert('BAD PASSWORD: is too simple' in chpasswd_cmd['stderr'], "Fail : password='{}' was set with an small len than the policy,\
                                                                                     even though, it was configured".format(passw_bad_test))


def test_passw_hardening_policies_digits(duthosts, enum_rand_one_per_hwsku_hostname, clean_passw_policies, clean_passw_one_policy_user):
    """ 
        Test password hardening digits class
        Good flow - set passw according the policy
        Bad flow - set passw not according the policy and expecting to get an error
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    passw_test = '19892022'
    passw_bad_test = 'b_a_d_passw_no_digs'
    passw_exp_error = 'BAD PASSWORD: is too simple'

    # set new passw hardening policies values
    passw_hardening_ob = PasswHardening(state='enabled',
                                        expiration='0',
                                        expiration_warning='0',
                                        history='0',
                                        len_min='1',
                                        reject_user_passw_match='false',
                                        lower_class='false',
                                        upper_class='false',
                                        digit_class="true",
                                        special_class='false')

    review_one_policy_with_user(duthost, passw_hardening_ob, passw_test, passw_bad_test, passw_exp_error, PAM_PASSWORD_CONF_DIGITS_ONLY_EXPECTED)


def test_passw_hardening_policies_lower_class(duthosts, enum_rand_one_per_hwsku_hostname, clean_passw_policies, clean_passw_one_policy_user):
    """ 
        Test password hardening lower class 
        Good flow - set passw according the policy
        Bad flow - set passw not according the policy and expecting to get an error
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    passw_test = 'n_v_d_i_a'
    passw_bad_test = 'BADFLOWNOLOWERLETTERS'
    passw_exp_error = 'BAD PASSWORD: is too simple'

    # set new passw hardening policies values
    passw_hardening_ob = PasswHardening(state='enabled',
                                        expiration='0',
                                        expiration_warning='0',
                                        history='0',
                                        len_min='1',
                                        reject_user_passw_match='false',
                                        lower_class='true',
                                        upper_class='false',
                                        digit_class="false",
                                        special_class='false')

    review_one_policy_with_user(duthost, passw_hardening_ob, passw_test, passw_bad_test, passw_exp_error, PAM_PASSWORD_CONF_LOWER_LETTER_ONLY_EXPECTED)

def test_passw_hardening_policies_upper_class(duthosts, enum_rand_one_per_hwsku_hostname, clean_passw_policies, clean_passw_one_policy_user):
    """ 
        Test password hardening upper class 
        Good flow - set passw according the policy
        Bad flow - set passw not according the policy and expecting to get an error
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    passw_test = 'NVI_DI_A_UP#'
    passw_bad_test = 'l_o_w_l_#_e#t1'
    passw_exp_error = 'BAD PASSWORD: is too simple'
    
    # set new passw hardening policies values
    passw_hardening_ob = PasswHardening(state='enabled',
                                        expiration='0',
                                        expiration_warning='0',
                                        history='0',
                                        len_min='1',
                                        reject_user_passw_match='false',
                                        lower_class='false',
                                        upper_class='true',
                                        digit_class="false",
                                        special_class='false')

    review_one_policy_with_user(duthost, passw_hardening_ob, passw_test, passw_bad_test, passw_exp_error, PAM_PASSWORD_CONF_UPPER_LETTER_ONLY_EXPECTED)

def test_passw_hardening_policies_special_class(duthosts, enum_rand_one_per_hwsku_hostname, clean_passw_policies, clean_passw_one_policy_user):
    """ 
        Test password hardening special class 
        Good flow - set passw according the policy
        Bad flow - set passw not according the policy and expecting to get an error
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    passw_test = 'nvipashar_'
    passw_bad_test = 'no11spec'
    passw_exp_error = 'BAD PASSWORD: is too simple'

    # set new passw hardening policies values
    passw_hardening_ob = PasswHardening(state='enabled',
                                        expiration='0',
                                        expiration_warning='0',
                                        history='0',
                                        len_min='1',
                                        reject_user_passw_match='false',
                                        lower_class='false',
                                        upper_class='false',
                                        digit_class="false",
                                        special_class='true')

    review_one_policy_with_user(duthost, passw_hardening_ob, passw_test, passw_bad_test, passw_exp_error, PAM_PASSWORD_CONF_SPECIAL_LETTER_ONLY_EXPECTED)

def test_passw_hardening_policy_reject_user_passw_match(duthosts, enum_rand_one_per_hwsku_hostname, clean_passw_policies, clean_passw_one_policy_user):
    """ 
        Test password hardening reject user passw match
        Bad flow - set passw not according the policy and expecting to get an error
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    passw_test = '19892022'
    passw_bad_test = USERNAME_ONE_POLICY
    passw_exp_error='BAD PASSWORD: contains the user name in some form'
    
    # set new passw hardening policies values
    passw_hardening_ob = PasswHardening(state='enabled',
                                        expiration='0',
                                        expiration_warning='0',
                                        history='0',
                                        len_min='1',
                                        reject_user_passw_match='true',
                                        lower_class='false',
                                        upper_class='false',
                                        digit_class="false",
                                        special_class='false')

    review_one_policy_with_user(duthost, passw_hardening_ob, passw_test, passw_bad_test, passw_exp_error, PAM_PASSWORD_CONF_REJECT_USER_PASSW_MATCH_EXPECTED)


