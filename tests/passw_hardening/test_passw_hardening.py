"""
Tests Password Hardening Feature in SONiC:
-test different policies configuration.
-test 'show password policies' command.
-test end to end by adding new user and test password according new passw policies.
"""



import json
import logging
import re

import pytest

from pkg_resources import parse_version
from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.daemon_utils import check_pmon_daemon_status
from tests.common.platform.device_utils import get_dut_psu_line_pattern
from tests.common.utilities import get_inventory_files, get_host_visible_vars
from tests.common.utilities import skip_release_for_platform
import subprocess
import os
import sys
import filecmp
import datetime
import difflib

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

class PasswHardening:
    def __init__(self, state, expiration, expiration_warning, history, len_min,
                 reject_user_passw_match, lower_class, upper_class,
                 digit_class, special_class):

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

@pytest.fixture(scope='module')
def dut_vars(duthosts, enum_rand_one_per_hwsku_hostname, request):
    inv_files = get_inventory_files(request)
    dut_vars = get_host_visible_vars(inv_files, enum_rand_one_per_hwsku_hostname)
    yield dut_vars

def run_diff(file1, file2):
    try:
        diff_out = subprocess.check_output('diff -ur {} {} || true'.format(file1, file2), shell=True)
        return diff_out
    except subprocess.CalledProcessError as err:
        syslog.syslog(syslog.LOG_ERR, "{} - failed: return code - {}, output:\n{}".format(err.cmd, err.returncode, err.output))
        return -1

def run_remote_command(duthost, command):
    '''Running cmd from remote (switch).
    If the command fail, the test module will not crash, the function will return false, other true'''
    cmd = None
    try:
        logging.debug('DUT command = {}'.format(command))
        cmd = duthost.shell(command)
        logging.debug('command output lines = {}'.format(cmd["stdout_lines"]))
        return True, cmd["stdout_lines"]
    except Exception as e:
        logging.error('command={} fail, error={}'.format(command, e))
        return False, e.results['stderr_lines']

def config_user(duthost, username, password=None, mode='add'):
    username = username.strip()
    cmd_res = False, False
    if mode == 'add':
        command = "useradd {}".format(username)
        res_add_user = run_remote_command(duthost, command)
        # TODO: add some condition about user succcess
        cmd_res = change_username_password(duthost, password, username)
    elif mode == 'del':
        command = "userdel {}".format(username)
        cmd_res = run_remote_command(duthost, command)
    return cmd_res

def change_username_password(duthost, password, username):
    passwd_cmd = "echo -e \'"+password+"\' | passwd "+username
    cmd_res = run_remote_command(duthost, passwd_cmd)
    return cmd_res

def get_user_expire_time_global(duthost, age_type):
    """ Function verify that the current age expiry policy values are equal from the old one
        Return update_age_status 'True' value meaning that was a modification from the last time, and vice versa.
    """
    days_num = -1
    regex_days = AGE_DICT[age_type]['REGEX_DAYS']
    days_type = AGE_DICT[age_type]['DAYS']

    # get login.def from remote switch
    command = regex_days+ ' /etc/login.defs'
    try:
        grep_max_days = duthost.command(command)
        grep_max_days_out = grep_max_days["stdout_lines"]

        # get max days value
        days_num = grep_max_days["stdout_lines"][0].split()[1]
        logging.debug('command output lines = {}'.format(grep_max_days["stdout_lines"]))
    except Exception as e:
        logging.error('command={} fail, error={}'.format(command, e))
        return days_num

    return days_num

def modify_last_password_change_user(duthost, normal_account):

    days_to_subtract = 100
    old_date = datetime.date.today() - datetime.timedelta(days=days_to_subtract)
    try:
        command = 'chage '+ normal_account + ' -i --lastday ' + str(old_date.isoformat())
        chage = duthost.command(command)
        chage_data = chage["stdout_lines"]

    except Exception as ex:
        logging.error('useradd fail, error={}'.format(ex))
        return False

    return True

def get_passw_expire_time_existing_user(duthost, normal_account):
    last_passw_change = ''
    REGEX_MAX_PASSW_CHANGE = r'^Maximum number of days between password change[ \t]*:[ \t]*(?P<max_passw_change>.*)'

    try:

        command = 'chage -l '+ normal_account
        chage = duthost.command(command)
        chage_data = chage["stdout_lines"]

        for line in chage_data:
            m1 = re.match(REGEX_MAX_PASSW_CHANGE, line.decode('utf-8'))
            if m1:
                last_passw_change = m1.group("max_passw_change").decode('utf-8')
                break

    except Exception as ex:
        logging.error('useradd fail, error={}'.format(ex))

    return last_passw_change

def configure_passw_policies(duthost, passw_hardening_ob):
    # config password hardening policies
    for key, value in passw_hardening_ob.policies.items():
        logging.info("configuration to be set: key={}, value={}".format(key, value))
        cmd_config = 'sudo config passw-hardening policies ' + key + ' ' + value
        try:
            passw_policies_config_res = duthost.command(cmd_config)

        except Exception as e:
            logging.error("fail when setting cmd: {}".format(cmd_config))
            logging.error(e)
            return False
    return True

def show_pass_policies(duthost):
    # show password hardening policies
    passw_policies_show_dict = {}
    try:
        cmd_show = 'show passw-hardening policies'
        passw_policies_show_res = duthost.command(cmd_show)
        passw_policies_show_out = passw_policies_show_res["stdout_lines"]
        passw_policies_show_out[0] = passw_policies_show_out[0].encode().lower()
        passw_policies_keys = re.split(r'\s{2,}', passw_policies_show_out[0])
        passw_policies_keys = [key.replace(' ','-') for key in passw_policies_keys]
        passw_policies_values = passw_policies_show_out[2].encode().split()
        passw_policies_show_dict = {passw_policies_keys[i]: passw_policies_values[i] for i in range(len(passw_policies_keys))}
        logging.debug("show password policies output: {}".format(passw_policies_show_out))

    except Exception as e:
        logging.error("fail when setting cmd: {}".format(cmd_show))
        logging.error(e)
        return -1
    return passw_policies_show_dict

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
    command_password_stdout = ''
    # need to compare DUT common-password with the expected one.

    read_command_password = 'cat ' + PAM_PASSWORD_CONF
    try:
        logging.debug('DUT command = {}'.format(read_command_password))
        cmd_command_password = duthost.command(read_command_password)
        command_password_stdout = cmd_command_password["stdout_lines"]
        command_password_stdout = [line.encode('utf-8') for line in command_password_stdout]
    except Exception as e:
        logging.error('command={} fail, error={}'.format(read_command_password, e))

    if not os.path.isfile(pam_file_expected):
        raise ValueError('filename: %s not exits' % (pam_file_expected))
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
    # config policy
    configure_passw_policies(duthost, passw_hardening_ob)

    # show policy
    passw_policies_show_dict = show_pass_policies(duthost)

    # ~~ test passw policies in show CLI ~~
    cli_passw_policies_cmp = cmp(passw_hardening_ob.policies, passw_policies_show_dict)
    pytest_assert(cli_passw_policies_cmp == 0, "Fail: expected: passw polices='{}',not equal to current: passw polices='{}'"
                                                .format(passw_hardening_ob.policies, passw_policies_show_dict))

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
    USERNAME_ONE_POLICY = 'user_one_policy_test'
    res_adduser_simple = config_user(duthost, USERNAME_ONE_POLICY, passw_test, 'add')
    res_chpasswd = False, False

    if res_adduser_simple[0]==True or ('New password: Retype new password: Sorry, passwords do not match.' in res_adduser_simple[1]):
        passw_test_force = passw_test.split('\n')[0]
        res_chpasswd = run_remote_command(duthost, 'echo '+USERNAME_ONE_POLICY+':'+passw_test_force+' | chpasswd')
    
    # 3. test user created succefully.
    pytest_assert(res_adduser_simple[0] or res_chpasswd[0], "Fail creating user: username='{}' with strong password='{}'".format(USERNAME_ONE_POLICY, passw_test))

    # 4. test bad flow - create new user with bad passw
    if passw_bad_test:
        user_bad_flow = 'User_bad_flow'
        if passw_bad_test == 'reject_user_passw_match':
            passw_bad_test = USERNAME_ONE_POLICY

        res_chpasswd = run_remote_command(duthost, 'echo '+USERNAME_ONE_POLICY+':'+passw_bad_test+' | chpasswd')
        
        # 5. test user was not created succefully.
        pytest_assert(passw_exp_error in res_chpasswd[1],"Fail: username='{}' with password='{}' was set, even though, strong policy configured, passw_exp_error = '{}'".format(user_bad_flow, passw_bad_test, passw_exp_error))

        # clean new user (todo mv it to fixture)
        res_adduser_simple_0 = config_user(duthost=duthost, username=user_bad_flow, mode='del')
    
def verify_age_flow(duthost, passw_hardening_ob, expected_login_error):
    
    # config one policy, check show CLI, test policy configured in switch
    config_and_review_policies(duthost, passw_hardening_ob, PAM_PASSWORD_CONF_LEN_MIN_ONLY_EXPECTED)
    
    # create user
    passw_test = '20212022\n20212022'
    res_adduser_simple = config_user(duthost, USERNAME_AGE, passw_test, 'add')
    res_chpasswd = False, False
    if res_adduser_simple[0]==True or ('New password: Retype new password: Sorry, passwords do not match.' in res_adduser_simple[1]):
        res_chpasswd = run_remote_command(duthost, 'echo '+USERNAME_AGE+':'+passw_test+' | chpasswd')

    pytest_assert(res_adduser_simple[0] or res_chpasswd[0], "Fail creating user: username='{}' with strong password='{}'".format(USERNAME_AGE, passw_test))
    
    # (mimic passw is old by rest 100 days)
    last_passw_chg_date_user0 = modify_last_password_change_user(duthost, USERNAME_AGE)
    
    # verify Age configuration in Linux files
    compare_passw_age_in_pam_dir(duthost, passw_hardening_ob, USERNAME_AGE)

    # login expecting to require passw change
    res_login = run_remote_command(duthost, 'echo '+passw_test+' | sudo -S su '+USERNAME_AGE)
    res_login_enc = [i.encode() for i in res_login[1]]
    pytest_assert(expected_login_error in res_login_enc, "Fail: the username='{}' could login, even though, this msg was expected='{}'".format(USERNAME_AGE, expected_login_error, expected_login_error))


def test_passw_hardening_en_dis_policies(duthosts, enum_rand_one_per_hwsku_hostname, dut_vars, clean_passw_policies, clean_passw_en_dis_policies):
    """
        Test password hardening policies default.
        Test passw policies configured in CLI (Verify output of `show passw-hardening policies`)
        Test passw policies configured in Linux system (PAM)
        Test passw 'enabled/disable' by disabled and enable the passw and creating users between with strong/weak passw
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # ~~ test default values (when feature disabled) ~~
    # create user when passw policies are disable. 
    USERNAME_SIMPLE_0 = 'user_test0'
    simple_passw_0 = '12345678\n12345678'

    res_adduser0_simple = config_user(duthost, USERNAME_SIMPLE_0, simple_passw_0, 'add')
    res_chpasswd = False, False
    if res_adduser0_simple[0]==True or ('New password: Retype new password: Sorry, passwords do not match.' in res_adduser0_simple[1]):
        res_chpasswd = run_remote_command(duthost, 'echo '+USERNAME_SIMPLE_0+':'+simple_passw_0+' | chpasswd')

    pytest_assert(res_adduser0_simple[0] or res_chpasswd[0], "Fail: expected: username={} to be added with weak passw={}, because passw hardening disabled"
                                            .format(USERNAME_SIMPLE_0, simple_passw_0))

    # enable passw hardening policies
    passw_hardening_ob = PasswHardening(state='enabled',
                                        expiration='100',
                                        expiration_warning='15',
                                        history='12',
                                        len_min='8',
                                        reject_user_passw_match='true',
                                        lower_class='true',
                                        upper_class='true',
                                        digit_class="true",
                                        special_class='true')

    # config one policy, check show CLI, test policy configured in switch
    config_and_review_policies(duthost, passw_hardening_ob, PAM_PASSWORD_CONF_EXPECTED)

    # ---  creating users to test diffent passw policies ---

    # ~~ test user with weak passw (only digits) bad flow ~~
    simple_passw_1 = '12345678'
    res_adduser_simple = config_user(duthost, USERNAME_SIMPLE_1, simple_passw_1, 'add')
    pytest_assert("New password: BAD PASSWORD: it is too simplistic/systematic" in res_adduser_simple[1],"Fail: username='{}' with simple password='{}' was set, even though, strong policy configured".format(USERNAME_SIMPLE_1, simple_passw_1))

    # ~~ test user with strong password (digits, lower class, upper class, special class) ~~
    strong_passw = 'Nvi_d_ia_2020\nNvi_d_ia_2020'
    res_adduser_strong = config_user(duthost, USERNAME_STRONG, strong_passw, 'add')
    res_chpasswd = False, False
    if res_adduser_strong[0]==True or ('New password: Retype new password: Sorry, passwords do not match.' in res_adduser_strong[1]):
        res_chpasswd = run_remote_command(duthost, 'echo '+USERNAME_STRONG+':'+strong_passw.split('\n')[0]+' | chpasswd')
        
    pytest_assert(res_adduser_strong[0] or res_chpasswd[0], "Fail creating user: username='{}' with strong password='{}'".format(USERNAME_STRONG, strong_passw))

    # clean new users
    res_adduser_simple_1 = config_user(duthost=duthost, username=USERNAME_SIMPLE_1, mode='del')
    pytest_assert(res_adduser_simple_1, "Fail: users: '{}'  was not deleted correctly".format(res_adduser_simple_1))

    # disable feature
    passw_hardening_dis_ob = PasswHardening(state='disabled',
                                        expiration='100',
                                        expiration_warning='15',
                                        history='12',
                                        len_min='8',
                                        reject_user_passw_match='true',
                                        lower_class='true',
                                        upper_class='true',
                                        digit_class="true",
                                        special_class='true')

    configure_passw_policies(duthost, passw_hardening_dis_ob)

    # ~~ test password hardening feature when- state: disabled ~~
    # testing it by trying to set a weak passw after feature disabled
    res_adduser_simple = config_user(duthost, USERNAME_SIMPLE_1, simple_passw_1, 'add')
    res_chpasswd = False, False
    if res_adduser0_simple[0]==True or ('New password: Retype new password: Sorry, passwords do not match.' in res_adduser0_simple[1]):
        res_chpasswd = run_remote_command(duthost, 'echo '+USERNAME_SIMPLE_1+':'+simple_passw_1+' | chpasswd')

    pytest_assert(res_adduser0_simple[0] or res_chpasswd[0], "Fail: expected: username={} to be added with weak passw={}, because passw hardening disabled"
                                            .format(USERNAME_SIMPLE_1, simple_passw_1))


def test_passw_hardening_history(duthosts, enum_rand_one_per_hwsku_hostname, dut_vars, clean_passw_policies, clean_passw_history):
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

    # 2. create user
    strong_passw = 'Nvidia_2020\nNvidia_2020'
    res_adduser_strong = config_user(duthost, USERNAME_HISTORY, strong_passw, 'add')
    res_chpasswd = False, False
    if res_adduser_strong[0]==True or ('New password: Retype new password: Sorry, passwords do not match.' in res_adduser_strong[1]):
        # 3. set passw
        res_chpasswd = run_remote_command(duthost, 'echo '+USERNAME_HISTORY+':'+strong_passw.split('\n')[0]+' | chpasswd')

    pytest_assert(res_adduser_strong[0] or res_chpasswd[0], "Fail creating user: username='{}' with strong password='{}'".format(USERNAME_HISTORY, strong_passw))

    # 4. set other passw
    strong_passw_2 = 'So_nic_p1'
    res_chpasswd = run_remote_command(duthost, 'echo '+USERNAME_HISTORY+':'+strong_passw_2+' | chpasswd')
    pytest_assert(res_chpasswd[0], "Fail changing passw with: username='{}' with strong password='{}'".format(USERNAME_HISTORY, strong_passw_2))

    # 5. try to set the first passw
    res_chpasswd = run_remote_command(duthost, 'echo '+USERNAME_HISTORY+':'+strong_passw.split('\n')[0]+' | chpasswd')
    
    # 6. expected "fail" because the firsts passw was already used.
    pytest_assert('Password has been already used. Choose another.' in res_chpasswd[1], "Fail : username='{}' with strong password='{}' was set with an old passw, even though, history was configured".format(USERNAME_HISTORY, strong_passw))


def test_passw_hardening_age_expiration(duthosts, enum_rand_one_per_hwsku_hostname, dut_vars, clean_passw_policies, clean_passw_age):
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

    
def test_passw_hardening_age_expiration_warning(duthosts, enum_rand_one_per_hwsku_hostname, dut_vars, clean_passw_policies, clean_passw_age):
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

def test_passw_hardening_len_min(duthosts, enum_rand_one_per_hwsku_hostname, dut_vars, clean_passw_policies, clean_passw_len_min):
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
    
    passw_test = '19892022\n19892022'

    res_adduser_simple = config_user(duthost, USERNAME_LEN_MIN, passw_test, 'add')
    res_chpasswd = False, False
    if res_adduser_simple[0]==True or ('New password: Retype new password: Sorry, passwords do not match.' in res_adduser_simple[1]):
        passw_test_force = passw_test.split('\n')[0]
        res_chpasswd = run_remote_command(duthost, 'echo '+USERNAME_LEN_MIN+':'+passw_test_force+' | chpasswd')

    pytest_assert(res_adduser_simple[0] or res_chpasswd[0], "Fail creating user: username='{}' with strong password='{}'".format(USERNAME_LEN_MIN, passw_test))

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

    # config policy
    configure_passw_policies(duthost, passw_hardening_ob_len_min_big)

    # test user with len min small than config
    passw_bad_test = 'asDD@@12\nasDD@@12'

    # test settig smaller passw than config
    res_chg_passw1 = change_username_password(duthost, passw_bad_test, USERNAME_LEN_MIN)
    if res_chg_passw1[0]==True or ('New password: Retype new password: Sorry, passwords do not match.' in res_chg_passw1[1]):
        passw_test_force = passw_bad_test.split('\n')[0]
        res_chpasswd = run_remote_command(duthost, 'echo '+USERNAME_LEN_MIN+':'+passw_test_force+' | chpasswd')
        
    pytest_assert('BAD PASSWORD: is too simple' in res_chpasswd[1], "Fail : password='{}' was set with an small len than the policy, even though, it was configured".format(passw_bad_test))


def test_passw_hardening_policies_digits(duthosts, enum_rand_one_per_hwsku_hostname, dut_vars, clean_passw_policies, clean_passw_one_policy_user):
    """ Test password hardening digits class """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    passw_test = '19892022\n19892022'
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


def test_passw_hardening_policies_lower_class(duthosts, enum_rand_one_per_hwsku_hostname, dut_vars, clean_passw_policies, clean_passw_one_policy_user):
    """ Test password hardening digits class """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    passw_test = 'n_v_d_i_a\nn_v_d_i_a'
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

def test_passw_hardening_policies_upper_class(duthosts, enum_rand_one_per_hwsku_hostname, dut_vars, clean_passw_policies, clean_passw_one_policy_user):
    """ Test password hardening digits class """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    passw_test = 'NVI_DIA_NV\nNVI_DIA_NV'
    passw_bad_test = 'l_o_w_l_\nl_o_w_l_'
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

def test_passw_hardening_policies_special_class(duthosts, enum_rand_one_per_hwsku_hostname, dut_vars, clean_passw_policies, clean_passw_one_policy_user):
    """ Test password hardening digits class """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    passw_test = 'nvipashar_\nnvipashar_'
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

def test_passw_hardening_policy_reject_user_passw_match(duthosts, enum_rand_one_per_hwsku_hostname, dut_vars, clean_passw_policies, clean_passw_one_policy_user):
    """ Test password hardening digits class """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    passw_test = '19892022\n19892022'
    passw_bad_test = 'reject_user_passw_match'
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


