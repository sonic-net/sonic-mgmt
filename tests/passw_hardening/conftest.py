import pytest
import test_passw_hardening

def set_default_passw_hardening_policies(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    passw_hardening_ob_dis = test_passw_hardening.PasswHardening(state='disabled',
                                            expiration='100',
                                            expiration_warning='15',
                                            history='12',
                                            len_min='8',
                                            reject_user_passw_match='true',
                                            lower_class='true',
                                            upper_class='true',
                                            digit_class="true",
                                            special_class='true')

    test_passw_hardening.config_and_review_policies(duthost, passw_hardening_ob_dis, test_passw_hardening.PAM_PASSWORD_CONF_DEFAULT_EXPECTED)


@pytest.fixture(scope="module", autouse=True)
def passw_policies_init(duthosts, enum_rand_one_per_hwsku_hostname):
    set_default_passw_hardening_policies(duthosts, enum_rand_one_per_hwsku_hostname)

@pytest.fixture(scope="function")
def clean_passw_policies(duthosts, enum_rand_one_per_hwsku_hostname):
    yield
    set_default_passw_hardening_policies(duthosts, enum_rand_one_per_hwsku_hostname)

@pytest.fixture(scope="function")
def clean_passw_one_policy_user(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    res_adduser_simple_0 = test_passw_hardening.config_user(duthost=duthost, username=test_passw_hardening.USERNAME_ONE_POLICY, mode='del')    
    res_chpasswd = duthost.shell('sed -i /^'+test_passw_hardening.USERNAME_ONE_POLICY+':/d /etc/security/opasswd')
    yield
    # duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    res_adduser_simple_0 = test_passw_hardening.config_user(duthost=duthost, username=test_passw_hardening.USERNAME_ONE_POLICY, mode='del')    
    res_chpasswd = duthost.shell('sed -i /^'+test_passw_hardening.USERNAME_ONE_POLICY+':/d /etc/security/opasswd')


@pytest.fixture(scope="function")
def clean_passw_len_min(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    res_adduser_simple_0 = test_passw_hardening.config_user(duthost=duthost, username=test_passw_hardening.USERNAME_LEN_MIN, mode='del')
    yield
    # duthost = duthosts[enum_rand_one_per_hwsku_hostname] # TODO: maybe can rm this line
    res_adduser_simple_0 = test_passw_hardening.config_user(duthost=duthost, username=test_passw_hardening.USERNAME_LEN_MIN, mode='del')

@pytest.fixture(scope="function")
def clean_passw_age(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    res_user_clean = test_passw_hardening.config_user(duthost=duthost, username=test_passw_hardening.USERNAME_AGE, mode='del')
    yield
    # duthost = duthosts[enum_rand_one_per_hwsku_hostname] # TODO: maybe can rm this line
    res_user_clean = test_passw_hardening.config_user(duthost=duthost, username=test_passw_hardening.USERNAME_AGE, mode='del')

@pytest.fixture(scope="function")
def clean_passw_en_dis_policies(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    # mv this init to module instead function.(save just the cleaning)
    res_adduser_simple_1 = test_passw_hardening.config_user(duthost=duthost, username=test_passw_hardening.USERNAME_SIMPLE_0, mode='del')
    res_adduser_simple_0 = test_passw_hardening.config_user(duthost=duthost, username=test_passw_hardening.USERNAME_SIMPLE_1, mode='del')
    res_adduser_strong = test_passw_hardening.config_user(duthost=duthost, username=test_passw_hardening.USERNAME_STRONG, mode='del')
    res_chpasswd = duthost.shell('sed -i /^'+test_passw_hardening.USERNAME_SIMPLE_0+':/d /etc/security/opasswd')
    res_chpasswd = duthost.shell('sed -i /^'+test_passw_hardening.USERNAME_SIMPLE_1+':/d /etc/security/opasswd')
    res_chpasswd = duthost.shell('sed -i /^'+test_passw_hardening.USERNAME_STRONG+':/d /etc/security/opasswd')

    yield
    # duthost = duthosts[enum_rand_one_per_hwsku_hostname] # TODO: maybe can rm this line
    res_adduser_simple_1 = test_passw_hardening.config_user(duthost=duthost, username=test_passw_hardening.USERNAME_SIMPLE_0, mode='del')
    res_adduser_simple_0 = test_passw_hardening.config_user(duthost=duthost, username=test_passw_hardening.USERNAME_SIMPLE_1, mode='del')
    res_adduser_strong = test_passw_hardening.config_user(duthost=duthost, username=test_passw_hardening.USERNAME_STRONG, mode='del')
    res_chpasswd = duthost.shell('sed -i /^'+test_passw_hardening.USERNAME_SIMPLE_0+':/d /etc/security/opasswd')
    res_chpasswd = duthost.shell('sed -i /^'+test_passw_hardening.USERNAME_SIMPLE_1+':/d /etc/security/opasswd')
    res_chpasswd = duthost.shell('sed -i /^'+test_passw_hardening.USERNAME_STRONG+':/d /etc/security/opasswd')

@pytest.fixture(scope="function")
def clean_passw_history(duthosts, enum_rand_one_per_hwsku_hostname):
    # TODO: first check that user exist
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    res_adduser_simple_1 = test_passw_hardening.config_user(duthost=duthost, username=test_passw_hardening.USERNAME_HISTORY, mode='del')
    res_chpasswd = duthost.shell('sed -i /^'+test_passw_hardening.USERNAME_HISTORY+':/d /etc/security/opasswd')
    yield
    # duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    res_adduser_simple_1 = test_passw_hardening.config_user(duthost=duthost, username=test_passw_hardening.USERNAME_HISTORY, mode='del')
    res_chpasswd = duthost.shell('sed -i /^'+test_passw_hardening.USERNAME_HISTORY+':/d /etc/security/opasswd')
