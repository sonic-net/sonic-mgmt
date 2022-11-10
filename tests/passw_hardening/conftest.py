import pytest
from tests.common.utilities import skip_release
import passw_hardening_utils

def set_default_passw_hardening_policies(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    passw_hardening_ob_dis = passw_hardening_utils.PasswHardening(state='disabled',
                                            expiration='100',
                                            expiration_warning='15',
                                            history='12',
                                            len_min='8',
                                            reject_user_passw_match='true',
                                            lower_class='true',
                                            upper_class='true',
                                            digit_class="true",
                                            special_class='true')

    passw_hardening_utils.config_and_review_policies(duthost, passw_hardening_ob_dis, passw_hardening_utils.PAM_PASSWORD_CONF_DEFAULT_EXPECTED)

@pytest.fixture(scope="module", autouse=True)
def passw_version_required(duthosts, enum_rand_one_per_hwsku_hostname):
    """Skips this test if the SONiC image installed on DUT is older than 202111

    Args:
        duthost: DUT host object.

    Returns:
        None.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    skip_release(duthost, ["201811", "201911", "202012", "202106", "202111"])


@pytest.fixture(scope="function")
def clean_passw_policies(duthosts, enum_rand_one_per_hwsku_hostname):
    yield
    set_default_passw_hardening_policies(duthosts, enum_rand_one_per_hwsku_hostname)

@pytest.fixture(scope="function")
def clean_passw_one_policy_user(duthosts, enum_rand_one_per_hwsku_hostname):
    yield
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    res_adduser_simple_0 = passw_hardening_utils.config_user(duthost=duthost, username=passw_hardening_utils.USERNAME_ONE_POLICY, mode='del')


@pytest.fixture(scope="function")
def clean_passw_len_min(duthosts, enum_rand_one_per_hwsku_hostname):
    yield
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    passw_hardening_utils.config_user(duthost=duthost, username=passw_hardening_utils.USERNAME_LEN_MIN, mode='del')
    duthost.shell('sed -i /^'+passw_hardening_utils.USERNAME_LEN_MIN+':/d /etc/security/opasswd')

@pytest.fixture(scope="function")
def clean_passw_age(duthosts, enum_rand_one_per_hwsku_hostname):
    yield
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    passw_hardening_utils.config_user(duthost=duthost, username=passw_hardening_utils.USERNAME_AGE, mode='del')
    duthost.shell('sed -i /^'+passw_hardening_utils.USERNAME_AGE+':/d /etc/security/opasswd')


@pytest.fixture(scope="function")
def clean_passw_en_dis_policies(duthosts, enum_rand_one_per_hwsku_hostname):
    yield
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    passw_hardening_utils.config_user(duthost=duthost, username=passw_hardening_utils.USERNAME_SIMPLE_0, mode='del')
    passw_hardening_utils.config_user(duthost=duthost, username=passw_hardening_utils.USERNAME_SIMPLE_1, mode='del')
    passw_hardening_utils.config_user(duthost=duthost, username=passw_hardening_utils.USERNAME_STRONG, mode='del')
    duthost.shell('sed -i /^'+passw_hardening_utils.USERNAME_SIMPLE_0+':/d /etc/security/opasswd')
    duthost.shell('sed -i /^'+passw_hardening_utils.USERNAME_SIMPLE_1+':/d /etc/security/opasswd')
    duthost.shell('sed -i /^'+passw_hardening_utils.USERNAME_STRONG+':/d /etc/security/opasswd')

@pytest.fixture(scope="function")
def clean_passw_history(duthosts, enum_rand_one_per_hwsku_hostname):
    yield
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    passw_hardening_utils.config_user(duthost=duthost, username=passw_hardening_utils.USERNAME_HISTORY, mode='del')
    duthost.shell('sed -i /^'+passw_hardening_utils.USERNAME_HISTORY+':/d /etc/security/opasswd')
