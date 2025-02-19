import logging
import pytest
import time
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.snmp_helpers import get_snmp_facts, get_snmp_facts_v3, SnmpOIDs

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

def setup_snmpv3_user(duthost, username=None, auth_pass=None, priv_pass=None):
    """Setup SNMPv3 user on DUT"""
    if not username:
        username = f"snmpTest_{int(time.time())}"
    if not auth_pass:
        auth_pass = "password123"
    if not priv_pass:
        priv_pass = "password123"

    try:
        # Remove existing user if any
        logger.info(f"Removing existing SNMPv3 user if exists: {username}")
        duthost.shell(f"sudo config snmp user del {username}", module_ignore_errors=True)
        time.sleep(2)

        # Create new SNMPv3 user
        create_cmd = f"sudo config snmp user add {username} Priv RO SHA {auth_pass} AES {priv_pass}"
        logger.info(f"Creating SNMPv3 user with command: {create_cmd}")
        result = duthost.shell(create_cmd)
        pytest_assert(result['rc'] == 0, f"Failed to create SNMPv3 user: {result['stderr']}")

        time.sleep(5)  # Wait for user creation

        return {
            "username": username,
            "auth_protocol": "SHA",  # Changed to uppercase to match SNMP requirements
            "auth_password": auth_pass,
            "priv_protocol": "AES",  # Changed to uppercase to match SNMP requirements
            "priv_password": priv_pass
        }

    except Exception as e:
        logger.error(f"Failed to setup SNMPv3 user: {str(e)}")
        raise

def cleanup_snmpv3_user(duthost, username):
    """Cleanup SNMPv3 user from DUT"""
    try:
        logger.info(f"Cleaning up SNMPv3 user: {username}")
        duthost.shell(f"sudo config snmp user del {username}", module_ignore_errors=True)
    except Exception as e:
        logger.error(f"Failed to cleanup SNMPv3 user: {str(e)}")  # Removed extra parenthesis

@pytest.mark.parametrize("test_case", [
    {
        "name": "wrong_username",
        "modify": lambda c: {"username": "invalid_user"},
        "error_msg": "Expected failure with invalid username"
    },
    {
        "name": "wrong_auth_password",
        "modify": lambda c: {"auth_key": "wrong_auth_pass"},
        "error_msg": "Expected failure with invalid auth password"
    },
    {
        "name": "wrong_priv_password",
        "modify": lambda c: {"priv_key": "wrong_priv_pass"},
        "error_msg": "Expected failure with invalid priv password"
    },
    {
        "name": "wrong_auth_protocol",
        "modify": lambda c: {"auth_protocol": "md5"},
        "error_msg": "Expected failure with invalid auth protocol"
    },
    {
        "name": "wrong_priv_protocol",
        "modify": lambda c: {"priv_protocol": "des"},
        "error_msg": "Expected failure with invalid priv protocol"
    }
])
def test_snmpv3_invalid_credentials(duthosts, rand_one_dut_hostname, localhost, test_case):
    """
    Test SNMPv3 GET operation with invalid credentials
    Will only run on virtual switch devices, but works with any topology
    """
    duthost = duthosts[rand_one_dut_hostname]
    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    v3_config = None

    try:
        # Create valid SNMPv3 user first
        v3_config = setup_snmpv3_user(duthost)
        logger.info(f"Created base SNMPv3 user: {v3_config['username']}")

        # Create invalid credentials based on the test case
        invalid_config = v3_config.copy()
        invalid_config.update(test_case["modify"](v3_config))
        
        logger.info(f"Testing invalid credentials case: {test_case['name']}")
        try:
            snmp_facts = get_snmp_facts(
                localhost,
                host=hostip,
                version="v3",
                username=invalid_config.get("username", v3_config["username"]),
                integrity=invalid_config.get("integrity", v3_config["auth_protocol"].lower()),
                authkey=invalid_config.get("authkey", v3_config["auth_password"]),
                privacy=invalid_config.get("privacy", v3_config["priv_protocol"]),
                privkey=invalid_config.get("privpassword", v3_config["priv_password"]),
                level="authPriv",
                wait=True,
                oid=SnmpOIDs.SYS_DESCR  # Using SnmpOIDs.SYS_DESCR directly
            )
            pytest.fail(f"SNMPv3 GET succeeded with invalid credentials for case: {test_case['name']}")
            
        except Exception as e:
            logger.info(f"{test_case['error_msg']}: {str(e)}")

    except Exception as e:
        pytest.fail(f"SNMPv3 invalid credentials test failed: {str(e)}")

    finally:
        if v3_config:
            cleanup_snmpv3_user(duthost, v3_config["username"])


def test_snmpv3_valid_after_invalid(duthosts, rand_one_dut_hostname, localhost):
    """
    Verify that valid SNMPv3 credentials still work after invalid attempts
    """
    duthost = duthosts[rand_one_dut_hostname]
    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    v3_config = None

    try:
        # Create valid SNMPv3 user
        v3_config = setup_snmpv3_user(duthost)
        logger.info(f"Created SNMPv3 user: {v3_config['username']}")

        # Now test with valid credentials
        logger.info("Verifying valid credentials still work")
        snmp_facts = get_snmp_facts_v3(
            localhost=localhost,
            wait=True,
            version="v3",
            host=hostip,
            username=v3_config["username"],  # Using valid username
            integrity=v3_config["auth_protocol"].lower(),
            authkey=v3_config["auth_password"],
            privacy=v3_config["priv_protocol"].lower(),
            privkey=v3_config["priv_password"],
            level="authPriv",
            oid=SnmpOIDs.SYS_DESCR
        )
        
        pytest_assert(snmp_facts is not None, "Failed to get SNMP facts with valid credentials")
        pytest_assert('ansible_facts' in snmp_facts, "No ansible_facts in SNMP response with valid credentials")
        logger.info("Successfully verified SNMPv3 access with valid credentials")

    except Exception as e:
        pytest.fail(f"SNMPv3 valid credentials verification failed: {str(e)}")

    finally:
        if v3_config:
            cleanup_snmpv3_user(duthost, v3_config["username"])

