import pytest
import logging
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import skip_release, delete_running_config

logger = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.topology('any')
]


@pytest.fixture
def check_image_version(duthost):
    """Skips this test if the SONiC image installed on DUT is older than 202112
    Args:
        duthost: Hostname of DUT.
    Returns:
        None.
    """
    skip_release(duthost, ["201811", "201911", "202012", "202106"])


TEST_RADIUS_SERVER_ADDRESS = "1.2.3.4"


@pytest.fixture
def setup_password(duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    # Backup original values - if no output, then no backup needed
    tacacs_backup = duthost.shell("sonic-db-cli CONFIG_DB hget 'TACPLUS|global' passkey", module_ignore_errors=True)['stdout'].strip()
    radius_backup = duthost.shell("sonic-db-cli CONFIG_DB hget 'RADIUS|global' passkey", module_ignore_errors=True)['stdout'].strip()
    server_existed = TEST_RADIUS_SERVER_ADDRESS in duthost.shell("sonic-db-cli CONFIG_DB keys 'RADIUS_SERVER|*'", module_ignore_errors=True)['stdout']

    # Setup TACACS/Radius password
    duthost.shell("sudo config tacacs passkey %s" % creds_all_duts[duthost.hostname]['tacacs_passkey'])
    duthost.shell("sudo config radius passkey %s" % creds_all_duts[duthost.hostname]['radius_passkey'])
    duthost.shell("sudo config radius add %s" % TEST_RADIUS_SERVER_ADDRESS)
    yield
    # Remove TACACS/Radius password
    duthost.shell("sudo config tacacs default passkey")
    duthost.shell("sudo config radius default passkey")
    duthost.shell("sudo config radius delete %s" % TEST_RADIUS_SERVER_ADDRESS)

    # Restore configuration
    if tacacs_backup:
        duthost.shell("sudo config tacacs passkey %s" % tacacs_backup)
    else:
        delete_keys_json = [{"TACPLUS": {}}]
        delete_running_config(delete_keys_json, duthost)
    
    if radius_backup:
        duthost.shell("sudo config radius passkey %s" % radius_backup)
    else:
        delete_keys_json = [{"RADIUS": {}}]
        delete_running_config(delete_keys_json, duthost)
    
    if not server_existed:
        duthost.shell("sudo config radius delete %s" % TEST_RADIUS_SERVER_ADDRESS)


def check_no_result(duthost, command):
    res = duthost.shell(command)
    logger.info(command)
    logger.info(res["stdout_lines"])
    pytest_assert(res["rc"] == 0)
    pytest_assert(len(res["stdout_lines"]) == 0)
    pytest_assert(len(res["stderr_lines"]) == 0)


def test_secret_removed_from_show_techsupport(
    duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts, check_image_version, setup_password
):
    """
    This test checks following secrets been removed from show techsupport result:
        Tacacs key
        Radius key
        snmp community string
        /etc/shadow, which includes the hash of local/domain users' password
        Certificate files: *.cer *.crt *.pem *.key
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    tacacs_passkey = creds_all_duts[duthost.hostname]['tacacs_passkey']
    radius_passkey = creds_all_duts[duthost.hostname]['radius_passkey']
    snmp_rocommunity = creds_all_duts[duthost.hostname]['snmp_rocommunity']

    # generate a new dump file. and find latest dump file with ls -t
    duthost.shell('rm -rf /var/dump/sonic_dump_*')
    duthost.shell('show techsupport')
    dump_file_path = duthost.shell('ls -t /var/dump/sonic_dump_* | tail -1')['stdout']
    dump_file_name = dump_file_path.replace("/var/dump/", "")

    # extract for next step check
    duthost.shell("tar -xf {0}".format(dump_file_path))
    dump_extract_path = "./{0}".format(dump_file_name.replace(".tar.gz", ""))

    # check Tacacs key
    sed_command = "sed -nE '/secret={0}/P' {1}/etc/tacplus_nss.conf".format(tacacs_passkey, dump_extract_path)
    check_no_result(duthost, sed_command)

    sed_command = "sed -nE '/secret={0}/P' {1}/etc/pam.d/common-auth-sonic".format(radius_passkey, dump_extract_path)
    check_no_result(duthost, sed_command)

    # check Radius key
    sed_command = "sed -nE '/secret={0}/P' {1}/etc/radius_nss.conf".format(radius_passkey, dump_extract_path)
    check_no_result(duthost, sed_command)

    sed_command = "sed -nE '/{0}/P' {1}/etc/pam_radius_auth.conf".format(radius_passkey, dump_extract_path)
    check_no_result(duthost, sed_command)

    # Check Radius passkey from per-server conf file
    sed_command = "sed -nE '/{0}/P' {1}/etc/pam_radius_auth.d/{2}_1812.conf"\
        .format(radius_passkey, dump_extract_path, TEST_RADIUS_SERVER_ADDRESS)
    check_no_result(duthost, sed_command)

    # check snmp community string not exist
    sed_command = r"sed -nE '/\s*snmp_rocommunity\s*:\s{0}/P' {1}/etc/sonic/snmp.yml"\
        .format(snmp_rocommunity, dump_extract_path)
    check_no_result(duthost, sed_command)

    # check /etc/shadow not exist
    test_command = "test -f {0}/etc/shadow && echo \"/etc/shadow exist\" || true".format(dump_extract_path)
    check_no_result(duthost, test_command)

    # check *.cer *.crt *.pem *.key not exist in dump files
    find_command = r"find {0}/ -type f \( -iname \*.cer -o -iname \*.crt -o -iname \*.pem -o -iname \*.key \)"\
        .format(dump_extract_path)
    check_no_result(duthost, find_command)
