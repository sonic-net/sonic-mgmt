import pytest
import logging
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import skip_release

logger = logging.getLogger(__name__)

@pytest.fixture
def check_image_version(duthost):
    """Skips this test if the SONiC image installed on DUT is older than 202112
    Args:
        duthost: Hostname of DUT.
    Returns:
        None.
    """
    skip_release(duthost, ["201811", "201911", "202012", "202106"])

@pytest.fixture
def setup_password(duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    # Setup TACACS/Radius password
    duthost.shell("sudo config tacacs passkey %s" % creds_all_duts[duthost.hostname]['tacacs_passkey'])
    duthost.shell("sudo config radius passkey %s" % creds_all_duts[duthost.hostname]['radius_passkey'])
    yield
    # Remove TACACS/Radius password
    duthost.shell("sudo config tacacs default passkey")
    duthost.shell("sudo config radius default passkey")

    # Remove TACACS/Radius keys
    duthost.copy(src="./show_techsupport/templates/del_keys.json", dest='/tmp/del_keys.json')
    duthost.shell("configlet -d -j {}".format("/tmp/del_keys.json"))

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
    dump_extract_path="./{0}".format(dump_file_name.replace(".tar.gz", ""))

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

    # Check Radius passkey from per-server conf file /etc/pam_radius_auth.d/{ip}_{port}.conf
    list_command = "ls {0}/etc/pam_radius_auth.d/*.conf || true".format(dump_extract_path)
    config_file_list = duthost.shell(list_command)["stdout_lines"]
    for config_file in config_file_list:
        sed_command = "sed -nE '/{0}/P' {1}/etc/pam_radius_auth.d/{1}".format(radius_passkey, dump_extract_path, config_file)
        check_no_result(duthost, sed_command)

    # check snmp community string not exist
    sed_command = "sed -nE '/\s*snmp_rocommunity\s*:\s{0}/P' {1}/etc/sonic/snmp.yml".format(snmp_rocommunity, dump_extract_path)
    check_no_result(duthost, sed_command)

    # check /etc/shadow not exist
    test_command = "test -f {0}/etc/shadow && echo \"/etc/shadow exist\" || true".format(dump_extract_path)
    check_no_result(duthost, test_command)

    # check *.cer *.crt *.pem *.key not exist in dump files
    find_command = "find {0}/ -type f \( -iname \*.cer -o -iname \*.crt -o -iname \*.pem -o -iname \*.key \)".format(dump_extract_path)
    check_no_result(duthost, find_command)
