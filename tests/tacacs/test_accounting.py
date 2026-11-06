import logging
import pytest
from .accounting import LogCursor, MissingAccounting, capture_logs, verify_accounting, LOCAL_TIMEOUT
from tests.common.helpers.tacacs.tacacs_helper import stop_tacacs_server, start_tacacs_server, \
    per_command_accounting_skip_versions, remove_all_tacacs_server, check_tacacs  # noqa: F401
from .utils import check_server_received, change_and_wait_aaa_config_update, get_auditd_config_reload_timestamp, \
    ssh_connect_remote_retry, ssh_run_command, cleanup_tacacs_log  # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import skip_release


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any', 't1-multi-asic'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)


def check_tacacs_accounting(ptfhost, tacacs_creds, rw_user_client):
    cursors = [LogCursor(ptfhost, "/var/log/tac_plus.acct")]
    capture_logs(cursors)
    ssh_run_command(rw_user_client, "grep")
    verify_accounting(cursors, tacacs_creds['tacacs_rw_user'], ["grep"])


def check_local_accounting(duthost, tacacs_creds, command, config_command,
                           ptfhost, rw_user_client, tacacs=False, retry=6):
    # Preserve the readiness check and six attempts for the known NSS/config
    # race. Only missing positives retry; forbidden records/read failures do not.
    for attempt in range(retry):
        change_and_wait_aaa_config_update(duthost, config_command)
        cleanup_tacacs_log(ptfhost, rw_user_client)
        cursors = [LogCursor(duthost, "/var/log/syslog", local=True)]
        if tacacs:
            cursors.append(LogCursor(ptfhost, "/var/log/tac_plus.acct"))
        capture_logs(cursors)
        ssh_run_command(rw_user_client, command)
        try:
            verify_accounting(cursors, tacacs_creds['tacacs_rw_user'], [command], timeout=LOCAL_TIMEOUT)
            return
        except MissingAccounting:
            # Cleanup on retry would erase an incomplete record before its
            # user/command can be validated, even if another source is missing.
            if any(cursor.pending for cursor in cursors):
                raise AssertionError("Incomplete accounting record prevents retry")
            logger.debug("Found logs: %s", duthost.command("tail /var/log/syslog -n 2000"))
            logger.debug("tacplus_nss.conf: %s", duthost.command("cat /etc/tacplus_nss.conf"))
            if attempt == retry - 1:
                raise


@pytest.fixture
def rw_user_client(duthosts, enum_rand_one_per_hwsku_hostname, tacacs_creds):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip
    ssh_client = ssh_connect_remote_retry(
                    dutip,
                    tacacs_creds['tacacs_rw_user'],
                    tacacs_creds['tacacs_rw_user_passwd'],
                    duthost)
    yield ssh_client
    ssh_client.close()


@pytest.fixture(scope="module", autouse=True)
def check_image_version(duthosts, enum_rand_one_per_hwsku_hostname):
    """Skips this test if the SONiC image installed on DUT is older than 202112
    Args:
        duthosts: DUT hosts.
    Returns:
        None.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    skip_release(duthost, per_command_accounting_skip_versions)


def test_accounting_tacacs_only(
                            ptfhost,
                            duthosts,
                            enum_rand_one_per_hwsku_hostname,
                            tacacs_creds,
                            check_tacacs,  # noqa: F811
                            rw_user_client,
                            skip_in_container_test):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    change_and_wait_aaa_config_update(duthost, "sudo config aaa accounting tacacs+")
    cleanup_tacacs_log(ptfhost, rw_user_client)

    # Verify expected and forbidden records from the same scenario boundary.
    check_tacacs_accounting(ptfhost, tacacs_creds, rw_user_client)


def test_accounting_tacacs_only_all_tacacs_server_down(
                                                    ptfhost,
                                                    duthosts,
                                                    enum_rand_one_per_hwsku_hostname,
                                                    tacacs_creds,
                                                    check_tacacs,  # noqa: F811
                                                    rw_user_client,
                                                    skip_in_container_test):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    change_and_wait_aaa_config_update(duthost, "sudo config aaa accounting tacacs+")
    cleanup_tacacs_log(ptfhost, rw_user_client)

    """
        when user login server are accessible.
        user run some command in whitelist and server are accessible.
    """
    # Verify expected and forbidden records from the same scenario boundary.
    check_tacacs_accounting(ptfhost, tacacs_creds, rw_user_client)

    cleanup_tacacs_log(ptfhost, rw_user_client)

    # Shutdown tacacs server
    try:
        pytest_assert(stop_tacacs_server(ptfhost), "TACACS server failed to stop")
        # Keep the existing SSH command path while all servers are inaccessible.
        ssh_run_command(rw_user_client, "grep")
    finally:
        pytest_assert(start_tacacs_server(ptfhost), "TACACS server failed to restart")


def test_accounting_tacacs_only_some_tacacs_server_down(
                                                    ptfhost,
                                                    duthosts,
                                                    enum_rand_one_per_hwsku_hostname,
                                                    tacacs_creds,
                                                    check_tacacs,  # noqa: F811
                                                    rw_user_client,
                                                    skip_in_container_test):
    """
        Setup multiple tacacs server for this UT.
        Tacacs server 127.0.0.1/::1 not accessible.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost_mgmt_info = duthost.get_mgmt_ip()
    invalid_tacacs_server_ip = "::1" if duthost_mgmt_info["version"] == "v6" else "127.0.0.1"
    tacacs_server_ip = ptfhost.mgmt_ipv6 if duthost_mgmt_info["version"] == "v6" else ptfhost.mgmt_ip

    # when tacacs config change multiple time in short time
    # auditd service may been request reload during reloading
    # when this happen, auditd will ignore request and only reload once
    last_timestamp = get_auditd_config_reload_timestamp(duthost)

    duthost.shell("sudo config tacacs timeout 1")
    remove_all_tacacs_server(duthost)
    duthost.shell("sudo config tacacs add %s --port 59" % invalid_tacacs_server_ip)
    duthost.shell("sudo config tacacs add %s --port 59" % tacacs_server_ip)
    change_and_wait_aaa_config_update(duthost,
                                      "sudo config aaa accounting tacacs+",
                                      last_timestamp)

    try:
        cleanup_tacacs_log(ptfhost, rw_user_client)
        # Verify expected and forbidden records from the same scenario boundary.
        check_tacacs_accounting(ptfhost, tacacs_creds, rw_user_client)
    finally:
        duthost.shell("sudo config tacacs delete %s" % invalid_tacacs_server_ip)


def test_accounting_local_only(
                            ptfhost,
                            duthosts,
                            enum_rand_one_per_hwsku_hostname,
                            tacacs_creds,
                            check_tacacs,  # noqa: F811
                            rw_user_client,
                            skip_in_container_test):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # Verify syslog have user command record.
    check_local_accounting(
                        duthost,
                        tacacs_creds,
                        "grep",
                        "sudo config aaa accounting local",
                        ptfhost,
                        rw_user_client)


def test_accounting_tacacs_and_local(
                                    ptfhost,
                                    duthosts,
                                    enum_rand_one_per_hwsku_hostname,
                                    tacacs_creds,
                                    check_tacacs,  # noqa: F811
                                    rw_user_client):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    check_local_accounting(
                        duthost,
                        tacacs_creds,
                        "grep",
                        'sudo config aaa accounting "tacacs+ local"',
                        ptfhost,
                        rw_user_client,
                        tacacs=True)


def test_accounting_tacacs_and_local_all_tacacs_server_down(
                                                        ptfhost,
                                                        duthosts,
                                                        enum_rand_one_per_hwsku_hostname,
                                                        tacacs_creds,
                                                        check_tacacs,  # noqa: F811
                                                        rw_user_client,
                                                        skip_in_container_test):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # Shutdown tacacs server
    try:
        pytest_assert(stop_tacacs_server(ptfhost), "TACACS server failed to stop")
        # Verify syslog have user command record.
        check_local_accounting(
                            duthost,
                            tacacs_creds,
                            "grep",
                            'sudo config aaa accounting "tacacs+ local"',
                            ptfhost,
                            rw_user_client)
    finally:
        pytest_assert(start_tacacs_server(ptfhost), "TACACS server failed to restart")


def test_send_remote_address(
                            ptfhost,
                            duthosts,
                            enum_rand_one_per_hwsku_hostname,
                            tacacs_creds,
                            check_tacacs,  # noqa: F811
                            rw_user_client,
                            skip_in_container_test):
    """
        Verify TACACS+ send remote address to server.
    """
    exit_code, stdout_stream, stderr_stream = ssh_run_command(rw_user_client, "echo $SSH_CONNECTION")
    pytest_assert(exit_code == 0)

    # Remote address is first part of SSH_CONNECTION: '10.250.0.1 47462 10.250.0.101 22'
    stdout = stdout_stream.readlines()
    remote_address = stdout[0].split(" ")[0]
    check_server_received(ptfhost, remote_address)
