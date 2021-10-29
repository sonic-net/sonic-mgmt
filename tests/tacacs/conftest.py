import pytest
from .utils import setup_tacacs_client, setup_tacacs_server, cleanup_tacacs

@pytest.fixture(scope="module")
def check_tacacs(ptfhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    tacacs_server_ip = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars['ansible_host']
    setup_tacacs_client(duthost, creds_all_duts, tacacs_server_ip)
    setup_tacacs_server(ptfhost, creds_all_duts, duthost)

    yield

    cleanup_tacacs(ptfhost, duthost, tacacs_server_ip)


@pytest.fixture(scope="module")
def check_tacacs_v6(ptfhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    ptfhost_vars = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars
    if 'ansible_hostv6' not in ptfhost_vars:
        pytest.skip("Skip IPv6 test. ptf ansible_hostv6 not configured.")
    tacacs_server_ip = ptfhost_vars['ansible_hostv6']
    setup_tacacs_client(duthost, creds_all_duts, tacacs_server_ip)
    setup_tacacs_server(ptfhost, creds_all_duts, duthost)

    yield

    cleanup_tacacs(ptfhost, duthost, tacacs_server_ip)