import logging
import pytest
from tests.common.fixtures.tacacs import tacacs_creds     # noqa F401
from .utils import setup_tacacs_client, setup_tacacs_server,\
                    cleanup_tacacs, restore_tacacs_servers

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def check_tacacs(ptfhost, duthosts, enum_rand_one_per_hwsku_hostname, tacacs_creds): # noqa F811
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    tacacs_server_ip = ptfhost.mgmt_ip
    tacacs_server_passkey = tacacs_creds[duthost.hostname]['tacacs_passkey']
    setup_tacacs_client(duthost, tacacs_creds, tacacs_server_ip, tacacs_server_passkey)
    setup_tacacs_server(ptfhost, tacacs_creds, duthost)

    yield

    cleanup_tacacs(ptfhost, tacacs_creds, duthost)
    restore_tacacs_servers(duthost)


@pytest.fixture(scope="module")
def check_tacacs_v6(ptfhost, duthosts, enum_rand_one_per_hwsku_hostname, tacacs_creds): # noqa F811
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    ptfhost_vars = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars
    if 'ansible_hostv6' not in ptfhost_vars:
        pytest.skip("Skip IPv6 test. ptf ansible_hostv6 not configured.")
    tacacs_server_ip = ptfhost_vars['ansible_hostv6']
    tacacs_server_passkey = tacacs_creds[duthost.hostname]['tacacs_passkey']
    setup_tacacs_client(duthost, tacacs_creds, tacacs_server_ip, tacacs_server_passkey)
    setup_tacacs_server(ptfhost, tacacs_creds, duthost)

    yield

    cleanup_tacacs(ptfhost, tacacs_creds, duthost)
    restore_tacacs_servers(duthost)
