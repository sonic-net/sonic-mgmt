import os
import logging
import yaml
import pytest
from .utils import setup_tacacs_client, setup_tacacs_server, cleanup_tacacs, restore_tacacs_servers

logger = logging.getLogger(__name__)
TACACS_CREDS_FILE='tacacs_creds.yaml'


@pytest.fixture(scope="module")
def tacacs_creds(creds_all_duts):
    creds_file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), TACACS_CREDS_FILE)
    hardcoded_creds = yaml.safe_load(open(creds_file_path).read())
    creds_all_duts.update(hardcoded_creds)
    return creds_all_duts

@pytest.fixture(scope="module")
def check_tacacs(ptfhost, duthosts, enum_rand_one_per_hwsku_hostname, tacacs_creds):
    logger.info('tacacs_creds: {}'.format(str(tacacs_creds)))
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    tacacs_server_ip = ptfhost.mgmt_ip
    default_tacacs_servers = setup_tacacs_client(duthost, tacacs_creds, tacacs_server_ip)
    setup_tacacs_server(ptfhost, tacacs_creds, duthost)

    yield

    cleanup_tacacs(ptfhost, tacacs_creds, duthost)
    restore_tacacs_servers(duthost, default_tacacs_servers, tacacs_server_ip)

@pytest.fixture(scope="module")
def check_tacacs_v6(ptfhost, duthosts, enum_rand_one_per_hwsku_hostname, tacacs_creds):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    ptfhost_vars = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars
    if 'ansible_hostv6' not in ptfhost_vars:
        pytest.skip("Skip IPv6 test. ptf ansible_hostv6 not configured.")
    tacacs_server_ip = ptfhost_vars['ansible_hostv6']
    setup_tacacs_client(duthost, tacacs_creds, tacacs_server_ip)
    setup_tacacs_server(ptfhost, tacacs_creds, duthost)

    yield

    cleanup_tacacs(ptfhost, tacacs_creds, duthost)
