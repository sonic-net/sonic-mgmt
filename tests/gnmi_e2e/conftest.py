import pytest
import logging

from tests.common import config_reload
from tests.common.helpers.assertions import pytest_require as pyrequire
from tests.common.helpers.dut_utils import check_container_state
from tests.common.helpers.gnmi_utils import gnmi_container, add_gnmi_client_common_name, \
                                            create_gnmi_certs, delete_gnmi_certs, GNMIEnvironment
from tests.common.gu_utils import create_checkpoint, rollback


logger = logging.getLogger(__name__)
SETUP_ENV_CP = "test_setup_checkpoint"


def apply_cert_config(duthost):
    command = 'sudo config save -y'
    duthost.shell(command, module_ignore_errors=True)

    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)

    # Setup gnmi client cert common name
    role = "gnmi_readwrite,gnmi_config_db_readwrite,gnmi_appl_db_readwrite,gnmi_dpu_appl_db_readwrite,gnoi_readwrite"
    add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
    add_gnmi_client_common_name(duthost, "test.client.revoked.gnmi.sonic", role)

    # Setup gnmi config
    command = 'sudo sonic-db-cli CONFIG_DB hset "GNMI|certs" "server_crt" "/etc/sonic/telemetry/gnmiserver.crt"'
    duthost.shell(command, module_ignore_errors=True)

    command = 'sudo sonic-db-cli CONFIG_DB hset "GNMI|certs" "server_key" "/etc/sonic/telemetry/gnmiserver.key"'
    duthost.shell(command, module_ignore_errors=True)

    command = 'sudo sonic-db-cli CONFIG_DB hset "GNMI|certs" "ca_crt" "/etc/sonic/telemetry/gnmiCA.pem"'
    duthost.shell(command, module_ignore_errors=True)

    command = 'sudo sonic-db-cli CONFIG_DB hset "GNMI|gnmi" "user_auth" "cert"'
    duthost.shell(command, module_ignore_errors=True)

    command = 'sudo sonic-db-cli CONFIG_DB hset "GNMI|gnmi" "port" "{}"'.format(env.gnmi_port)
    duthost.shell(command, module_ignore_errors=True)

    command = 'sudo sonic-db-cli CONFIG_DB hset "GNMI|gnmi" "log_level" "10"'
    duthost.shell(command, module_ignore_errors=True)

    # restart gnmi
    command = "docker exec {} supervisorctl stop {}".format(env.gnmi_container, env.gnmi_program)
    duthost.shell(command, module_ignore_errors=True)

    command = "docker exec {} supervisorctl start {}".format(env.gnmi_container, env.gnmi_program)
    duthost.shell(command, module_ignore_errors=True)


def recover_cert_config(duthost):
    config_reload(duthost)


@pytest.fixture(scope="module", autouse=True)
def setup_gnmi_server_e2e(duthosts, rand_one_dut_hostname, localhost, ptfhost):
    '''
    Create GNMI client certificates
    '''
    duthost = duthosts[rand_one_dut_hostname]

    # Check if GNMI is enabled on the device
    pyrequire(
        check_container_state(duthost, gnmi_container(duthost), should_be_running=True),
        "Test was not supported on devices which do not support GNMI!")

    create_gnmi_certs(duthost, localhost, ptfhost)

    create_checkpoint(duthost, SETUP_ENV_CP)
    apply_cert_config(duthost)

    yield

    recover_cert_config(duthost)
    delete_gnmi_certs(localhost)

    # Rollback configuration
    rollback(duthost, SETUP_ENV_CP)
