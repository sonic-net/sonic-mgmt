import pytest
import logging

from tests.common import config_reload
from tests.common.helpers.assertions import pytest_require as pyrequire
from tests.common.helpers.dut_utils import check_container_state
from tests.common.helpers.gnmi_utils import gnmi_container, add_gnmi_client_common_name, \
                                            create_gnmi_certs, delete_gnmi_certs, GNMIEnvironment, \
                                            GNMI_CERT_NAME
from tests.common.gu_utils import create_checkpoint, rollback
from tests.gnmi_e2e.helper import telemetry_enabled


logger = logging.getLogger(__name__)
SETUP_ENV_CP = "test_setup_checkpoint"


def setup_service_config(duthost, table, port):
    command = 'sudo sonic-db-cli CONFIG_DB hset "{}|certs" "server_crt" "/etc/sonic/telemetry/gnmiserver.crt"' \
              .format(table)
    duthost.shell(command, module_ignore_errors=True)

    command = 'sudo sonic-db-cli CONFIG_DB hset "{}|certs" "server_key" "/etc/sonic/telemetry/gnmiserver.key"' \
              .format(table)
    duthost.shell(command, module_ignore_errors=True)

    command = 'sudo sonic-db-cli CONFIG_DB hset "{}|certs" "ca_crt" "/etc/sonic/telemetry/gnmiCA.pem"' \
              .format(table)
    duthost.shell(command, module_ignore_errors=True)

    command = 'sudo sonic-db-cli CONFIG_DB hset "{}|gnmi" "user_auth" "cert"' \
              .format(table)
    duthost.shell(command, module_ignore_errors=True)

    command = 'sudo sonic-db-cli CONFIG_DB hset "{}|gnmi" "port" "{}"' \
              .format(table, port)
    duthost.shell(command, module_ignore_errors=True)

    command = 'sudo sonic-db-cli CONFIG_DB hset "{}|gnmi" "log_level" "10"' \
              .format(table)
    duthost.shell(command, module_ignore_errors=True)


def apply_cert_config(duthost):
    command = 'sudo config save -y'
    duthost.shell(command, module_ignore_errors=True)

    gnmi_env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)

    # Setup gnmi & telemetry client cert common name
    role = "gnmi_readwrite,gnmi_config_db_readwrite,gnmi_appl_db_readwrite,gnmi_dpu_appl_db_readwrite,gnoi_readwrite"
    add_gnmi_client_common_name(duthost, GNMI_CERT_NAME, role)

    # Setup gnmi config
    setup_service_config(duthost, "GNMI", gnmi_env.gnmi_port)

    # restart gnmi
    command = "docker exec {} supervisorctl stop {}".format(gnmi_env.gnmi_container, gnmi_env.gnmi_program)
    duthost.shell(command, module_ignore_errors=True)

    command = "docker exec {} supervisorctl start {}".format(gnmi_env.gnmi_container, gnmi_env.gnmi_program)
    duthost.shell(command, module_ignore_errors=True)

    # tememetry container not avaliable on all image
    if telemetry_enabled(duthost):
        tele_env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)
        # Setup telemetry config
        setup_service_config(duthost, "TELEMETRY", tele_env.gnmi_port)

        # Restart telemetry service to apply the updated configuration changes
        command = "docker exec {} supervisorctl stop {}".format(tele_env.gnmi_container, tele_env.gnmi_program)
        duthost.shell(command, module_ignore_errors=True)

        command = "docker exec {} supervisorctl start {}".format(tele_env.gnmi_container, tele_env.gnmi_program)
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
