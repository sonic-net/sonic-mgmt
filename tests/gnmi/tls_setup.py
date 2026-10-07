"""Managed gNMI service lifecycle using the legacy test certificate paths."""
import logging
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from tests.common.fixtures.grpc_fixtures import _configure_gnoi_tls_server, _restart_gnoi_server
from tests.common.grpc_config import grpc_config
from tests.common.gu_utils import create_checkpoint, rollback
from tests.common.helpers.assertions import pytest_require
from tests.common.helpers.dut_utils import check_container_state
from tests.common.helpers.gnmi_utils import (
    add_gnmi_client_common_name, create_gnmi_certs, delete_gnmi_certs,
    del_gnmi_client_common_name, gnmi_container,
)
from tests.common.utilities import wait_until
from .helper import check_gnmi_status, check_system_time_sync

logger = logging.getLogger(__name__)


@contextmanager
def gnmi_server_context(duthost, localhost, ptfhost, vrf_config):
    """Yield the endpoint/cert adapter; rotation remains owned by the caller's fixtures."""
    pytest_require(
        check_container_state(duthost, gnmi_container(duthost), should_be_running=True),
        "Test was not supported on devices which do not support GNMI!")
    create_gnmi_certs(duthost, localhost, ptfhost, dut_ip=vrf_config.get("dut_ip"))
    create_checkpoint(duthost, "test_setup_checkpoint")
    _configure_gnoi_tls_server(duthost)
    # Keep the legacy certificates, CRL policy and logging on the managed service.
    duthost.shell('sonic-db-cli CONFIG_DB hset "GNMI|certs" '
                  'ca_crt /etc/sonic/telemetry/gnmiCA.pem '
                  'server_crt /etc/sonic/telemetry/gnmiserver.crt '
                  'server_key /etc/sonic/telemetry/gnmiserver.key')
    duthost.shell('sonic-db-cli CONFIG_DB hset "GNMI|gnmi" enable_crl true log_level 10')
    role = "gnmi_readwrite,gnmi_config_db_readwrite,gnmi_appl_db_readwrite,gnmi_dpu_appl_db_readwrite,gnoi_readwrite"
    add_gnmi_client_common_name(duthost, "test.client.revoked.gnmi.sonic", role)
    _restart_gnoi_server(duthost)
    if duthost.facts['platform'] != 'x86_64-kvm_x86_64-r0':
        is_time_synced = wait_until(80, 3, 0, check_system_time_sync, duthost)
        assert is_time_synced, "Failed to synchronize DUT system time with NTP Server"

    try:
        yield SimpleNamespace(
            host=duthost.mgmt_ip, port=grpc_config.DEFAULT_TLS_PORT,
            pygnmi_client=SimpleNamespace(ca_cert="gnmiCA.pem", client_cert="gnmiclient.crt",
                                          client_key="gnmiclient.key"))
    finally:
        delete_gnmi_certs(localhost)
        rollback(duthost, "test_setup_checkpoint")
        duthost.shell("config save -y", module_ignore_errors=True)
        del_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")
        del_gnmi_client_common_name(duthost, "test.client.revoked.gnmi.sonic")
        # The restored service can use a different port from the managed TLS setup.
        duthost.shell("docker exec gnmi supervisorctl restart gnmi-native")
        if not wait_until(300, 3, 0, check_gnmi_status, duthost):
            output = duthost.shell("tail /var/log/gnmi.log", module_ignore_errors=True)
            logger.error("GNMI service failed to start. GNMI log: {}".format(output['stdout']))
            pytest.fail("Failed to recover GNMI client cert configuration.")
        if not check_container_state(duthost, "telemetry", should_be_running=True):
            duthost.shell("sudo systemctl restart telemetry", module_ignore_errors=True)
        duthost.shell("sudo /usr/bin/container_checker")
