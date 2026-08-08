"""Managed gRPC test environment for native sonic-mgmt clients."""

import logging
import os
import shutil
import uuid
from dataclasses import dataclass
from enum import Enum

from tests.common.cert_utils import create_gnmi_cert_generator
from tests.common.grpc_config import grpc_config
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.pygnmi_client import PygnmiClient
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)


class GrpcConnection(Enum):
    """Connection kinds supported by the managed gRPC environment."""

    MTLS_TCP = "mtls-tcp"
    PLAINTEXT_TCP = "plaintext-tcp"
    DUT_UDS = "dut-uds"


class GrpcServerProfile(Enum):
    """Server behavior profiles configured by the environment."""

    STANDARD = "standard"


@dataclass(frozen=True)
class GrpcTestSpec:
    """Complete gRPC environment selection for one test module."""

    connection: GrpcConnection = GrpcConnection.MTLS_TCP
    profile: GrpcServerProfile = GrpcServerProfile.STANDARD
    identity: str = "read-only"


DEFAULT_GRPC_TEST_SPEC = GrpcTestSpec()


class GrpcTestEnvironment:
    """Own managed server setup and native client construction for one DUT."""

    CLIENT_CN = "test.client.gnmi.sonic"
    CLIENT_ROLES = "gnmi_readonly"

    def __init__(self, duthost, spec=DEFAULT_GRPC_TEST_SPEC):
        self.duthost = duthost
        self.spec = spec
        resource_id = uuid.uuid4().hex[:8]
        self._checkpoint = "grpc_test_environment_{}".format(resource_id)
        self._cert_dir = "/tmp/grpc_test_environment_{}".format(resource_id)
        self._dut_cert_dir = "{}/grpc-test-{}".format(grpc_config.DUT_CERT_DIR, resource_id)
        self._lock_dir = "/tmp/sonic-mgmt-grpc-test-environment.lock"
        self._lock_acquired = False
        self._checkpoint_created = False

    def start(self):
        """Provision the selected server profile and prove native readiness."""
        self._validate_spec()
        self._acquire_lock()
        create_checkpoint(self.duthost, self._checkpoint)
        self._checkpoint_created = True
        self._generate_certificates()
        self._push_server_certificates()
        self._configure_server()
        self._restart_server()
        if not wait_until(60, 2, 0, self._native_ready):
            raise RuntimeError("gNMI server did not become ready for native mTLS calls")
        return self

    def stop(self):
        """Restore the DUT and remove local test credentials."""
        if not self._checkpoint_created:
            shutil.rmtree(self._cert_dir, ignore_errors=True)
            self._release_lock()
            return

        errors = []
        restored = False
        try:
            output = rollback(self.duthost, self._checkpoint)
            stdout = output.get("stdout", "")
            if output.get("rc") or "Config rolled back successfully" not in stdout:
                errors.append("rollback failed: {}".format(output))
            else:
                try:
                    self._restart_server()
                    wait_critical_processes(self.duthost)
                    restored = True
                except Exception as exc:
                    errors.append("restored configuration is not healthy: {}".format(exc))

            if restored:
                for description, cleanup in (
                    ("delete checkpoint", lambda: delete_checkpoint(self.duthost, self._checkpoint)),
                    ("delete DUT credentials",
                     lambda: self.duthost.shell("rm -rf {}".format(self._dut_cert_dir))),
                    ("delete local credentials",
                     lambda: shutil.rmtree(self._cert_dir, ignore_errors=True)),
                ):
                    try:
                        cleanup()
                    except Exception as exc:
                        errors.append("{} failed: {}".format(description, exc))
                self._checkpoint_created = False
        finally:
            try:
                self._release_lock()
            except Exception as exc:
                errors.append("release lock failed: {}".format(exc))

        if errors:
            raise RuntimeError(
                "gRPC test environment cleanup failed; checkpoint and credentials "
                "were preserved unless restoration completed: {}".format("; ".join(errors))
            )

    def gnmi_client(self):
        """Return a target- and credential-bound native gNMI client."""
        return PygnmiClient(
            self.duthost.mgmt_ip,
            grpc_config.DEFAULT_TLS_PORT,
            ca_cert=os.path.join(self._cert_dir, grpc_config.CA_CERT),
            client_cert=os.path.join(self._cert_dir, grpc_config.CLIENT_CERT),
            client_key=os.path.join(self._cert_dir, grpc_config.CLIENT_KEY),
        )

    def _acquire_lock(self):
        result = self.duthost.shell(
            "mkdir {}".format(self._lock_dir),
            module_ignore_errors=True,
        )
        if result.get("rc"):
            raise RuntimeError(
                "Another managed gRPC test environment owns {}".format(self._lock_dir)
            )
        self._lock_acquired = True

    def _release_lock(self):
        if self._lock_acquired:
            self.duthost.shell("rm -rf {}".format(self._lock_dir))
            self._lock_acquired = False

    def _native_ready(self):
        try:
            self.gnmi_client().capabilities()
            return True
        except Exception as exc:
            logger.debug("Native gNMI readiness probe failed: %s", exc)
            return False

    def _validate_spec(self):
        if self.spec != DEFAULT_GRPC_TEST_SPEC:
            raise ValueError("Unsupported gRPC test spec: {!r}".format(self.spec))

    def _generate_certificates(self):
        generator = create_gnmi_cert_generator(server_ip=self.duthost.mgmt_ip)
        generator.write_all(self._cert_dir)

    def _push_server_certificates(self):
        self.duthost.shell("mkdir -p {}".format(self._dut_cert_dir))
        for name in (grpc_config.CA_CERT, grpc_config.SERVER_CERT, grpc_config.SERVER_KEY):
            self.duthost.copy(
                src=os.path.join(self._cert_dir, name),
                dest="{}/{}".format(self._dut_cert_dir, name),
            )

    def _configure_server(self):
        certs = {
            "ca_crt": "{}/{}".format(self._dut_cert_dir, grpc_config.CA_CERT),
            "server_crt": "{}/{}".format(self._dut_cert_dir, grpc_config.SERVER_CERT),
            "server_key": "{}/{}".format(self._dut_cert_dir, grpc_config.SERVER_KEY),
        }
        commands = [
            'sonic-db-cli CONFIG_DB hset "GNMI|gnmi" port {}'.format(grpc_config.DEFAULT_TLS_PORT),
            'sonic-db-cli CONFIG_DB hset "GNMI|gnmi" client_auth true',
            'sonic-db-cli CONFIG_DB hset "GNMI|gnmi" user_auth cert',
            'sonic-db-cli CONFIG_DB hdel "GNMI|gnmi" vrf enable_crl crl_expire_duration',
            'sonic-db-cli CONFIG_DB hset "GNMI|certs" ca_crt "{}"'.format(certs["ca_crt"]),
            'sonic-db-cli CONFIG_DB hset "GNMI|certs" server_crt "{}"'.format(certs["server_crt"]),
            'sonic-db-cli CONFIG_DB hset "GNMI|certs" server_key "{}"'.format(certs["server_key"]),
            ('sonic-db-cli CONFIG_DB hset "GNMI_CLIENT_CERT|{}" "role@" "{}"'
             .format(self.CLIENT_CN, self.CLIENT_ROLES)),
        ]
        for command in commands:
            self.duthost.shell(command)

    def _restart_server(self):
        result = self.duthost.shell(
            "docker exec gnmi supervisorctl restart gnmi-native",
            module_ignore_errors=True,
        )
        if result.get("rc"):
            raise RuntimeError("Failed to restart gnmi-native: {}".format(result))

        def _running():
            status = self.duthost.shell(
                "docker exec gnmi supervisorctl status gnmi-native",
                module_ignore_errors=True,
            )
            return "RUNNING" in status.get("stdout", "")

        if not wait_until(30, 1, 0, _running):
            raise RuntimeError("gnmi-native did not reach RUNNING")
