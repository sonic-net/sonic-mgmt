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
    enable_crl: bool = False


DEFAULT_GRPC_TEST_SPEC = GrpcTestSpec()


class GrpcTestEnvironment:
    """Own managed server setup and native client construction for one DUT."""

    CLIENT_CN = "test.client.gnmi.sonic"
    CLIENT_ROLES = "gnmi_readonly"
    REVOKED_CN = "test.client.revoked.gnmi.sonic"
    REVOKED_ROLES = "gnmi_readwrite"
    CRL_PORT = 8080

    def __init__(self, duthost, spec=DEFAULT_GRPC_TEST_SPEC, ptfhost=None):
        self.duthost = duthost
        self.spec = spec
        self.ptfhost = ptfhost
        resource_id = uuid.uuid4().hex[:8]
        self._checkpoint = "grpc_test_environment_{}".format(resource_id)
        self._cert_dir = "/tmp/grpc_test_environment_{}".format(resource_id)
        self._dut_cert_dir = "{}/grpc-test-{}".format(grpc_config.DUT_CERT_DIR, resource_id)
        self._lock_dir = "/tmp/sonic-mgmt-grpc-test-environment.lock"
        self._lock_acquired = False
        self._checkpoint_created = False
        self._crl_ptf_dir = None
        self._crl_pid = None
        self._crl_bind_address = None
        self._gnmi_log_start_line = 1

    def start(self):
        """Provision the selected server profile and prove native readiness."""
        self._validate_spec()
        self._acquire_lock()
        create_checkpoint(self.duthost, self._checkpoint)
        self._checkpoint_created = True
        self._generate_certificates()
        self._push_server_certificates()
        if self.spec.enable_crl:
            self._start_crl_server()
        self._configure_server()
        self._restart_server()
        if not wait_until(60, 2, 0, self._native_ready):
            raise RuntimeError("gNMI server did not become ready for native mTLS calls")
        self._mark_gnmi_log_start()
        return self

    def stop(self):
        """Restore the DUT and remove local test credentials."""
        if not self._checkpoint_created:
            shutil.rmtree(self._cert_dir, ignore_errors=True)
            self._release_lock()
            return

        errors = []
        restored = False
        if self.spec.enable_crl:
            self._stop_crl_server(errors)
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

    def gnmi_client(self, connect=True):
        """Return a target- and credential-bound native gNMI client."""
        return PygnmiClient(
            self.duthost.mgmt_ip,
            grpc_config.DEFAULT_TLS_PORT,
            ca_cert=os.path.join(self._cert_dir, grpc_config.CA_CERT),
            client_cert=os.path.join(self._cert_dir, grpc_config.CLIENT_CERT),
            client_key=os.path.join(self._cert_dir, grpc_config.CLIENT_KEY),
            connect=connect,
        )

    def revoked_client(self):
        """Return a credential-bound native gNMI client using the revoked certificate."""
        return PygnmiClient(
            self.duthost.mgmt_ip,
            grpc_config.DEFAULT_TLS_PORT,
            ca_cert=os.path.join(self._cert_dir, grpc_config.CA_CERT),
            client_cert=os.path.join(self._cert_dir, "gnmiclient.revoked.cer"),
            client_key=os.path.join(self._cert_dir, "gnmiclient.revoked.key"),
            connect=False,
        )

    def gnmi_log(self):
        """Return gNMI log lines emitted after this environment became ready."""
        result = self.duthost.shell(
            "sudo tail -n +{} /var/log/gnmi.log".format(
                self._gnmi_log_start_line
            ),
            module_ignore_errors=True,
        )
        return result.get("stdout", "")

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

    def _mark_gnmi_log_start(self):
        result = self.duthost.shell(
            "sudo sh -c 'wc -l < /var/log/gnmi.log'",
            module_ignore_errors=True,
        )
        try:
            self._gnmi_log_start_line = int(result.get("stdout", "0").strip()) + 1
        except (TypeError, ValueError):
            logger.warning(
                "Unable to determine gNMI log offset: %s", result
            )
            self._gnmi_log_start_line = 1

    def _validate_spec(self):
        if (self.spec.connection != GrpcConnection.MTLS_TCP
                or self.spec.profile != GrpcServerProfile.STANDARD
                or self.spec.identity != DEFAULT_GRPC_TEST_SPEC.identity):
            raise ValueError("Unsupported gRPC test spec: {!r}".format(self.spec))
        if self.spec.enable_crl and self.ptfhost is None:
            raise ValueError("CRL-enabled gRPC test environment requires ptfhost")

    def _generate_certificates(self):
        generator = create_gnmi_cert_generator(server_ip=self.duthost.mgmt_ip)
        generator.write_all(self._cert_dir)
        if self.spec.enable_crl:
            dut_facts = self.duthost.dut_basic_facts()["ansible_facts"]["dut_basic_facts"]
            if dut_facts.get("is_mgmt_ipv6_only", False) and self.ptfhost.mgmt_ipv6:
                self._crl_bind_address = self.ptfhost.mgmt_ipv6
                crl_url = "http://[{}]:{}/sonic.crl.pem".format(
                    self.ptfhost.mgmt_ipv6, self.CRL_PORT
                )
            else:
                crl_url = "http://{}:{}/sonic.crl.pem".format(
                    self.ptfhost.mgmt_ip, self.CRL_PORT
                )
            generator.generate_revoked_cert_with_crl(crl_url, self._cert_dir)

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
        if self.spec.enable_crl:
            commands += [
                'sonic-db-cli CONFIG_DB hset "GNMI|gnmi" enable_crl true',
                'sonic-db-cli CONFIG_DB hset "GNMI|gnmi" crl_expire_duration 30',
                ('sonic-db-cli CONFIG_DB hset "GNMI_CLIENT_CERT|{}" "role@" "{}"'
                 .format(self.REVOKED_CN, self.REVOKED_ROLES)),
            ]
        for command in commands:
            self.duthost.shell(command)

    def _crl_port_free(self):
        """Raise if CRL_PORT is already in use on the PTF host."""
        result = self.ptfhost.shell(
            "ss -ltnH 'sport = :{}'".format(self.CRL_PORT),
            module_ignore_errors=True,
        )
        if result.get("stdout", "").strip():
            raise RuntimeError(
                "CRL port {} is already occupied on PTF host".format(self.CRL_PORT)
            )

    def _start_crl_server(self):
        """Copy crl_server.py + CRL PEM to a UUID dir on PTF and launch it."""
        self._crl_port_free()
        ptf_dir = "/root/crl-{}".format(uuid.uuid4().hex[:8])
        self._crl_ptf_dir = ptf_dir
        self.ptfhost.shell("mkdir -p {}".format(ptf_dir))

        # Locate crl_server.py relative to this module's package root
        crl_server_src = os.path.join(
            os.path.dirname(__file__), "..", "..", "tests", "gnmi", "crl", "crl_server.py"
        )
        crl_server_src = os.path.normpath(crl_server_src)
        self.ptfhost.copy(src=crl_server_src, dest="{}/crl_server.py".format(ptf_dir))
        self.ptfhost.copy(
            src=os.path.join(self._cert_dir, "sonic.crl.pem"),
            dest="{}/sonic.crl.pem".format(ptf_dir),
        )

        # Launch; capture PID; validate it is an integer
        bind_arg = ""
        if self._crl_bind_address:
            bind_arg = " --bind {}".format(self._crl_bind_address)
        result = self.ptfhost.shell(
            "cd {dir}; nohup /root/env-python3/bin/python crl_server.py "
            "--port {port}{bind_arg} > crl.log 2>&1 </dev/null & echo $!".format(
                dir=ptf_dir,
                port=self.CRL_PORT,
                bind_arg=bind_arg,
            )
        )
        pid_str = result.get("stdout", "").strip()
        try:
            self._crl_pid = int(pid_str)
        except (ValueError, TypeError):
            raise RuntimeError(
                "CRL server did not return a valid PID; got: {!r}".format(pid_str)
            )
        logger.info("CRL server started at PID %d in %s", self._crl_pid, ptf_dir)

        def _crl_ready():
            res = self.ptfhost.shell(
                "grep -c 'Ready handle request' {}/crl.log".format(ptf_dir),
                module_ignore_errors=True,
            )
            return res.get("rc", 1) == 0 and int(res.get("stdout", "0").strip() or "0") > 0

        if not wait_until(60, 1, 0, _crl_ready):
            raise RuntimeError("CRL server did not signal readiness in {}".format(ptf_dir))
        logger.info("CRL server ready")

    def _stop_crl_server(self, errors):
        """Kill the CRL server by exact PID, wait for exit, then remove the PTF dir."""
        if self._crl_pid is not None:
            try:
                self.ptfhost.shell(
                    "kill {} 2>/dev/null || true".format(self._crl_pid),
                    module_ignore_errors=True,
                )
                # Wait for the process to exit (up to 10 s)
                if not wait_until(
                    10,
                    1,
                    0,
                    lambda: self.ptfhost.shell(
                        "kill -0 {} 2>/dev/null; echo $?".format(self._crl_pid),
                        module_ignore_errors=True,
                    ).get("stdout", "0").strip() != "0",
                ):
                    errors.append(
                        "CRL server PID {} did not exit".format(self._crl_pid)
                    )
            except Exception as exc:
                errors.append("stop CRL server failed: {}".format(exc))
            finally:
                self._crl_pid = None
        if self._crl_ptf_dir:
            try:
                self.ptfhost.shell(
                    "rm -rf {}".format(self._crl_ptf_dir),
                    module_ignore_errors=True,
                )
            except Exception as exc:
                errors.append("remove CRL PTF dir failed: {}".format(exc))
            finally:
                self._crl_ptf_dir = None

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
