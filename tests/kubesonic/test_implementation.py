"""Incremental implementation tests for kubesonic.

Each test verifies a specific component before moving to the next.
Run tests one at a time to isolate issues:
    pytest kubesonic/test_implementation.py::test_step1_minikube_setup -v
"""

import pytest
import logging

from tests.kubesonic.lib import MinikubeManager, CertManager, DutKubeConfig, KubeClient

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),  # Skip sanity check - monit gives false positives
    pytest.mark.disable_loganalyzer,  # Disable log analyzer - ctrmgrd logs cause false positives
]


class TestImplementationSteps:
    """Incremental tests - run one at a time to verify each component."""

    def test_step1_minikube_setup(self, vmhost, creds):
        """Step 1: Verify minikube starts and API server is accessible from vmhost."""
        mgr = MinikubeManager(vmhost, creds)
        try:
            mgr.stop()  # Clean any existing
            mgr.install_prerequisites()
            mgr.download()
            mgr.start()
            assert mgr.wait_ready(timeout=180), "Minikube not ready after 180s"
            assert mgr.check_api_server(), "API server not accessible from vmhost"
            logger.info("Step 1 PASSED: Minikube is running and API server accessible")
        finally:
            mgr.stop()

    def test_step2_dut_connectivity(self, vmhost, duthost, creds):
        """Step 2: Verify DUT can reach API server on vmhost."""
        mgr = MinikubeManager(vmhost, creds)
        mgr.stop()
        mgr.install_prerequisites()
        mgr.download()
        mgr.start()
        assert mgr.wait_ready(timeout=180), "Minikube not ready"

        try:
            # Check from DUT
            result = duthost.shell(
                f"curl -k -s -o /dev/null -w '%{{http_code}}' https://{vmhost.mgmt_ip}:6443/healthz",
                module_ignore_errors=True
            )
            http_code = result.get("stdout", "").strip()
            logger.info("DUT curl to API server returned HTTP %s", http_code)
            assert http_code in ("200", "401", "403"), \
                f"DUT cannot reach API server at {vmhost.mgmt_ip}:6443, got HTTP {http_code}"
            logger.info("Step 2 PASSED: DUT can reach API server")
        finally:
            mgr.stop()

    def test_step3_cert_extraction(self, vmhost, creds):
        """Step 3: Verify certificates can be extracted from minikube."""
        mgr = MinikubeManager(vmhost, creds)
        mgr.stop()
        mgr.install_prerequisites()
        mgr.download()
        mgr.start()
        assert mgr.wait_ready(timeout=180), "Minikube not ready"

        try:
            cert_mgr = CertManager(vmhost, None)  # duthost not needed for extraction
            cert, key = cert_mgr.extract_certs()
            assert "BEGIN CERTIFICATE" in cert, "Invalid certificate format"
            assert "BEGIN" in key and "KEY" in key, "Invalid key format"
            logger.info("Step 3 PASSED: Certificates extracted successfully")
            logger.info("Certificate preview: %s...", cert[:100])
        finally:
            mgr.stop()

    def test_step4_cert_installation(self, vmhost, duthost, creds):
        """Step 4: Verify certificates can be installed on DUT."""
        mgr = MinikubeManager(vmhost, creds)
        mgr.stop()
        mgr.install_prerequisites()
        mgr.download()
        mgr.start()
        assert mgr.wait_ready(timeout=180), "Minikube not ready"

        cert_mgr = CertManager(vmhost, duthost)
        try:
            cert_mgr.setup()

            # Verify certs exist on DUT
            result = duthost.shell("ls -la /etc/sonic/credentials/", module_ignore_errors=True)
            assert "restapiserver.crt" in result["stdout"], "restapiserver.crt not found on DUT"
            assert "restapiserver.key" in result["stdout"], "restapiserver.key not found on DUT"
            logger.info("Step 4 PASSED: Certificates installed on DUT")
        finally:
            cert_mgr.teardown()
            mgr.stop()

    def test_step5_dns_setup(self, vmhost, duthost):
        """Step 5: Verify DNS entry can be added to DUT /etc/hosts."""
        cfg = DutKubeConfig(duthost, vmhost)
        try:
            cfg.setup_dns()
            result = duthost.shell("cat /etc/hosts | grep control-plane.minikube.internal")
            assert vmhost.mgmt_ip in result["stdout"], \
                f"DNS entry not found, expected {vmhost.mgmt_ip}"
            logger.info("Step 5 PASSED: DNS entry added to DUT /etc/hosts")
        finally:
            cfg.remove_dns()

    def test_step6_kubelet_config(self, vmhost, creds):
        """Step 6: Verify kubelet config can be updated."""
        mgr = MinikubeManager(vmhost, creds)
        mgr.stop()
        mgr.install_prerequisites()
        mgr.download()
        mgr.start()
        assert mgr.wait_ready(timeout=180), "Minikube not ready"

        try:
            mgr.update_kubelet_config()
            # Verify config was updated
            result = vmhost.shell(
                "NO_PROXY=192.168.49.2 minikube kubectl -- get cm kubelet-config-1.22 "
                "-n kube-system -o yaml | grep /etc/kubernetes/pki/ca.crt"
            )
            assert "/etc/kubernetes/pki/ca.crt" in result["stdout"], \
                "Kubelet config not updated with correct ca.crt path"
            logger.info("Step 6 PASSED: Kubelet config updated")
        finally:
            mgr.stop()

    def test_step7_kube_client(self, vmhost, creds):
        """Step 7: Verify Python K8s client can list nodes."""
        mgr = MinikubeManager(vmhost, creds)
        mgr.stop()
        mgr.install_prerequisites()
        mgr.download()
        mgr.start()
        assert mgr.wait_ready(timeout=180), "Minikube not ready"

        try:
            kubeconfig = mgr.get_kubeconfig_data()
            client = KubeClient(kubeconfig_dict=kubeconfig)
            assert client.node_exists("minikube"), "Minikube node not found via Python client"
            assert client.is_node_ready("minikube"), "Minikube node not ready via Python client"
            logger.info("Step 7 PASSED: Python K8s client can connect and list nodes")
        finally:
            mgr.stop()

    def test_step8_dut_join(self, vmhost, duthost, creds):
        """Step 8: Full integration - DUT joins K8s cluster."""
        # Check kube support first
        result = duthost.shell(
            "systemctl list-unit-files ctrmgrd.service",
            module_ignore_errors=True
        )
        if "ctrmgrd.service" not in result.get("stdout", ""):
            pytest.skip("DUT does not have kubesonic support (ctrmgrd service not found)")

        # Setup minikube
        mgr = MinikubeManager(vmhost, creds)
        mgr.setup()  # Full setup including daemonset

        # Setup certs
        cert_mgr = CertManager(vmhost, duthost)
        cert_mgr.setup()

        # Setup DUT config
        dut_cfg = DutKubeConfig(duthost, vmhost)
        dut_cfg.setup()

        try:
            # Verify DUT can reach API server before join
            result = duthost.shell(
                f"curl -k -s -o /dev/null -w '%{{http_code}}' https://{vmhost.mgmt_ip}:6443/healthz",
                module_ignore_errors=True
            )
            http_code = result.get("stdout", "").strip()
            assert http_code in ("200", "401", "403"), \
                f"DUT cannot reach API server, got HTTP {http_code}"

            # Join cluster
            dut_cfg.join(timeout=180)

            # Verify with Python client
            kubeconfig = mgr.get_kubeconfig_data()
            client = KubeClient(kubeconfig_dict=kubeconfig)
            assert client.node_exists(duthost.hostname), \
                f"DUT {duthost.hostname} not found in cluster"
            assert client.is_node_ready(duthost.hostname), \
                f"DUT {duthost.hostname} not ready in cluster"
            logger.info("Step 8 PASSED: DUT successfully joined K8s cluster")
        finally:
            try:
                dut_cfg.disjoin()
            except Exception:
                pass
            dut_cfg.teardown()
            cert_mgr.teardown()
            mgr.teardown()
