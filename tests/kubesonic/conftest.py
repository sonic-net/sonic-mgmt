"""Pytest fixtures for kubesonic tests.

These fixtures provide a complete minikube-based K8s test environment:
- minikube cluster running on vmhost
- Certificates installed on DUT
- DUT configured and joined to the cluster
- Python K8s client for verification

Usage:
    # For tests that need DUT joined to minikube cluster:
    def test_something(kubesonic_cluster):
        client = kubesonic_cluster['client']
        duthost = kubesonic_cluster['duthost']
        assert client.is_node_ready(duthost.hostname)

    # For tests that need individual components:
    def test_minikube_only(minikube, kube_client):
        assert kube_client.is_node_ready("minikube")
"""

import pytest
import logging

from tests.common.kubesonic import MinikubeManager, CertManager, DutKubeConfig, KubeClient
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def check_kube_support(duthost):
    """Check if DUT has kubesonic support, skip tests if not."""
    result = duthost.shell(
        "systemctl list-unit-files ctrmgrd.service",
        module_ignore_errors=True
    )
    if "ctrmgrd.service" not in result.get("stdout", ""):
        pytest.skip("DUT does not have kubesonic support (ctrmgrd service not found)")


@pytest.fixture(scope="module")
def minikube(check_kube_support, vmhost, creds):
    """Setup minikube cluster on vmhost.

    Yields:
        MinikubeManager: Manager instance for the minikube cluster
    """
    mgr = MinikubeManager(vmhost, creds)
    mgr.setup()
    yield mgr
    mgr.teardown()


@pytest.fixture(scope="module")
def dut_certs(minikube, vmhost, duthost):
    """Install certs on DUT.

    Yields:
        CertManager: Manager instance for certificate management
    """
    mgr = CertManager(vmhost, duthost)
    mgr.setup()
    yield mgr
    mgr.teardown()


@pytest.fixture(scope="module")
def dut_kube_config(dut_certs, duthost, vmhost):
    """Configure DUT for K8s (DNS, state DB, cgroup driver).

    Yields:
        DutKubeConfig: Configuration manager instance
    """
    cfg = DutKubeConfig(duthost, vmhost)
    cfg.setup()
    yield cfg
    cfg.teardown()


@pytest.fixture(scope="module")
def kube_client(minikube):
    """Return configured KubeClient with kubeconfig built in memory.

    Returns:
        KubeClient: Python K8s client connected to minikube
    """
    return KubeClient(kubeconfig_dict=minikube.get_kubeconfig_data())


@pytest.fixture(scope="module")
def dut_joined(dut_kube_config, kube_client, duthost):
    """Join DUT to cluster and verify.

    This fixture joins the DUT to the minikube cluster and waits for it
    to become ready. On teardown, it disjoins and waits for removal.

    Yields:
        None (use kube_client to interact with the cluster)
    """
    dut_kube_config.join()

    # Wait for node to appear and become ready
    assert wait_until(120, 10, 0, kube_client.is_node_ready, duthost.hostname), \
        f"DUT {duthost.hostname} did not become ready in cluster"

    yield

    dut_kube_config.disjoin()

    # Wait for node to be removed
    def node_gone():
        return not kube_client.node_exists(duthost.hostname)

    wait_until(60, 5, 0, node_gone)


@pytest.fixture(scope="module")
def kubesonic_cluster(minikube, dut_certs, dut_kube_config, kube_client, dut_joined, duthost, vmhost):
    """High-level fixture providing complete kubesonic test environment.

    This is the recommended fixture for most kubesonic tests. It sets up:
    - Minikube cluster on vmhost
    - Certificates installed on DUT
    - DUT configured and joined to the cluster
    - Python K8s client for verification

    Yields:
        dict: {
            'client': KubeClient instance,
            'minikube': MinikubeManager instance,
            'dut_config': DutKubeConfig instance,
            'cert_manager': CertManager instance,
            'duthost': DUT host fixture,
            'vmhost': VM host fixture
        }

    Example:
        def test_pod_deployment(kubesonic_cluster):
            client = kubesonic_cluster['client']
            duthost = kubesonic_cluster['duthost']

            # Verify DUT is in cluster
            assert client.is_node_ready(duthost.hostname)

            # Check pods on DUT node
            pods = client.get_pods(node_name=duthost.hostname)
    """
    yield {
        'client': kube_client,
        'minikube': minikube,
        'dut_config': dut_kube_config,
        'cert_manager': dut_certs,
        'duthost': duthost,
        'vmhost': vmhost
    }


# Autouse fixtures for log handling
@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(duthost, loganalyzer):
    """Ignore expected failure logs during kubesonic test execution.

    Kubernetes join attempts cause some expected failure logs when
    the master service is unreachable or during normal operation.
    """
    if loganalyzer:
        ignoreRegex = [
            ".*Max retries exceeded with url: /admin.conf.*",
            ".*for troubleshooting tips.*",
            ".*kubeproxy.*",
            ".*ctrmgrd.*",
        ]
        loganalyzer[duthost.hostname].ignore_regex.extend(ignoreRegex)
    yield
