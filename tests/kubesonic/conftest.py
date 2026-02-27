"""Pytest fixtures for kubesonic tests.

Fixtures:
    minikube: Minikube cluster on vmhost with Python K8s client
    dut_joined_minikube: Ensures DUT is setup and joined to minikube cluster

Usage:
    # Manual control - use helper functions
    def test_manual(duthost, minikube):
        from tests.kubesonic.kubesonic_utils import setup_dut, join_cluster
        setup_dut(duthost, minikube.vmhost)
        join_cluster(duthost, minikube.vip)
        assert minikube.client.is_node_ready(duthost.hostname)

    # Auto setup/teardown (most common)
    def test_auto(duthost, minikube, dut_joined_minikube):
        assert minikube.client.is_node_ready(duthost.hostname)
"""

import pytest
import logging
from types import SimpleNamespace

from tests.common.kubesonic import MinikubeManager, KubeClient
from tests.kubesonic.kubesonic_utils import setup_dut, join_cluster, disjoin_cluster, cleanup_dut

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def minikube(vmhost, creds):
    """Minikube cluster on vmhost with Python K8s client.

    Yields:
        SimpleNamespace with:
            client: KubeClient instance
            vip: API server IP (vmhost management IP)
            vmhost: vmhost fixture reference
    """
    # Check for kube support before setting up
    mgr = MinikubeManager(vmhost, creds)
    mgr.setup()

    client = KubeClient(kubeconfig_dict=mgr.get_kubeconfig_data())

    cluster = SimpleNamespace(
        client=client,
        vip=vmhost.mgmt_ip,
        vmhost=vmhost,
        _mgr=mgr  # internal reference for advanced usage
    )

    yield cluster

    mgr.teardown()


@pytest.fixture(scope="module")
def dut_joined_minikube(minikube, duthost):
    """Ensure DUT is setup and joined to minikube cluster.

    This fixture:
    - Setup: Configures DUT (certs, DNS, cgroup) and joins to cluster
    - Teardown: Disjoins DUT and cleans up config

    Use with minikube fixture to access the cluster client.
    """
    # Check kube support
    result = duthost.shell(
        "systemctl list-unit-files ctrmgrd.service",
        module_ignore_errors=True
    )
    if "ctrmgrd.service" not in result.get("stdout", ""):
        pytest.skip("DUT does not have kubesonic support (ctrmgrd service not found)")

    setup_dut(duthost, minikube.vmhost)
    join_cluster(duthost, minikube.vip, vmhost=minikube.vmhost)

    yield

    disjoin_cluster(duthost)
    cleanup_dut(duthost)


# Autouse fixture for log handling
@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(duthost, loganalyzer):
    """Ignore expected failure logs during kubesonic test execution."""
    if loganalyzer:
        ignoreRegex = [
            ".*Max retries exceeded with url: /admin.conf.*",
            ".*for troubleshooting tips.*",
            ".*kubeproxy.*",
            ".*ctrmgrd.*",
        ]
        loganalyzer[duthost.hostname].ignore_regex.extend(ignoreRegex)
    yield
