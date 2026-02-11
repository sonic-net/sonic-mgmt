"""Pytest fixtures for kubesonic tests using Python K8s client."""

import pytest
import logging

from tests.kubesonic.lib import MinikubeManager, CertManager, DutKubeConfig, KubeClient

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def minikube(vmhost, creds):
    """Setup minikube cluster on vmhost."""
    mgr = MinikubeManager(vmhost, creds)
    mgr.setup()
    yield mgr
    mgr.teardown()


@pytest.fixture(scope="module")
def dut_certs(minikube, vmhost, duthost):
    """Install certs on DUT."""
    mgr = CertManager(vmhost, duthost)
    mgr.setup()
    yield mgr
    mgr.teardown()


@pytest.fixture(scope="module")
def dut_kube_config(dut_certs, duthost, vmhost):
    """Configure DUT for K8s (DNS, state DB)."""
    cfg = DutKubeConfig(duthost, vmhost)
    cfg.setup()
    yield cfg
    cfg.teardown()


@pytest.fixture(scope="module")
def kube_client(minikube):
    """Return configured KubeClient with kubeconfig built in memory."""
    return KubeClient(kubeconfig_dict=minikube.get_kubeconfig_data())


@pytest.fixture(scope="module")
def dut_joined(dut_kube_config, kube_client, duthost):
    """Join DUT to cluster and verify."""
    dut_kube_config.join()
    assert kube_client.wait_for_node(duthost.hostname, timeout=120)
    yield
    dut_kube_config.disjoin()
    assert kube_client.wait_for_node_gone(duthost.hostname, timeout=60)
