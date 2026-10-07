"""Qualify the Kubernetes container infrastructure with a gNMI workload."""

import pytest

from tests.common.helpers.gnmi_utils import gnmi_capabilities
from tests.k8s_container.dut_selection import select_kubesonic_duthost


pytest_plugins = ("tests.k8s_container.gnmi_provider",)

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.disable_loganalyzer,
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.skip_check_dut_health,
]


@pytest.fixture(scope="module")
def minikube_duthost(request, duthosts):
    duthost = select_kubesonic_duthost(request, duthosts)
    if not duthost.sonichost.is_frontend_node():
        pytest.fail("Kubernetes gNMI qualification requires a frontend DUT")
    if duthost.facts.get("num_asic") != 1:
        pytest.fail("Kubernetes gNMI qualification currently supports one ASIC")
    return duthost


def test_kubernetes_gnmi_capabilities(minikube_duthost, localhost, kubernetes_gnmi_workload):
    result, output = gnmi_capabilities(minikube_duthost, localhost)
    assert result == 0, output
    assert "sonic-db" in output
    assert "JSON_IETF" in output
