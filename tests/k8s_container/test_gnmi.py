"""Qualify the Kubernetes container infrastructure with a gNMI workload."""

import pytest

from tests.common.helpers.gnmi_utils import gnmi_capabilities


pytest_plugins = ("tests.k8s_container.gnmi_provider",)

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.disable_loganalyzer,
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.skip_check_dut_health,
]


@pytest.fixture(scope="module")
def minikube_duthost(rand_selected_dut):
    if not rand_selected_dut.sonichost.is_frontend_node():
        pytest.skip("Kubernetes gNMI qualification requires a frontend DUT")
    if rand_selected_dut.facts.get("num_asic") != 1:
        pytest.skip("Kubernetes gNMI qualification currently supports one ASIC")
    return rand_selected_dut


def test_kubernetes_gnmi_capabilities(minikube_duthost, localhost, kubernetes_gnmi_workload):
    result, output = gnmi_capabilities(minikube_duthost, localhost)
    assert result == 0, output
    assert "sonic-db" in output
    assert "JSON_IETF" in output
