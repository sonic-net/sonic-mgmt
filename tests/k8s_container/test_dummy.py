"""Show the minimal KubeSonic contract for another SONiC container."""

import pytest

from tests.k8s_container.dut_selection import select_kubesonic_duthost


pytest_plugins = ("tests.k8s_container.dummy_provider",)

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
        pytest.fail(
            "Kubernetes dummy qualification requires a frontend DUT"
        )
    if duthost.facts.get("num_asic") != 1:
        pytest.fail(
            "Kubernetes dummy qualification currently supports one ASIC"
        )
    if duthost.facts.get("router_subtype") == "SmartSwitch":
        pytest.fail(
            "Kubernetes dummy qualification targets generic switches"
        )
    return duthost


def test_kubernetes_dummy_readiness(kubernetes_dummy_workload):
    """Verify the image-native dummy process reports ready."""

    result = kubernetes_dummy_workload.exec(
        "dummyk8s",
        ["/bin/bash", "/usr/bin/readiness-probe.sh"],
    )

    assert result.rc == 0, result.stderr
