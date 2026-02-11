"""POC: Kubesonic tests using Python kubernetes client."""

import pytest
import logging

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health
]

DAEMONSET_LABEL = "deployDaemonset"
POD_LABEL_SELECTOR = "group=test-ds-pod"


class TestKubesonicPythonClient:
    """Test kubesonic functionality using Python K8s client."""

    def test_dut_joins_cluster(self, dut_joined, kube_client, duthost):
        """Verify DUT successfully joins the K8s cluster."""
        assert kube_client.node_exists(duthost.hostname)
        assert kube_client.is_node_ready(duthost.hostname)
        logger.info("DUT %s is Ready in cluster", duthost.hostname)

    def test_daemonset_deploys_on_label(self, dut_joined, kube_client, duthost):
        """Verify DaemonSet pod deploys when node is labeled."""
        # Label the node
        kube_client.label_node(duthost.hostname, {DAEMONSET_LABEL: "true"})
        logger.info("Labeled node %s with %s=true", duthost.hostname, DAEMONSET_LABEL)

        # Wait for pod
        pod = kube_client.wait_for_pod_on_node(
            duthost.hostname,
            label_selector=POD_LABEL_SELECTOR,
            timeout=60
        )
        pytest_assert(pod is not None, "DaemonSet pod did not deploy on DUT")
        logger.info("Pod %s is running on %s", pod.metadata.name, duthost.hostname)

        # Verify container on DUT
        result = duthost.shell("docker ps | grep mock-ds-container", module_ignore_errors=True)
        pytest_assert(result["stdout"] != "", "Container not found on DUT")

    def test_daemonset_removes_on_unlabel(self, dut_joined, kube_client, duthost):
        """Verify DaemonSet pod is removed when label is removed."""
        # Ensure labeled first
        kube_client.label_node(duthost.hostname, {DAEMONSET_LABEL: "true"})
        pod = kube_client.wait_for_pod_on_node(
            duthost.hostname,
            label_selector=POD_LABEL_SELECTOR,
            timeout=60
        )
        pytest_assert(pod is not None, "Setup failed: pod not deployed")

        # Remove label
        kube_client.remove_node_label(duthost.hostname, DAEMONSET_LABEL)
        logger.info("Removed label %s from node %s", DAEMONSET_LABEL, duthost.hostname)

        # Wait for pod removal
        gone = kube_client.wait_for_pod_gone(
            duthost.hostname,
            label_selector=POD_LABEL_SELECTOR,
            timeout=60
        )
        pytest_assert(gone, "DaemonSet pod was not removed after unlabeling")

        # Verify container removed from DUT
        result = duthost.shell("docker ps | grep mock-ds-container", module_ignore_errors=True)
        pytest_assert(result["stdout"] == "", "Container still running on DUT")
        logger.info("Pod successfully removed from %s", duthost.hostname)
