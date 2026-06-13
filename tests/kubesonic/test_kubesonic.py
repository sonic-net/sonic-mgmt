"""Kubesonic integration tests.

Tests SONiC Kubernetes integration using minikube cluster on vmhost.
"""

import pytest
import logging

from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
]


class TestKubesonic:
    """Kubesonic integration tests."""

    def test_dut_node_ready(self, duthost, minikube, dut_joined_minikube):
        """Verify DUT appears in cluster and is Ready."""
        assert minikube.client.node_exists(duthost.hostname), \
            f"DUT {duthost.hostname} not found in cluster"
        assert minikube.client.is_node_ready(duthost.hostname), \
            f"DUT {duthost.hostname} not Ready"

    def test_daemonset_scheduling(self, duthost, minikube, dut_joined_minikube):
        """Verify DaemonSet pods schedule on DUT when labeled."""
        client = minikube.client
        node_name = duthost.hostname

        # Label node to trigger DaemonSet scheduling
        logger.info("Labeling node %s with deployDaemonset=true", node_name)
        client.label_node(node_name, {"deployDaemonset": "true"})

        try:
            # Wait for pod to be scheduled
            def pod_running_on_node():
                pods = client.get_pods(
                    namespace="default",
                    node_name=node_name,
                    label_selector="group=test-ds-pod"
                )
                for pod in pods:
                    if pod.status.phase == "Running":
                        return True
                return False

            assert wait_until(60, 5, 0, pod_running_on_node), \
                f"DaemonSet pod not running on {node_name}"

            # Verify container on DUT (use docker ps without format to avoid Jinja2 escaping)
            result = duthost.shell(
                "docker ps | grep -q pause",
                module_ignore_errors=True
            )
            assert result.get("rc", 1) == 0, "Pause container not found on DUT"

        finally:
            # Remove label to clean up
            logger.info("Removing deployDaemonset label from %s", node_name)
            client.unlabel_node(node_name, ["deployDaemonset"])

    def test_daemonset_removal(self, duthost, minikube, dut_joined_minikube):
        """Verify DaemonSet pods are removed when label is removed."""
        client = minikube.client
        node_name = duthost.hostname

        # Label node
        client.label_node(node_name, {"deployDaemonset": "true"})

        # Wait for pod
        def pod_exists():
            pods = client.get_pods(
                namespace="default",
                node_name=node_name,
                label_selector="group=test-ds-pod"
            )
            return len(pods) > 0

        assert wait_until(60, 5, 0, pod_exists), "Pod not scheduled"

        # Remove label
        logger.info("Removing deployDaemonset label")
        client.unlabel_node(node_name, ["deployDaemonset"])

        # Wait for pod removal
        def pod_gone():
            pods = client.get_pods(
                namespace="default",
                node_name=node_name,
                label_selector="group=test-ds-pod"
            )
            return len(pods) == 0

        assert wait_until(60, 5, 0, pod_gone), \
            "DaemonSet pod not removed after unlabeling"

    def test_kube_server_status(self, duthost, dut_joined_minikube):
        """Verify DUT shows connected status."""
        result = duthost.shell("show kube server status")
        assert "true" in result["stdout"].lower(), \
            "DUT not showing connected status"
