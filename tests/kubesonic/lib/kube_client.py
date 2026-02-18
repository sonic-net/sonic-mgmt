"""Kubernetes Python client wrapper."""

import logging
import time
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

logger = logging.getLogger(__name__)


def wait_until(condition, timeout=60, interval=5):
    """Wait until condition() returns truthy value.

    Args:
        condition: Callable that returns truthy value when done
        timeout: Max seconds to wait
        interval: Seconds between checks

    Returns:
        The truthy result from condition(), or None if timeout
    """
    start = time.time()
    while time.time() - start < timeout:
        result = condition()
        if result:
            return result
        time.sleep(interval)
    return None


class KubeClient:
    """Minimal Kubernetes client wrapper."""

    def __init__(self, kubeconfig_dict=None, kubeconfig_path=None):
        """Initialize K8s client.

        Args:
            kubeconfig_dict: Kubeconfig as dict (preferred - no files needed)
            kubeconfig_path: Path to kubeconfig file (fallback)
        """
        if kubeconfig_dict:
            config.load_kube_config_from_dict(kubeconfig_dict)
        elif kubeconfig_path:
            config.load_kube_config(config_file=kubeconfig_path)
        else:
            config.load_kube_config()
        self.v1 = client.CoreV1Api()
        self.apps_v1 = client.AppsV1Api()

    def get_node(self, name):
        """Get node or None if not found."""
        try:
            return self.v1.read_node(name)
        except ApiException as e:
            if e.status == 404:
                return None
            raise

    def node_exists(self, name):
        """Check if node exists."""
        return self.get_node(name) is not None

    def is_node_ready(self, name):
        """Check if node exists and is Ready."""
        node = self.get_node(name)
        if not node:
            return False
        for cond in node.status.conditions or []:
            if cond.type == "Ready":
                return cond.status == "True"
        return False

    def get_pods(self, namespace="default", node_name=None, label_selector=None):
        """Get pods with optional filters."""
        kwargs = {"namespace": namespace}
        if node_name:
            kwargs["field_selector"] = f"spec.nodeName={node_name}"
        if label_selector:
            kwargs["label_selector"] = label_selector
        return self.v1.list_namespaced_pod(**kwargs).items
