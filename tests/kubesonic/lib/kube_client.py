"""Kubernetes Python client wrapper."""

import logging
import time
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

logger = logging.getLogger(__name__)


class KubeClient:
    """Kubernetes client wrapper for SONiC testing."""

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

    def node_exists(self, name):
        """Check if node exists."""
        try:
            self.v1.read_node(name)
            return True
        except ApiException as e:
            if e.status == 404:
                return False
            raise

    def is_node_ready(self, name):
        """Check if node is Ready."""
        try:
            node = self.v1.read_node(name)
            for cond in node.status.conditions:
                if cond.type == "Ready":
                    return cond.status == "True"
        except ApiException:
            pass
        return False

    def label_node(self, name, labels):
        """Add labels to node."""
        body = {"metadata": {"labels": labels}}
        return self.v1.patch_node(name, body)

    def remove_node_label(self, name, label_key):
        """Remove label from node."""
        body = {"metadata": {"labels": {label_key: None}}}
        return self.v1.patch_node(name, body)

    def get_pods_on_node(self, node_name, label_selector=None, namespace="default"):
        """Get pods on a specific node."""
        kwargs = {
            "namespace": namespace,
            "field_selector": f"spec.nodeName={node_name}"
        }
        if label_selector:
            kwargs["label_selector"] = label_selector
        return self.v1.list_namespaced_pod(**kwargs).items

    def wait_for_node(self, name, timeout=120, ready=True):
        """Wait for node to exist and be ready."""
        start = time.time()
        while time.time() - start < timeout:
            if self.node_exists(name):
                if not ready or self.is_node_ready(name):
                    return True
            time.sleep(5)
        return False

    def wait_for_node_gone(self, name, timeout=60):
        """Wait for node to be removed."""
        start = time.time()
        while time.time() - start < timeout:
            if not self.node_exists(name):
                return True
            time.sleep(5)
        return False

    def wait_for_pod_on_node(self, node_name, label_selector, timeout=60, namespace="default"):
        """Wait for pod to be running on node."""
        start = time.time()
        while time.time() - start < timeout:
            pods = self.get_pods_on_node(node_name, label_selector, namespace)
            for pod in pods:
                if pod.status.phase == "Running":
                    return pod
            time.sleep(5)
        return None

    def wait_for_pod_gone(self, node_name, label_selector, timeout=60, namespace="default"):
        """Wait for pod to be removed from node."""
        start = time.time()
        while time.time() - start < timeout:
            pods = self.get_pods_on_node(node_name, label_selector, namespace)
            if not pods:
                return True
            time.sleep(5)
        return False
