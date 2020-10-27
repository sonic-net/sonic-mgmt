import pytest
import logging

logger = logging.getLogger(__name__)


@pytest.fixture(autouse=True)
def check_k8s_vms(k8shosts):
    """
    This fixture runs before each k8s test to make sure that Kubernetes API server is reachable on all backend master servers
    This fixture also runs after each test to start kubelet if necessary- in case test code stopped kubelet, and test failed before reaching logic to start kubelet

    Args:
    k8shosts:  Shortcut fixture for getting Kubernetes hosts
    """
    for i in range(1, len(k8shosts)):
        k8shost = k8shosts['m{}'.format(i)]['host']
        logger.info("Checking to make sure master and API server are reachable on {}".format(k8shost.hostname))
        assert k8shost.check_k8s_master_ready()
    yield
    for i in range(1, len(k8shosts)):
        k8shost = k8shosts['m{}'.format(i)]['host']
        logger.info("Making sure kubelet is started on {}".format(k8shost.hostname))
        kubelet_status = k8shost.shell("sudo systemctl status kubelet | grep 'Active: '")
        for line in kubelet_status["stdout_lines"]:
            if not "running" in line:
                k8shost.shell("sudo systemctl start kubelet")

