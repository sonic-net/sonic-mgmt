import pytest
import logging

logger = logging.getLogger(__name__)


@pytest.fixture(autouse=True)
def check_k8s_vms(k8scluster):
    """
    This fixture runs before each k8s test to make sure that Kubernetes API server is reachable on all backend master servers
    This fixture also runs after each test to start kubelet if necessary- in case test code stopped kubelet, and test failed before reaching logic to start kubelet

    Args:
    k8scluster:  Shortcut fixture for getting Kubernetes master hosts
    """
    k8scluster.check_k8s_masters_ready()
    yield
    k8scluster.ensure_all_kubelet_running()


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(duthost, loganalyzer):
    """
       Ignore expected failures logs during test execution

       Kubernetes join attempt causes some expected failure logs when master service is unreachable

       Args:
           loganalyzer: Loganalyzer utility fixture
    """
    # When loganalyzer is disabled, the object could be None
    if loganalyzer:
         ignoreRegex = [
             ".*Max retries exceeded with url: /admin.conf.*",
             ".*for troubleshooting tips.*",
             ".*kubeproxy.*",
         ]
         loganalyzer[duthost.hostname].ignore_regex.extend(ignoreRegex)
    yield
