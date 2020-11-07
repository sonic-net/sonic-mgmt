import pytest
import logging

logger = logging.getLogger(__name__)


@pytest.fixture(autouse=True)
def check_k8s_vms(k8smasters):
    """
    This fixture runs before each k8s test to make sure that Kubernetes API server is reachable on all backend master servers
    This fixture also runs after each test to start kubelet if necessary- in case test code stopped kubelet, and test failed before reaching logic to start kubelet

    Args:
    k8smasters:  Shortcut fixture for getting Kubernetes master hosts
    """
    for i in range(1, len(k8smasters)):
        k8smaster = k8smasters['m{}'.format(i)]['host']
        logger.info("Checking to make sure master and API server are reachable on {}".format(k8smaster.hostname))
        assert k8smaster.check_k8s_master_ready()
    yield
    for i in range(1, len(k8smasters)):
        k8smaster = k8smasters['m{}'.format(i)]['host']
        logger.info("Making sure kubelet is started on {}".format(k8smaster.hostname))
        kubelet_status = k8smaster.shell("sudo systemctl status kubelet | grep 'Active: '", module_ignore_errors=True)
        for line in kubelet_status["stdout_lines"]:
            if not "running" in line:
                k8smaster.shell("sudo systemctl start kubelet")

@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(duthost, loganalyzer):
    """
       Ignore expected failures logs during test execution

       Kubernetes join attempt causes some expected failure logs when master service is unreachable

       Args:
           duthost: DUT fixture
           loganalyzer: Loganalyzer utility fixture
    """
    # When loganalyzer is disabled, the object could be None
    if loganalyzer:
         ignoreRegex = [
             ".*Max retries exceeded with url: /admin.conf.*",
             ".*for troubleshooting tips.*",
             ".*kubeproxy.*",
         ]
         loganalyzer.ignore_regex.extend(ignoreRegex)
    yield
