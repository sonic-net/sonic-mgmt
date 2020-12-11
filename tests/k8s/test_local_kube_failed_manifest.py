import pytest
import logging
import time
import k8s_test_utilities as ku
from tests.common.utilities import wait_until

from tests.common.helpers.assertions import pytest_assert

WAIT_FOR_SYNC = 60

logger = logging.getLogger(__name__)


pytestmark = [
     pytest.mark.topology('any')
]

@pytest.mark.parametrize("feature", ["snmp", "dhcp_relay", "radv"])
def test_local_kube_failed_manifest(duthost, k8scluster, feature):
    """
    Test case to ensure DUT properly transitions from local mode to kube mode only when manifest is properly applied.
    If manifest application fails, feature should remain running in local mode until kube mode feature is properly made available. 

    Ensures that DUT is joined to Kubernetes master

    Applies invalid URL manifest for kube mode feature, ensures that feature continues running in local mode

    Stops feature service, ensures that feature stops as expected

    Starts feature service, ensures that feature starts as expected

    Fixes manifest URL and reapplies manifest, ensures feature transitions as expected 

    Args:
        duthost: DUT host object
        k8scluster: shortcut fixture for getting cluster of Kubernetes master hosts
        feature: SONiC feature under test
    """
    ku.join_master(duthost, k8scluster.vip) # Assertion within to ensure successful join
    
    local_version = int(ku.check_feature_version(duthost, feature))
    desired_feature_version = str(local_version + 1)
    ku.apply_manifest(duthost, k8scluster.vip, feature, desired_feature_version, False)
    
    duthost.shell('sudo config feature owner {} kube'.format(feature))

    time.sleep(WAIT_FOR_SYNC)
    pytest_assert(ku.is_service_running(duthost, feature), "{} service is not running".format(feature))
    
    current_running_version = ku.check_feature_version(duthost, feature)
    pytest_assert(str(local_version) == current_running_version, "{} feature version unexpectedly changed".format(feature))

    duthost.shell('sudo systemctl stop {}'.format(feature))
    pytest_assert(not ku.is_service_running(duthost, feature), "{} service is unexpectedly running".format(feature))

    duthost.shell('sudo systemctl start {}'.format(feature))
    pytest_assert(ku.is_service_running(duthost, feature), "{} service is not running".format(feature))

    ku.apply_manifest(duthost, k8scluster.vip, feature, desired_feature_version, True)
    
    pytest_assert(ku.poll_for_status_change(duthost, 'feature_owner', 'kube', feature), '{} feature owner failed to update to kube'.format(feature))
    pytest_assert(ku.is_service_running(duthost, feature), "{} service is not running".format(feature))
    running_feature_version = ku.check_feature_version(duthost, feature)
    pytest_assert(running_feature_version == desired_feature_version), "Unexpected {} feature version running. Expected feature version: {}, Found feature version: {}".format(feature, desired_feature_version, running_feature_version)

    duthost.shell('sudo config feature owner {} local'.format(feature))
    pytest_assert(ku.poll_for_status_change(duthost, 'feature_owner', 'local', feature), "Unexpected feature owner status")
    
