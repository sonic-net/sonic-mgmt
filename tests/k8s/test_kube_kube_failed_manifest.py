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
def test_kube_kube_failed_manifest(duthost, k8scluster, feature):
    """
    Test case to ensure DUT properly responds to failed manifest application to upgrade kube mode feature to v200. 
    Kube mode feature v111 should continue running until v200 manifest is successfully applied.

    Ensures that DUT is joined to Kubernetes master

    Applies valid manifest for kube mode feature, expect transition from local to kube mode v111 once image is downloaded from registry

    Applies invalid manifest for kube mode feature, expect kube mode feature to continue running v111

    Stops feature service, ensures that feature stops as expected

    Starts feature service, ensures that feature starts as expected

    Fixes manifest URL and reapplies manifest, expect kube mode feature to start running v200

    Args:
        duthost: DUT host object
        k8scluster: shortcut fixture for getting cluster of Kubernetes master hosts
        feature: SONiC feature under test
    """

    ku.join_master(duthost, k8scluster.vip)

    local_version = int(ku.check_feature_version(duthost, feature))
    desired_feature_version = str(local_version + 1)
    ku.apply_manifest(duthost, k8scluster.vip, feature, desired_feature_version, True)

    duthost.shell('sudo config feature owner {} kube'.format(feature))
    pytest_assert(ku.poll_for_status_change(duthost, 'feature_owner', 'kube', feature), '{} feature owner failed to update to kube'.format(feature))
    pytest_assert(ku.is_service_running(duthost, feature), "{} service is not running".format(feature))
    running_feature_version = ku.check_feature_version(duthost, feature)
    pytest_assert(running_feature_version == desired_feature_version), "Unexpected {} version running. Expected feature version: {}, Found feature version: {}".format(feature, desired_feature_version, running_feature_version)

    desired_feature_version=str(local_version + 2)
    ku.apply_manifest(duthost, k8scluster.vip, feature, desired_feature_version, False)
    
    time.sleep(WAIT_FOR_SYNC)
    pytest_assert(ku.is_service_running(duthost, feature), "{} service is not running".format(feature))

    duthost.shell('sudo systemctl stop {}'.format(feature))
    pytest_assert(not ku.is_service_running(duthost, feature), "{} service is unexpectedly running".format(feature))

    duthost.shell('sudo systemctl start {}'.format(feature))
    pytest_assert(ku.poll_for_status_change(duthost, 'feature_owner', 'local', feature), '{} feature owner failed to update to local'.format(feature))
    pytest_assert(ku.is_service_running(duthost, feature), "{} service failed to start".format(feature))
    running_feature_version = ku.check_feature_version(duthost, feature)
    pytest_assert(int(running_feature_version) < int(desired_feature_version), "Upgrade feature version request unexpectedly went through from {} to {}".format(running_feature_version, desired_feature_version))


    ku.apply_manifest(duthost, k8scluster.vip, feature, desired_feature_version, True)
    pytest_assert(ku.poll_for_status_change(duthost, 'feature_owner', 'kube', feature), '{} feature owner failed to update to local'.format(feature))
    pytest_assert(ku.is_service_running(duthost, feature), "{} service is not running".format(feature))
    running_feature_version = ku.check_feature_version(duthost, feature)
    pytest_assert(running_feature_version == desired_feature_version, "Unexpected feature version running")

    duthost.shell('sudo config feature owner {} local'.format(feature))
    pytest_assert(ku.poll_for_status_change(duthost, 'feature_owner', 'local', feature), "Unexpected feature owner status")
