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
def test_local_kube_success_manifest(duthost, k8scluster, feature):
    """
    Test case to ensure DUT properly transitions between local mode and kube mode when manifest is properly applied.

    Ensures that DUT is joined to Kubernetes master

    Applies valid manifest for kube mode feature, expect transition from local to kube mode once image is downloaded from ACR

    Configure owner back to local mode, expect transition from kube to local mode

    Configure owner back to kube mode, expect transition from local to kube mode with previously downloaded kube mode image

    Args:
        duthost: DUT host object
        k8scluster: shortcut fixture for getting cluster of Kubernetes master hosts
        feature: SONiC feature under test
    """

    ku.join_master(duthost, k8scluster.vip) # Assertion within to ensure successful join
    
    local_version = int(ku.check_feature_version(duthost, feature))
    desired_feature_version = str(local_version + 1)
    ku.apply_manifest(duthost, k8scluster.vip, feature, desired_feature_version, True)

    duthost.shell('sudo config feature owner {} kube'.format(feature))
    pytest_assert(ku.poll_for_status_change(duthost, 'feature_owner', 'kube', feature), '{} feature owner failed to update to kube as expected'.format(feature))
    pytest_assert(ku.is_service_running(duthost, feature), "{} service is not running".format(feature))
    running_feature_version = ku.check_feature_version(duthost, feature)
    pytest_assert(running_feature_version == desired_feature_version), "Unexpected {} feature version running. Expected feature version: {}, Found feature version: {}".format(feature, desired_feature_version, running_feature_version)

    duthost.shell('sudo config feature owner {} local'.format(feature))
    pytest_assert(ku.poll_for_status_change(duthost, 'feature_owner', 'local', feature), "Unexpected feature owner status")
    pytest_assert(ku.is_service_running(duthost, feature), "{} service is not running".format(feature))
    running_feature_version = ku.check_feature_version(duthost, feature)
    pytest_assert((running_feature_version == str(local_version)), "Unexpected {} feature version running. Expected feature version: {}, Found feature version: {}".format(feature, desired_feature_version, running_feature_version))

    duthost.shell('sudo config feature owner {} kube'.format(feature))
    pytest_assert(ku.poll_for_status_change(duthost, 'feature_owner', 'kube', feature), "Unexpected feature owner status")
    pytest_assert(ku.is_service_running(duthost, feature), "{} service is not running".format(feature))
    running_feature_version = ku.check_feature_version(duthost, feature)
    pytest_assert(running_feature_version == desired_feature_version), "Unexpected {} feature version running. Expected feature version: {}, Found feature version: {}".format(feature, desired_feature_version, running_feature_version)

    time.sleep(WAIT_FOR_SYNC)
    duthost.shell('sudo config feature owner {} local'.format(feature))
    pytest_assert(ku.poll_for_status_change(duthost, 'feature_owner', 'local', feature), "Unexpected feature owner status")
