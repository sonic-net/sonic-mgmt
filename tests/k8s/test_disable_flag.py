import pytest
import time
import k8s_test_utilities as ku

from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any')
]

def test_disable_flag(duthost, k8scluster):
    """
    Test case to ensure that kube server disable flag works as expected when toggled

    Joins master to set baseline state (disable=false, joined to master)

    Set disable=true, ensure DUT resets from master

    Set disable=false, ensure DUT joins master

    Args:
        duthost: DUT host object
        k8scluster: shortcut fixture for getting cluster of Kubernetes master hosts
    """
    ku.join_master(duthost, k8scluster.vip)

    duthost.shell('sudo config kube server disable on')
    server_connect_exp_status = False
    server_connect_act_status = ku.check_connected(duthost)
    server_connect_status_updated = ku.poll_for_status_change(duthost, server_connect_exp_status)
    pytest_assert(server_connect_status_updated, "Test disable flag failed, Expected server connected status: {}, Found server connected status: {}".format(server_connect_exp_status, server_connect_act_status))
    
    duthost.shell('sudo config kube server disable off')
    server_connect_exp_status = True
    server_connect_act_status = ku.check_connected(duthost)
    server_connect_status_updated = ku.poll_for_status_change(duthost, server_connect_exp_status)
    pytest_assert(server_connect_status_updated, "Test disable flag failed, Expected server connected status: {}, Found server connected status: {}".format(server_connect_exp_status, server_connect_act_status))
