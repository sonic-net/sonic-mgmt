import pytest
import time
import k8s_test_utilities as ku

from tests.common.helpers.assertions import pytest_assert

WAIT_FOR_SYNC = 60

pytestmark = [
    pytest.mark.topology('any')
]

def test_join_available_master(duthost, k8scluster):
    """
    Test case to ensure DUT properly joins Kubernetes master once VIP and API servers are both reachable

    Makes VIP unreachable

    Attempts to join DUT by configuring VIP and enabling kube server connection

    Ensures that DUT joins master once VIP is reachable

    Args:
        duthost: DUT host object
        k8scluster: shortcut fixture for getting cluster of Kubernetes master hosts
    """
    duthost.shell('sudo config kube server disable on')
    time.sleep(WAIT_FOR_SYNC)
    
    server_connect_exp_status = False
    server_connect_act_status = ku.check_connected(duthost)
    pytest_assert(server_connect_exp_status == server_connect_act_status, "DUT shows unexpected kubernetes server connected status, Expected server connected status: {}, Found server connected status: {}".format(server_connect_exp_status, server_connect_act_status))
    
    ku.make_vip_unreachable(duthost, k8scluster.vip)
    duthost.shell('sudo config kube server disable off') 
    duthost.shell('sudo config kube server ip {}'.format(k8scluster.vip))
    time.sleep(WAIT_FOR_SYNC)
    
    server_connect_exp_status = False
    server_connect_act_status = ku.check_connected(duthost)
    pytest_assert(server_connect_exp_status == server_connect_act_status, "DUT shows unexpected kubernetes server connected status, Expected server connected status: {}, Found server connected status: {}".format(server_connect_exp_status, server_connect_act_status))

    ku.make_vip_reachable(duthost, k8scluster.vip)

    server_connect_exp_status = True
    server_connect_act_status = ku.check_connected(duthost)
    server_connect_status_updated = ku.poll_for_status_change(duthost, server_connect_exp_status)
    pytest_assert(server_connect_status_updated, "DUT join available master failed, Expected server connected status: {}, Found server connected status: {}".format(server_connect_exp_status, server_connect_act_status))
