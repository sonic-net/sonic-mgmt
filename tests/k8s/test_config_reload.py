import pytest
import time
import k8s_test_utilities as ku

from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.config_reload import config_reload

pytestmark = [
    pytest.mark.topology('any')
]

def test_config_reload_no_toggle(duthost, k8scluster):
    """
    Test case to ensure that when DUT starts as joined to master, and config is saved with disable=false, DUT is still joined to master after config reload
    
    Joins master

    Performs config reload

    Ensures that DUT is still joined to master after config reload

    Args:
        duthost: DUT host object
        k8scluster: shortcut fixture for getting cluster of Kubernetes master hosts
    """
    ku.join_master(duthost, k8scluster.vip) # Assertion within to ensure successful join
    duthost.shell('sudo config save -y')
    config_reload(duthost)
    wait_critical_processes(duthost)

    server_connect_exp_status = True
    server_connect_act_status = ku.check_connected(duthost)
    server_connect_status_updated = ku.poll_for_status_change(duthost, server_connect_exp_status)
    pytest_assert(server_connect_status_updated, "Unexpected k8s server connection status after config reload, Expected server connected status: {}, Found server connected status: {}".format(server_connect_exp_status, server_connect_act_status))


def test_config_reload_toggle_join(duthost, k8scluster):
    """
    Test case to ensure that when DUT is not joined to the master due to (unsaved) disable=true, but config is saved with disable=false, DUT joins after config reload

    Saves config with configured VIP and disable=false

    Sets disable=true without saving config, and ensure that DUT resets from master

    Performs config reload

    Ensures that DUT is joined to master after config reload

    Args:
        duthost: DUT host object
        k8scluster: shortcut fixture for getting cluster of Kubernetes master hosts
    """
    dut_cmds = ['sudo config kube server ip {}'.format(k8scluster.vip),
                'sudo config kube server disable off',
                'sudo config save -y']
    duthost.shell_cmds(cmds=dut_cmds)
  
    duthost.shell('sudo config kube server disable on')
    server_connect_exp_status = False
    server_connect_act_status = ku.check_connected(duthost)
    server_connect_status_updated = ku.poll_for_status_change(duthost, server_connect_exp_status)
    pytest_assert(server_connect_status_updated, "Unexpected k8s server connection status after setting disable=true, Expected server connected status: {}, Found server connected status: {}".format(server_connect_exp_status, server_connect_act_status))
    
    config_reload(duthost)
    wait_critical_processes(duthost)

    server_connect_exp_status = True
    server_connect_act_status = ku.check_connected(duthost)
    server_connect_status_updated = ku.poll_for_status_change(duthost, server_connect_exp_status)
    pytest_assert(server_connect_status_updated, "Unexpected k8s server connection status after config reload, Expected server connected status: {}, Found server connected status: {}".format(server_connect_exp_status, server_connect_act_status))


def test_config_reload_toggle_reset(duthost, k8scluster):
    """
    Test case to ensure that when DUT is joined to master (disable=false, unsaved) but config is saved with disable=true, DUT resets from master after config reload

    Saves config with disable=true

    Joins master, which sets disable=false unsaved

    Performs config reload

    Ensures that DUT has reset from the master after config reload, as disable=true was saved 
    
    Args:
        duthost: DUT host object
        k8scluster: shortcut fixture for getting cluster of Kubernetes master hosts
    """
    dut_cmds = ['sudo config kube server disable on',
                'sudo config save -y']
    duthost.shell_cmds(cmds=dut_cmds)

    ku.join_master(duthost, k8scluster.vip) 

    config_reload(duthost)
    wait_critical_processes(duthost)

    server_connect_exp_status = False
    server_connect_act_status = ku.check_connected(duthost)
    server_connect_status_updated = ku.poll_for_status_change(duthost, server_connect_exp_status)
    pytest_assert(server_connect_status_updated, "Unexpected k8s server connection status after config reload, Expected server connected status: {}, Found server connected status: {}".format(server_connect_exp_status, server_connect_act_status))
