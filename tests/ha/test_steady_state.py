import pytest   # noqa: F401

from common.ha.smartswitch_ha_dataplane_utils import send_traffic_with_action   # noqa: F401
from common.ha.smartswitch_ha_helper import npu_zero, npu_one                   # noqa: F401


def test_steady_state_active(setup_namespaces_with_routes, deploy_files,
                             npu_zero, npu_one, send_traffic_with_action):      # noqa: F811
    """
    Verify normal operation in healthy state. Traffic lands on active DUT.
    """

    send_traffic_with_action(npu_zero, verify=True, allowed_disruption_duration=0,
                             allowed_disruption_count=0, action=None,
                             send_interval=0.01, stop_after=60)
