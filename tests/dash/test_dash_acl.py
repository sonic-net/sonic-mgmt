import time
import logging
import pytest
import ptf.testutils as testutils

from constants import *  # noqa: F403
import packets
from dash_acl import acl_test_pkts  # noqa: F401

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('appliance'),
    pytest.mark.disable_loganalyzer
]


def test_acl_fields(ptfadapter, apply_vnet_configs, acl_test_pkts):  # noqa: F811
    for pkt in acl_test_pkts:
        logger.info("Testing packet: {}".format(pkt.get_description()))
        _, vxlan_packet, expected_packet = packets.outbound_vnet_packets(pkt.dash_config_info,
                                                                         pkt.inner_extra_conf)
        testutils.send(ptfadapter,
                       pkt.dash_config_info[LOCAL_PTF_INTF],
                       vxlan_packet, 1)
        if pkt.expected_receiving:
            testutils.verify_packets_any(ptfadapter,
                                         expected_packet,
                                         ports=pkt.dash_config_info[REMOTE_PTF_INTF])
        else:
            testutils.verify_no_packet_any(ptfadapter,
                                           expected_packet,
                                           ports=pkt.dash_config_info[REMOTE_PTF_INTF])
        time.sleep(1)
