import pytest

from tests.watermark.conftest import WatermarkTestBase


pytestmark = [pytest.mark.topology("t0", "t1", "lt2", "ft2")]


class QueueWatermarkTest(WatermarkTestBase):
    # Container-specific parameters for unicast queue watermarks.
    CONTAINER = "queue"
    SUBTYPE = "unicast"
    COLUMN_PREFIX = "UC"
    TC_MAP_NAME = "tc_to_queue_map"
    TC_MAP_TABLE = "TC_TO_QUEUE_MAP"
    TOLERANCE = 5

    def get_container_ports(self, ingress_port, egress_ports):
        return egress_ports

    def get_queues_to_block(self, container_ids, duthost, ingress_port, egress_ports):
        return list(container_ids)


class TestQueueWatermarkIpv4(QueueWatermarkTest):
    IP_VERSION = "ipv4"


class TestQueueWatermarkIpv6(QueueWatermarkTest):
    IP_VERSION = "ipv6"
