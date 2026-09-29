import pytest

from tests.watermark.conftest import WatermarkTestBase, get_egress_queues_for_pgs


pytestmark = [pytest.mark.topology("t0", "t1", "lt2", "ft2")]


class PgSharedWatermarkTest(WatermarkTestBase):
    # Container-specific parameters for shared priority-group (PG) watermarks.
    CONTAINER = "priority-group"
    SUBTYPE = "shared"
    COLUMN_PREFIX = "PG"
    TC_MAP_NAME = "tc_to_pg_map"
    TC_MAP_TABLE = "TC_TO_PRIORITY_GROUP_MAP"
    # This is set higher than the queue watermark tolerance because the PG shared watermark value
    # may be lower than the queue watermark value on some SKUs.
    TOLERANCE = 10

    def get_container_ports(self, ingress_port, egress_ports):
        return [ingress_port]

    def get_queues_to_block(self, container_ids, duthost, ingress_port, egress_ports):
        return get_egress_queues_for_pgs(duthost, ingress_port, egress_ports, set(container_ids))


class TestPgSharedWatermarkIpv4(PgSharedWatermarkTest):
    IP_VERSION = "ipv4"


class TestPgSharedWatermarkIpv6(PgSharedWatermarkTest):
    IP_VERSION = "ipv6"
