"""
gNOI System service tests over a native (PTF-free) mTLS gRPC client.
"""
import logging
import time

import pytest

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
    # The gnoi_client fixture mutates GNMI CONFIG_DB (rolled back on teardown).
    # Without this marker the teardown core_dump_and_config_check flags the
    # change as drift and forces a config reload; there is no CLI flag for it.
    pytest.mark.skip_check_dut_health,
]


def test_gnoi_system_time(gnoi_client):
    """gNOI System.Time returns a plausible current timestamp (ns since epoch)."""
    from sonic_grpc.gnoi import system_pb2

    response = gnoi_client.system.Time(system_pb2.TimeRequest(), timeout=10)

    now_ns = time.time() * 1e9
    logger.info("gNOI System.Time -> %d ns", response.time)
    pytest_assert(response.time > 0, "System.Time returned a non-positive timestamp")
    # Allow a wide skew window (1 day) - this asserts a sane clock, not sync.
    pytest_assert(
        abs(response.time - now_ns) < 24 * 3600 * 1e9,
        "System.Time {} ns is not within a day of local time {} ns".format(
            response.time, int(now_ns)
        ),
    )
