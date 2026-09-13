"""
gNOI File service tests over a native (PTF-free) mTLS gRPC client.

The File stub is reached via ``GnoiClient.channel`` (equivalently the
``client.file`` convenience property), demonstrating that new gNOI services
plug in without client changes.
"""
import logging

import pytest

from sonic_grpc.gnoi import file_pb2

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.skip_check_dut_health,
]


def test_gnoi_file_stat(gnoi_client):
    """gNOI File.Stat on a known DUT file returns a typed stat entry."""
    path = "/etc/hostname"
    response = gnoi_client.file.Stat(file_pb2.StatRequest(path=path), timeout=10)

    logger.info("gNOI File.Stat(%s) -> %s", path, response)
    pytest_assert(len(response.stats) >= 1, "File.Stat returned no stat entries")
    stat = response.stats[0]
    pytest_assert(
        stat.path == path,
        "File.Stat returned path {!r}, expected {!r}".format(stat.path, path),
    )
    pytest_assert(stat.size > 0, "File.Stat reported size 0 for {}".format(path))
