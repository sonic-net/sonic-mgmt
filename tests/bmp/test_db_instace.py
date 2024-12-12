"""
Test the database intance
"""
import logging
import pytest
import json

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]


def test_redis_instance(duthosts, rand_one_dut_hostname):
    """
    @summary: Test that redis has bmp instance
    """
    duthost = duthosts[rand_one_dut_hostname]
    result = duthost.command(argv=["ps", "aux", "|", "grep", "redis"])["stdout"]
    expected_substring = "/usr/bin/redis-server 127.0.0.1:6400"  
    pytest_assert (expected_substring in result, "BMP Redis instance is not launched correctly")


def test_redis_unix_socket(duthosts, rand_one_dut_hostname):
    """
    @summary: Test that redis has the unix socket option enabled
    """
    duthost = duthosts[rand_one_dut_hostname]

    unixsocket_config_json = duthost.command(argv=["redis-cli", "--json", "CONFIG", "GET", "unixsocket"])["stdout"]
    unixsocket_config = json.loads(unixsocket_config_json)
    pytest_assert(unixsocket_config["unixsocket"] == "/var/run/redis/redis_bmp.sock",
                  "Redis unixsocket is not configured correctly")
