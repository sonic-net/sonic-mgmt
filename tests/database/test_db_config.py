"""
Test the database config
"""
import logging
import pytest
import json

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]


def test_redis_save_disabled(duthosts, rand_one_dut_hostname):
    """
    @summary: Test that the database isn't being saved to disk
    """
    duthost = duthosts[rand_one_dut_hostname]

    save_config_json = duthost.command(argv=["redis-cli", "--json", "CONFIG", "GET", "save"])["stdout"]
    save_config = json.loads(save_config_json)
    pytest_assert(save_config["save"] == "", "Redis should not be persisting contents to disk, save config is {}"
                  .format(save_config["save"]))


def test_redis_database_count(duthosts, rand_one_dut_hostname):
    """
    @summary: Test that redis is configured to support 100 databases
    """
    duthost = duthosts[rand_one_dut_hostname]

    database_config_json = duthost.command(argv=["redis-cli", "--json", "CONFIG", "GET", "databases"])["stdout"]
    database_config = json.loads(database_config_json)
    pytest_assert(database_config["databases"] == "100", "Redis is configured to support {} instead of 100 databases"
                  .format(database_config["databases"]))


def test_redis_unix_socket(duthosts, rand_one_dut_hostname):
    """
    @summary: Test that redis has the unix socket option enabled
    """
    duthost = duthosts[rand_one_dut_hostname]

    unixsocket_config_json = duthost.command(argv=["redis-cli", "--json", "CONFIG", "GET", "unixsocket"])["stdout"]
    unixsocket_config = json.loads(unixsocket_config_json)
    pytest_assert(unixsocket_config["unixsocket"] == "/var/run/redis/redis.sock",
                  "Redis unixsocket is not configured correctly")
