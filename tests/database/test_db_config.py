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
    pytest_assert(save_config["save"] == "", "Redis should not be persisting contents to disk, save config is {}".format(save_config["save"]))
