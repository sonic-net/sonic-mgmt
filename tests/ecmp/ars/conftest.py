import pytest
import json
import os


@pytest.fixture(scope="session")
def base_ars_config():
    base_dir = os.path.dirname(__file__)
    ars_file = os.path.join(base_dir, "ars.json")
    with open(ars_file) as f:
        return json.load(f)


@pytest.fixture(scope="session")
def acl_config():
    base_dir = os.path.dirname(__file__)
    acl_file = os.path.join(base_dir, "acl.json")
    with open(acl_file) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def router_mac(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.facts["router_mac"]
