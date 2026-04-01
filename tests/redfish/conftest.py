import logging
import os

import pytest
import yaml

from tests.common.helpers.assertions import pytest_require as pyrequire

logger = logging.getLogger(__name__)

REDFISH_ROOT = "/redfish/v1"


@pytest.fixture(scope="module", autouse=True)
def is_bmc_present(request, tbinfo):
    """Skip the module if the target is not a BMC device.

    Checks the topology name from tbinfo. If the topology contains 'bmc'
    (e.g. bmc-dual-mgmt, bmc-shared-mgmt) the check passes immediately.
    Otherwise duthost.is_bmc() is consulted via DUT SSH.
    """
    if 'bmc' in tbinfo['topo']['name']:
        return
    duthosts = request.getfixturevalue("duthosts")
    hostname = request.getfixturevalue("enum_rand_one_per_hwsku_hostname")
    duthost = duthosts[hostname]
    pyrequire(duthost.is_bmc(),
              "DUT is not a BMC device (dut_type != NetworkBmc), skipping Redfish tests")


@pytest.fixture(scope="module")
def bmc_ip(tbinfo):
    """Return the BMC Redfish IP from testbed.yaml (bmc_ip field)."""
    ip = tbinfo.get("bmc_ip")
    pyrequire(ip, "bmc_ip field missing from testbed.yaml entry for this testbed")
    return ip


@pytest.fixture(scope="module")
def bmc_creds():
    """Return BMC credentials from ansible/group_vars/all/creds.yml.

    Uses sonic_login as the username and sonic_default_passwords[0] as
    the password — the same credentials used for SONiC device SSH access.
    """
    creds_file = os.path.join(
        os.path.dirname(__file__), "../../ansible/group_vars/all/creds.yml"
    )
    with open(creds_file) as f:
        creds_data = yaml.safe_load(f)
    default_passwords = creds_data.get("sonic_default_passwords", [])
    return {
        "user": creds_data.get("sonic_login"),
        "password": default_passwords[0] if default_passwords else None,
    }


@pytest.fixture(scope="module")
def redfish_base_url(bmc_ip):
    return "https://{}{}".format(bmc_ip, REDFISH_ROOT)
