import pytest
from tests.common.helpers.assertions import pytest_require

pytestmark = [pytest.mark.topology("t0", "t1", "t2")]


def test_mgmt_ipv6_only_image_download(creds, duthost):
    """
    Test image download in mgmt ipv6 only scenario
    """
    image_url = creds.get("test_image_url", {}).get("ipv6", "")
    pytest_require(len(image_url) != 0, "Cannot get image url")
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    mgmt_interfaces = cfg_facts.get("MGMT_INTERFACE", {}).keys()
    for mgmt_interface in mgmt_interfaces:
        output = duthost.shell("curl --fail --interface {} {}".format(mgmt_interface, image_url),
                               module_ignore_errors=True)
        if output["rc"] == 0:
            break
    else:
        pytest.fail("Failed to download image from image_url {} via any of {}"
                    .format(image_url, list(mgmt_interfaces)))
