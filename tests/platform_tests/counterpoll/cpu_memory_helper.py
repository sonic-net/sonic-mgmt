import pytest

from tests.platform_tests.counterpoll.counterpoll_constants import CounterpollConstants
from tests.platform_tests.counterpoll.counterpoll_helper import ConterpollHelper


@pytest.fixture(params=[CounterpollConstants.WATERMARK,
                        CounterpollConstants.PORT_BUFFER_DROP,
                        CounterpollConstants.PORT,
                        CounterpollConstants.QUEUE,
                        CounterpollConstants.PG_DROP,
                        CounterpollConstants.RIF])
def counterpoll_type(request):
    return request.param


@pytest.fixture()
def restore_counter_poll(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if "201811" in duthost.os_version or "201911" in duthost.os_version or "202012" in duthost.os_version:
        pytest.skip("Test is supported for 202106 and later images. Skipping the test")
    counter_poll_show = ConterpollHelper.get_counterpoll_show_output(duthost)
    parsed_counterpoll_before = ConterpollHelper.get_parsed_counterpoll_show(counter_poll_show)
    yield
    counter_poll_show = ConterpollHelper.get_counterpoll_show_output(duthost)
    parsed_counterpoll_after = ConterpollHelper.get_parsed_counterpoll_show(counter_poll_show)
    ConterpollHelper.restore_counterpoll_interval(duthost, parsed_counterpoll_before, parsed_counterpoll_after)
    ConterpollHelper.restore_counterpoll_status(duthost, parsed_counterpoll_before, parsed_counterpoll_after)
