import pytest

from tests.platform_tests.counterpoll.counterpoll_constants import CounterpollConstants
from tests.platform_tests.counterpoll.counterpoll_helper import ConterpollHelper
from tests.common.utilities import skip_release


@pytest.fixture(params=[CounterpollConstants.PORT_BUFFER_DROP])
def counterpoll_type(request):
    return request.param


@pytest.fixture()
def restore_counter_poll(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    skip_release(duthost, ["201811", "201911", "202012"])

    counter_poll_show = ConterpollHelper.get_counterpoll_show_output(duthost)
    parsed_counterpoll_before = ConterpollHelper.get_parsed_counterpoll_show(counter_poll_show)
    yield
    counter_poll_show = ConterpollHelper.get_counterpoll_show_output(duthost)
    parsed_counterpoll_after = ConterpollHelper.get_parsed_counterpoll_show(counter_poll_show)
    ConterpollHelper.restore_counterpoll_status(duthost, parsed_counterpoll_before, parsed_counterpoll_after)
