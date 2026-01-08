import pytest

from tests.common.constants import CounterpollConstants
from tests.common.helpers.counterpoll_helper import ConterpollHelper
from tests.common.utilities import skip_release


@pytest.fixture(params=[CounterpollConstants.PORT_BUFFER_DROP])
def counterpoll_type(request):
    return request.param


@pytest.fixture()
def restore_counter_poll(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    parsed_counterpoll_before_multi_asic = {}
    skip_release(duthost, ["201811", "201911", "202012"])
    if duthost.is_multi_asic:
        for asic in duthost.asics:
            counter_poll_show = ConterpollHelper.get_counterpoll_show_output(duthost, asic)
            parsed_counterpoll_before_multi_asic[asic.asic_index] = (
                ConterpollHelper.get_parsed_counterpoll_show(counter_poll_show))
    else:
        counter_poll_show = ConterpollHelper.get_counterpoll_show_output(duthost)
        parsed_counterpoll_before = ConterpollHelper.get_parsed_counterpoll_show(counter_poll_show)

    yield
    if duthost.is_multi_asic:
        parsed_counterpoll_after_multi_asic = {}
        for asic in duthost.asics:
            counter_poll_show = ConterpollHelper.get_counterpoll_show_output(duthost, asic)
            parsed_counterpoll_after_multi_asic[asic.asic_index] = (
                ConterpollHelper.get_parsed_counterpoll_show(counter_poll_show))
            ConterpollHelper.restore_counterpoll_status(duthost, parsed_counterpoll_before_multi_asic[asic.asic_index],
                                                        parsed_counterpoll_after_multi_asic[asic.asic_index])
    else:
        counter_poll_show = ConterpollHelper.get_counterpoll_show_output(duthost)
        parsed_counterpoll_after = ConterpollHelper.get_parsed_counterpoll_show(counter_poll_show)
        ConterpollHelper.restore_counterpoll_status(duthost, parsed_counterpoll_before, parsed_counterpoll_after)
