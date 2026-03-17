import pytest

from tests.common.constants import CounterpollConstants


@pytest.fixture(params=[CounterpollConstants.PORT_BUFFER_DROP])
def counterpoll_type(request):
    return request.param
