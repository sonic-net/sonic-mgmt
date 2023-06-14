import pytest
from tests.common.cisco_data import is_cisco_device


@pytest.fixture
def setup_cgm_alpha_cisco(duthost):
    if not is_cisco_device(duthost):
        return
    duthost.shell("mmuconfig -p pg_lossless_100000_300m_profile -a -6")
    yield
    duthost.shell("mmuconfig -p pg_lossless_100000_300m_profile -a -2")
