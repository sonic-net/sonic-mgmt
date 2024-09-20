# Helper Functions
import pytest
from tests.common.utilities import run_show_features

pytestmark = [
    pytest.mark.topology('any')
]


def test_show_features(duthosts, enum_dut_hostname):
    run_show_features(duthosts, enum_dut_hostname)
