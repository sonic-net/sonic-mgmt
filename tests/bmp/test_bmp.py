import pytest
import logging

from .helper import bmp_capabilities

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]


def test_bmp_capabilities(duthosts, rand_one_dut_hostname, localhost):
    '''
    Verify BMP capabilities
    '''
    duthost = duthosts[rand_one_dut_hostname]
    ret, msg = bmp_capabilities(duthost, localhost)
    assert ret == 0, msg
    assert "sonic-db" in msg, msg
    assert "JSON_IETF" in msg, msg
