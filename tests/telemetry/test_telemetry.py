import logging
import pytest

pytestmark = [
    pytest.mark.topology('any', 't1-multi-asic')
]

logger = logging.getLogger(__name__)

METHOD_SUBSCRIBE = "subscribe"


def invoke_py_cli_from_ptf(ptfhost, cmd, callback):
    ret = ptfhost.shell(cmd)
    assert ret["rc"] == 0, "PTF docker did not get a response"
    if callback is not None:
        callback(ret["stdout"])
