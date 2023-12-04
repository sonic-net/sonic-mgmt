import time
import logging
import pytest
import ptf.testutils as testutils

from dash_acl import check_dataplane, acl_fields_test, acl_multi_stage_test  # noqa: F401

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('dpu'),
]


# flake8: noqa: F811
def test_acl_fields(
        ptfadapter,
        acl_fields_test,
        skip_dataplane_checking
        ):
    if skip_dataplane_checking:
        return
    check_dataplane(ptfadapter, acl_fields_test)


# flake8: noqa: F811
def test_acl_multi_stage(
        ptfadapter,
        acl_multi_stage_test,
        skip_dataplane_checking
        ):
    if skip_dataplane_checking:
        return
    check_dataplane(ptfadapter, acl_multi_stage_test)
