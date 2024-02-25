import time
import logging
import pytest
import ptf.testutils as testutils

from dash_acl import check_dataplane, acl_fields_test, acl_multi_stage_test  # noqa: F401
from dash_acl import acl_tag_test, acl_multi_tag_test, acl_tag_order_test, acl_multi_tag_order_test  # noqa: F401
from dash_acl import acl_tag_update_ip_test, acl_tag_remove_ip_test, acl_tag_scale_test, acl_tag_not_exists_test  # noqa: F401
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


# flake8: noqa: F811
def test_acl_tag(
        ptfadapter,
        acl_tag_test,
        skip_dataplane_checking
        ):
    if skip_dataplane_checking:
        return
    check_dataplane(ptfadapter, acl_tag_test)


# flake8: noqa: F811
def test_acl_multi_tag(
        ptfadapter,
        acl_multi_tag_test,
        skip_dataplane_checking
        ):
    if skip_dataplane_checking:
        return
    check_dataplane(ptfadapter, acl_multi_tag_test)


# flake8: noqa: F811
def test_acl_tag_not_exists(
        ptfadapter,
        acl_tag_not_exists_test,
        skip_dataplane_checking
        ):
    if skip_dataplane_checking:
        return
    check_dataplane(ptfadapter, acl_tag_not_exists_test)


# flake8: noqa: F811
def test_acl_tag_order(
        ptfadapter,
        acl_tag_order_test,
        skip_dataplane_checking
        ):
    if skip_dataplane_checking:
        return
    check_dataplane(ptfadapter, acl_tag_order_test)


# flake8: noqa: F811
def test_acl_multi_tag_order(
        ptfadapter,
        acl_multi_tag_order_test,
        skip_dataplane_checking
        ):
    if skip_dataplane_checking:
        return
    check_dataplane(ptfadapter, acl_multi_tag_order_test)


# flake8: noqa: F811
def test_acl_tag_update_ip(
        ptfadapter,
        acl_tag_update_ip_test,
        skip_dataplane_checking
        ):
    if skip_dataplane_checking:
        return
    check_dataplane(ptfadapter, acl_tag_update_ip_test)


# flake8: noqa: F811
def test_acl_tag_remove_ip(
        ptfadapter,
        acl_tag_remove_ip_test,
        skip_dataplane_checking
        ):
    if skip_dataplane_checking:
        return
    check_dataplane(ptfadapter, acl_tag_remove_ip_test)


# flake8: noqa: F811
def test_acl_tag_scale(
        ptfadapter,
        acl_tag_scale_test,
        skip_dataplane_checking
        ):
    if skip_dataplane_checking:
        return
    check_dataplane(ptfadapter, acl_tag_scale_test)
