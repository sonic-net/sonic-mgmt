import time
import logging
import pytest
import ptf.testutils as testutils

from dash_acl import check_dataplane, acl_fields_test, acl_multi_stage_test, check_tcp_rst_dataplane, acl_tcp_rst_test # noqa: F401
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


def test_acl_tcp_rst(
        ptfadapter,
        acl_tcp_rst_test
        ):
    """
    This case is to verify the two following scenarios when CT miss for TCP packet on Nvidia dpu
    1. CT miss +  No SYN packet(ACK) + ACL permit
    2. CT miss +  No SYN packet(ACK) + ACL deny
    Test steps:
    1. configure ACL permit for src:11.1.1.1/32, dst:20.2.2.2/32, src_port: 24563, dst_port: 80, protocol: tcp
    2. configure ACL deny for src:20.2.2.2/32, dst:11.1.1.1/32, src_port: 80, dst_port: 24563, protocol: tcp
    3. Send no SYN packet(ACK) matching ACL permit
    4. Check the TCP packet will be forwarded to the correct port
    5. Send no SYN packet(ACK) matching ACL Deny
    6. Check the TCP packet will be dropped, and the RST packet will be sent to the two ends
    """
    check_tcp_rst_dataplane(ptfadapter, acl_tcp_rst_test)
