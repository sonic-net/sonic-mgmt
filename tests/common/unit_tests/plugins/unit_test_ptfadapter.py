from types import SimpleNamespace

import pytest

from tests.common.plugins.ptfadapter import _get_ptf_nn_agent_ip


@pytest.mark.parametrize(
    ('host', 'expected'),
    [
        (SimpleNamespace(mgmt_ip='192.0.2.1'), '192.0.2.1'),
        (
            SimpleNamespace(mgmt_ip='2001:db8::1', _mgmt_ipv4='192.0.2.1'),
            '192.0.2.1',
        ),
        (
            SimpleNamespace(mgmt_ip='2001:db8::1', _mgmt_ipv4=None),
            '2001:db8::1',
        ),
    ],
)
def test_get_ptf_nn_agent_ip(host, expected):
    assert _get_ptf_nn_agent_ip(host) == expected
