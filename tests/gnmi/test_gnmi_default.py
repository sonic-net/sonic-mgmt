import pytest

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
]


def test_gnmi_enabled_by_default(duthosts, enum_rand_one_per_hwsku_hostname):
    '''
    Verify the gnmi feature is enabled by default.

    Deliberately queries FEATURE|gnmi directly, without GNMIEnvironment (which
    falls back to the telemetry container) and without the gNMI setup fixtures
    (which skip when the gnmi container is not running): the test must fail,
    not pass against FEATURE|telemetry or skip, when gnmi is disabled.
    '''
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    state = duthost.shell('sonic-db-cli CONFIG_DB HGET "FEATURE|gnmi" state')['stdout'].strip()
    assert state in ("enabled", "always_enabled"), "gnmi feature is not enabled by default, state={}".format(state)
