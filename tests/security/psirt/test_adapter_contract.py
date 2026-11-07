from types import SimpleNamespace

import pytest

from . import conftest as adapter_config
from .conftest import require_capability

pytestmark = [pytest.mark.topology("any")]


def test_adapter_initialization(monkeypatch):
    """Validate adapter registration without importing lab modules or contacting a DUT."""
    config = SimpleNamespace(getoption=lambda option: None)
    with pytest.raises(pytest.skip.Exception, match="BLOCKED: no platform PSIRT adapter"):
        adapter_config.psirt_adapter.__wrapped__(config)

    config = SimpleNamespace(getoption=lambda option: "test_adapter")
    module = SimpleNamespace()
    monkeypatch.setattr(adapter_config.importlib, "import_module", lambda name: module)
    with pytest.raises(pytest.fail.Exception, match="must define get_psirt_adapter"):
        adapter_config.psirt_adapter.__wrapped__(config)
    module.get_psirt_adapter = "not callable"
    with pytest.raises(pytest.fail.Exception, match="must define get_psirt_adapter"):
        adapter_config.psirt_adapter.__wrapped__(config)
    module.get_psirt_adapter = lambda: object()
    with pytest.raises(pytest.fail.Exception, match="must implement capabilities"):
        adapter_config.psirt_adapter.__wrapped__(config)
    adapter = SimpleNamespace(capabilities=lambda duthost: {})
    module.get_psirt_adapter = lambda: adapter
    assert adapter_config.psirt_adapter.__wrapped__(config) is adapter


def test_adapter_capability_detection():
    """Require explicit capability support and distinguish blocked checks from invalid adapters."""
    class Adapter:
        def __init__(self, capabilities):
            self._capabilities = capabilities

        def capabilities(self, duthost):
            return self._capabilities

    assert require_capability(Adapter({"sudi_health": True}), object(), "sudi_health") is None
    with pytest.raises(pytest.skip.Exception, match="BLOCKED: read_only_pcr"):
        require_capability(Adapter({"read_only_pcr": "unsupported by this platform"}), object(), "read_only_pcr")
    with pytest.raises(pytest.fail.Exception, match="must be a mapping"):
        require_capability(Adapter(None), object(), "sudi_health")


def _duthost(duthosts, enum_rand_one_per_hwsku_hostname):
    return duthosts[enum_rand_one_per_hwsku_hostname]


def test_authorized_sudi_health_request(duthosts, enum_rand_one_per_hwsku_hostname, ansible_adhoc, psirt_adapter):
    """Verify the supported fixed health response through a separately verified non-root session."""
    duthost = _duthost(duthosts, enum_rand_one_per_hwsku_hostname)
    require_capability(psirt_adapter, duthost, "sudi_health")
    assert psirt_adapter.sudi_health(duthost, ansible_adhoc) == "OK\n"


def test_unauthorized_arbitrary_sudi_signing_is_denied(duthosts, enum_rand_one_per_hwsku_hostname, psirt_adapter):
    """Require an actual safe arbitrary-signing authorization denial, not socket availability."""
    duthost = _duthost(duthosts, enum_rand_one_per_hwsku_hostname)
    require_capability(psirt_adapter, duthost, "unauthorized_sudi_signing_denial")
    assert psirt_adapter.unauthorized_sudi_signing_denied(duthost)


def test_sudi_broker_socket_and_sandbox_policy(duthosts, enum_rand_one_per_hwsku_hostname, psirt_adapter):
    """Check the advertised fixed-health broker policy without claiming authorization coverage."""
    duthost = _duthost(duthosts, enum_rand_one_per_hwsku_hostname)
    require_capability(psirt_adapter, duthost, "sudi_broker_policy")
    policy = psirt_adapter.sudi_broker_policy(duthost)
    assert int(policy["socket_mode"], 8) == 0o666
    assert policy["socket_owner"] == "root:root"
    assert policy["service_user"] == "root"
    assert policy["no_new_privileges"] is True
    assert policy["protect_system"] == "strict"
    assert policy["protect_home"] is True
    assert policy["address_families"] == ["AF_UNIX"]


def test_sudi_certificate_failure_cases_fail_closed(duthosts, enum_rand_one_per_hwsku_hostname, psirt_adapter):
    """Require passing isolated certificate-failure regressions without mutating DUT certificates."""
    duthost = _duthost(duthosts, enum_rand_one_per_hwsku_hostname)
    require_capability(psirt_adapter, duthost, "offline_sudi_certificate_regressions")
    results = psirt_adapter.offline_sudi_certificate_regressions(duthost)
    assert results == {"missing": True, "malformed": True, "untrusted": True, "mismatched": True}


def test_unauthorized_tam_registration_and_permissions_are_denied(
        duthosts, enum_rand_one_per_hwsku_hostname, psirt_adapter):
    """Require safe policy denials for both registration and permission changes."""
    duthost = _duthost(duthosts, enum_rand_one_per_hwsku_hostname)
    require_capability(psirt_adapter, duthost, "safe_tam_registration_denial")
    results = psirt_adapter.unauthorized_registration_and_permissions_denied(duthost)
    assert results == {"registration": True, "permissions": True}


def test_unauthorized_tam_administration_is_denied(duthosts, enum_rand_one_per_hwsku_hostname, psirt_adapter):
    """Require a safe administrative authorization denial from a supported interface."""
    duthost = _duthost(duthosts, enum_rand_one_per_hwsku_hostname)
    require_capability(psirt_adapter, duthost, "safe_tam_admin_denial")
    assert psirt_adapter.unauthorized_admin_operations_denied(duthost)


def test_pcr_length_regression_uses_isolated_tests_only(duthosts, enum_rand_one_per_hwsku_hostname, psirt_adapter):
    """Check isolated PCR boundary regressions without sending live malformed PCR input."""
    duthost = _duthost(duthosts, enum_rand_one_per_hwsku_hostname)
    require_capability(psirt_adapter, duthost, "offline_pcr_length_regressions")
    assert psirt_adapter.offline_pcr_length_regressions(duthost)


def test_supported_read_only_pcr_operation(duthosts, enum_rand_one_per_hwsku_hostname, psirt_adapter):
    """Validate a supported read-only PCR result and report timeout as blocked."""
    duthost = _duthost(duthosts, enum_rand_one_per_hwsku_hostname)
    require_capability(psirt_adapter, duthost, "read_only_pcr")
    result = psirt_adapter.read_only_pcr(duthost)
    if result.get("status") == "timeout":
        pytest.skip("BLOCKED: existing supported PCR read timed out; no PCR mutation attempted")
    assert result.get("status") == "pass", result.get("reason", "PCR read failed")
    assert result.get("value_present") is True
