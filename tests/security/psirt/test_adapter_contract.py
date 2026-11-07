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
    module.get_psirt_adapter = object
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

    assert require_capability(Adapter({"security_health": True}), object(), "security_health") is None
    with pytest.raises(pytest.skip.Exception, match="BLOCKED: broker_policy"):
        require_capability(Adapter({"broker_policy": "unsupported by this platform"}), object(), "broker_policy")
    with pytest.raises(pytest.fail.Exception, match="must be a mapping"):
        require_capability(Adapter(None), object(), "security_health")


def _duthost(duthosts, enum_rand_one_per_hwsku_hostname):
    return duthosts[enum_rand_one_per_hwsku_hostname]


def test_authorized_security_health(duthosts, enum_rand_one_per_hwsku_hostname, ansible_adhoc, psirt_adapter):
    """Verify a supported non-mutating health check through an authorized non-root session."""
    duthost = _duthost(duthosts, enum_rand_one_per_hwsku_hostname)
    require_capability(psirt_adapter, duthost, "security_health")
    result = psirt_adapter.security_health(duthost, ansible_adhoc)
    assert isinstance(result, dict), "Security health result must be a mapping"
    if result.get("status") == "timeout":
        pytest.skip("BLOCKED: supported security health check timed out")
    assert result.get("status") == "pass", result.get("reason", "Security health check failed")


def test_security_broker_policy(duthosts, enum_rand_one_per_hwsku_hostname, psirt_adapter):
    """Inspect documented platform broker policy without sending management requests."""
    duthost = _duthost(duthosts, enum_rand_one_per_hwsku_hostname)
    require_capability(psirt_adapter, duthost, "broker_policy")
    checks = psirt_adapter.broker_policy(duthost)
    assert isinstance(checks, dict) and checks, "Broker policy must report named checks"
    assert all(value is True for value in checks.values()), "Broker policy checks failed: {}".format(checks)
