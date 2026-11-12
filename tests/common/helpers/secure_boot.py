import pytest


def require_secure_boot(duthost):
    """Skip the test unless UEFI Secure Boot is enabled."""
    secure_boot_state = duthost.command("mokutil --sb-state", module_ignore_errors=True)
    if secure_boot_state["rc"] != 0 or "SecureBoot enabled" not in secure_boot_state["stdout"]:
        pytest.skip("Secure Boot is not enabled")
