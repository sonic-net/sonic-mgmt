import pytest


@pytest.fixture(scope="session")
def everflow_capabilities(duthosts):
    """Collect switch capability facts once for Everflow tests.

    Returns:
        dict: hostname -> switch capability dict (STATE_DB switch_capabilities)
    """
    caps = {}
    for dut in duthosts:
        facts = dut.switch_capabilities_facts()
        switch_caps = (facts
                       .get("ansible_facts", {})
                       .get("switch_capabilities", {})
                       .get("switch", {}))
        caps[dut.hostname] = switch_caps
    return caps
