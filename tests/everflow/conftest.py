import pytest


@pytest.fixture(autouse=True)
def skip_egress_acl_everflow_on_dnx_macsec(request, duthosts, rand_one_dut_hostname,
                                           is_macsec_enabled_for_test):
    # Mirrors the egress-ACL skip in tests/acl/test_acl.py::stage: egress-ACL
    # everflow variants are not supported with MACsec on broadcom-dnx ASICs.
    if not is_macsec_enabled_for_test:
        return
    duthost = duthosts[rand_one_dut_hostname]
    if duthost.facts.get("platform_asic") != "broadcom-dnx":
        return
    cls = request.cls
    if cls is None:
        return
    fn = cls.__dict__.get("acl_stage")
    if callable(fn) and fn(cls) == "egress":
        pytest.skip("Egress ACL everflow tests not supported with MACSEC on "
                    "\"{}\" ASICs".format(duthost.facts.get("asic_type")))


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
