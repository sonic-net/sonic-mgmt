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
    inst = request.instance
    if inst is None:
        return
    fn = getattr(inst, "acl_stage", None)
    if callable(fn) and fn() == "egress":
        pytest.skip("Egress ACL everflow tests not supported with MACSEC on "
                    "\"{}\" ASICs".format(duthost.facts.get("asic_type")))
