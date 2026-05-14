"""
Simple connectivity smoke test for the FX3 QoS testbeds.

This module exposes exactly one test function -- ``test_simple_connect``
-- which detects the active testbed shape at runtime and runs the
matching connectivity check.  The test reports only PASS or FAIL; it
never skips.

Supported topology shapes:

  * Non-breakout testbed:   D1T1:3 (single DUT, three TGEN ports).
                            Verifies the single DUT and TGEN are
                            reachable.

  * Breakout testbed:       D1T1:1 + D1D2:1 + D2T1:1 (two DUTs with a
                            broken-out peer link and one TGEN port
                            each).  Verifies both DUTs and the TGEN
                            are reachable.

If the active testbed matches neither shape, the test FAILs with an
explicit message naming the unrecognised shape -- this surfaces new
testbed topologies as actionable failures rather than silent skips.
"""

import pytest

from spytest import st, tgapi


# --- Module state -----------------------------------------------------------
# Populated by the autouse fixture; topology-agnostic.
vars = None


# --- Topology shape probes --------------------------------------------------

def _testbed_is_single_dut_d1t1_3():
    """True iff testbed is single-DUT with at least 3 D1<->T1 links.

    Single-DUT means D1D2P1 is *not* present (no peer DUT).  This is
    the non-breakout FX3 QoS testbed shape.
    """
    tb_preview = st.get_testbed_vars()
    for i in range(1, 4):
        if not hasattr(tb_preview, 'D1T1P{}'.format(i)):
            return False
    if hasattr(tb_preview, 'D1D2P1'):
        return False
    return True


def _testbed_is_d1d2_peer_link():
    """True iff testbed has a D1<->D2 peer link plus a TGEN port on
    each DUT.

    Requires D1D2P1, D2D1P1, D1T1P1, and D2T1P1 -- the minimum shape
    of the FX3 breakout testbed (D1T1:1 + D1D2:1 + D2T1:1).
    """
    tb_preview = st.get_testbed_vars()
    required = ('D1D2P1', 'D2D1P1', 'D1T1P1', 'D2T1P1')
    return all(hasattr(tb_preview, k) for k in required)


def _detect_topo_mode():
    """Classify the active testbed.

    Returns one of ``'breakout'``, ``'non_breakout'``, or
    ``'unsupported'``.  The breakout shape is checked first because
    it is the more constrained / specific match.
    """
    if _testbed_is_d1d2_peer_link():
        return 'breakout'
    if _testbed_is_single_dut_d1t1_3():
        return 'non_breakout'
    return 'unsupported'


# --- Fixture ----------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    """Cheap, topology-agnostic setup: resolve the TGEN chassis handle.

    No ``ensure_min_topology`` here -- the test function owns its own
    topology contract and calls ``ensure_min_topology`` itself once it
    has detected which shape is in play.  This keeps the fixture
    universally satisfiable so the test always runs.
    """
    global vars
    vars = st.get_testbed_vars()
    tg = tgapi.get_chassis(vars)
    st.log("setup_topo: TGEN chassis handle acquired: {}".format(tg))
    yield
    st.log("setup_topo: teardown complete")


# --- Test -------------------------------------------------------------------

def test_simple_connect():
    """Smoke test: verify DUT(s) and TGEN are reachable on the active
    FX3 QoS testbed.

    Detects the testbed shape at runtime and runs the matching check:
      * ``non_breakout`` (D1T1:3, no D2): ``show clock`` on D1.
      * ``breakout`` (D1T1:1 + D1D2:1 + D2T1:1): ``show clock`` on
        both D1 and D2.

    Reports only PASS or FAIL -- never SKIP.  An unrecognised testbed
    shape FAILs with an explicit message so the gap is visible in the
    regression report and easy to fix (one branch in
    ``_detect_topo_mode``).
    """
    mode = _detect_topo_mode()
    st.banner("test_simple_connect STARTED [mode={}]".format(mode))

    if mode == 'non_breakout':
        tb_dict = st.ensure_min_topology("D1T1:3")
        dut = tb_dict.D1
        st.log("DUT handle acquired: {}".format(dut))

        output = st.show(dut, "show clock", skip_tmpl=True)
        st.log("DUT 'show clock' output: {}".format(output.strip()))

        st.log("DUT and TGEN connections verified successfully")
        st.report_pass(
            'msg',
            'Simple connect [non_breakout] passed: D1 + TGEN reachable')
        return

    if mode == 'breakout':
        tb_dict = st.ensure_min_topology("D1T1:1", "D1D2:1", "D2T1:1")
        dut1 = tb_dict.D1
        dut2 = tb_dict.D2
        st.log("DUT handles acquired: D1={}, D2={}".format(dut1, dut2))

        out_d1 = st.show(dut1, "show clock", skip_tmpl=True)
        st.log("D1 'show clock' output: {}".format(out_d1.strip()))

        out_d2 = st.show(dut2, "show clock", skip_tmpl=True)
        st.log("D2 'show clock' output: {}".format(out_d2.strip()))

        st.log("D1, D2, and TGEN connections verified successfully")
        st.report_pass(
            'msg',
            'Simple connect [breakout] passed: D1 + D2 + TGEN reachable')
        return

    tb_preview = st.get_testbed_vars()
    present_keys = sorted(
        k for k in dir(tb_preview)
        if (k.startswith('D1T1P') or k.startswith('D2T1P')
            or k.startswith('D1D2P') or k.startswith('D2D1P')))
    st.log("Unsupported testbed shape; topology keys present: {}".format(
        present_keys))
    st.report_fail(
        'msg',
        'Simple connect FAILED: testbed shape not recognised '
        '(neither D1T1:3 single-DUT nor D1T1:1 + D1D2:1 + D2T1:1 '
        'two-DUT breakout); topology keys present: {}. '
        'Add the new shape to _detect_topo_mode() in '
        'test_simple_connect.py to support it.'.format(present_keys))
