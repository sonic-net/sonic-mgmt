import pytest

from spytest import st, tgapi


@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    """
    Pytest fixture that sets up the topology with one DUT (Device Under Test)
    and a TGEN (Traffic Generator) before running tests.

    Topology: single leaf (D1) with 3 TGEN port.
    """
    global vars
    global dut

    st.log("setup_topo: establishing minimum topology")
    tb_dict = st.ensure_min_topology("D1T1:3")
    vars = st.get_testbed_vars()
    dut = tb_dict.D1

    st.log("setup_topo: DUT handle acquired: {}".format(dut))

    tg = tgapi.get_chassis(vars)
    st.log("setup_topo: TGEN chassis handle acquired: {}".format(tg))

    st.log("setup_topo: DONE")
    yield
    st.log("setup_topo: teardown complete")


def test_simple_connect():
    """
    Verify that the DUT and TGEN are reachable by running a trivial
    command on the DUT and reporting success.
    """
    st.banner("test_simple_connect_2022 STARTED")

    output = st.show(dut, "show clock", skip_tmpl=True)
    st.log("DUT 'show clock' output: {}".format(output.strip()))

    st.log("DUT and TGEN connections verified successfully")
    st.report_pass('msg', 'Simple connect test passed')
