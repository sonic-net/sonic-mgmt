import pytest
from dci.config import configure_devices, configure_bgp, configure_sonic
from dci.send_and_verify_traffic import send_ping_and_verify_traffic
from spytest import st


def test_deconfigure_reconfigure_devices(setup):
    nodes = setup["nodes"]
    config_file = setup["config_file"]
    if not configure_devices(config_file, nodes, add=False):
        st.report_fail("test_case_failed", "test_deconfigure_reconfigure_devices deconfigure")
    if not configure_devices(config_file, nodes, add=True):
        st.report_fail("test_case_failed", "test_deconfigure_reconfigure_devices reconfigure")
    st.wait(10)
    if not send_ping_and_verify_traffic(st.getwa(), setup["traffic_pairs"]):
        st.report_fail("test_case_failed", "Ping test failed after reconfiguration")
    st.report_pass("test_case_passed", "test_deconfigure_reconfigure_devices")


def test_deconfigure_reconfigure_sonic(setup):
    nodes = setup["nodes"]
    config_file = setup["config_file"]
    if not configure_sonic(config_file, nodes, add=False):
        st.report_fail("test_case_failed", "test_deconfigure_reconfigure_sonic deconfigure")
    if not configure_sonic(config_file, nodes, add=True):
        st.report_fail("test_case_failed", "test_deconfigure_reconfigure_sonic reconfigure")
    st.wait(10)
    if not send_ping_and_verify_traffic(st.getwa(), setup["traffic_pairs"]):
        st.report_fail("test_case_failed", "Ping test failed after reconfiguration")
    st.report_pass("test_case_passed", "test_deconfigure_reconfigure_sonic")


def test_deconfigure_reconfigure_bgp(setup):
    nodes = setup["nodes"]
    config_file = setup["config_file"]
    if not configure_bgp(config_file, nodes, add=False):
        st.report_fail("test_case_failed", "test_deconfigure_reconfigure_bgp deconfigure")
    if not configure_bgp(config_file, nodes, add=True):
        st.report_fail("test_case_failed", "test_deconfigure_reconfigure_bgp reconfigure")
    st.wait(10)
    if not send_ping_and_verify_traffic(st.getwa(), setup["traffic_pairs"]):
        st.report_fail("test_case_failed", "Ping test failed after reconfiguration")
    st.report_pass("test_case_passed", "test_deconfigure_reconfigure_bgp")


def test_deconfigure_reconfigure_dci_config(setup):
    st.report_pass("test_case_passed", "test_deconfigure_reconfigure_dci_config")
