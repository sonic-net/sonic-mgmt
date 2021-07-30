from spytest import st

def _wait(dut, secs, msg):
    if st.is_vsonic(dut):
        st.wait(secs, msg)

def vsonic_mac_learn(dut=None, secs=10, msg="Wait for MAC Learning in vSONiC"):
    _wait(dut, secs, msg)

def vsonic_ip_apply(dut=None, secs=15, msg="Wait for IP Apply in vSONiC"):
    _wait(dut, secs, msg)

def arp_clear_on_link_down(dut=None, secs=2, msg="wait for ARP entries to be cleared"):
    if not st.is_feature_supported("arp-clear-nowait", dut):
        _wait(dut, secs, msg)
