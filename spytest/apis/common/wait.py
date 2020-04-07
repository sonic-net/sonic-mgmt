from spytest import st

def _wait(dut, secs):
    if st.is_vsonic(dut):
        st.wait(secs)

def mac_learn(dut=None, secs=10):
    _wait(dut, secs)

def tgen_stats(dut=None, secs=15):
    _wait(dut, secs)

def tgen_send(dut=None, secs=15):
    _wait(dut, secs)

def nat_stats(dut=None, secs=10):
    _wait(dut, secs)

