from spytest import st

def init(dut):
    st.create_init_config_db(dut)

def extend(dut):
    st.log("Extend base config if needed", dut=dut)
    st.config(dut, "config feature state nat enabled")
    st.config(dut, "config feature state sflow enabled")

