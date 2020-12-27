from spytest import st

def init(dut):
    st.create_init_config_db(dut)

def remove_vlan_1(dut):
    if not st.is_feature_supported("sai-removes-vlan-1", dut):
        import apis.common.asic as asicapi
        asicapi.remove_vlan_1(dut)

def post_reboot(dut, is_upgrade=False):
    st.banner("Remove VLAN-1 post reboot", dut=dut)
    remove_vlan_1(dut)

def extend(dut):
    st.log("Extend base config if needed", dut=dut)
    if not st.is_feature_supported("nat-default-enabled", dut):
        st.config(dut, "config feature state nat enabled")
    if not st.is_feature_supported("sflow-default-enabled", dut):
        st.config(dut, "config feature state sflow enabled")
    #st.config(dut, "configure lldp status disabled", type='lldp')
    st.banner("Remove VLAN-1 in base config", dut=dut)
    remove_vlan_1(dut)

