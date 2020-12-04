
from spytest import st

def _session_init(scope):

    def f(dut, scope):
        if st.get_device_type(dut) in ["sonic", "vsonic"]:
            st.banner("apis_instrument: {}".format(scope), dut=dut)
            st.show(dut, "show version", skip_error_check=True,
                     skip_tmpl=True)
            st.show(dut, "show runningconfiguration all",
                     skip_error_check=True, skip_tmpl=True)
            if st.is_feature_supported("system-status", dut):
                st.show(dut, "show system status", skip_error_check=True,
                         skip_tmpl=True)
    st.exec_each(st.get_dut_names(), f, scope)

def _show_runcfg(scope, data):
    st.banner("apis_instrument: {} {}".format(scope, data), dut=data)
    st.show(data, "show runningconfiguration all",
             skip_error_check=True, skip_tmpl=True)

def apis_instrument(scope, data):
    if st.getenv("SPYTEST_API_INSTRUMENT_SUPPORT", "0") == "0":
        return
    if scope in ["session-init-start", "session-init-end"]:
        _session_init(scope)
    elif scope in ["session-clean-start", "session-clean-end"]:
        pass
    elif scope in ["init-config-start", "init-config-end"]:
        _show_runcfg(scope, data)
    elif scope in ["apply-base-config-dut", "apply-base-config-dut-start", "apply-base-config-dut-end"]:
        _show_runcfg(scope, data)
    elif scope in ["module-init-start", "module-init-end"]:
        pass
    elif scope in ["module-clean-start", "module-clean-end"]:
        pass
    elif scope in ["function-init-start", "function-init-end"]:
        pass
    elif scope in ["function-clean-start", "function-clean-end"]:
        pass
    elif scope in ["post-module-prolog", "post-class-prolog"]:
        _show_runcfg(scope, data)
    else:
        st.warn("Unknown scope {}".format(scope))

