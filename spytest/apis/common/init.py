import os

# this file is imported from framework and hence
# we can't import framework API globally here
# import them with in functions
#from spytest import st

def _api_common_session_begin():
    from spytest import st, utils
    st.debug ("---- common session begin ----")
    if not os.getenv("SPYTEST_SKIP_INIT_COMMANDS"):
        def f(dut):
            if st.get_device_type(dut) in ["sonic", "vsonic"]:
                st.show(dut, "show version", skip_error_check=True,
                         skip_tmpl=True)
                st.show(dut, "show runningconfiguration all",
                         skip_error_check=True, skip_tmpl=True)
                if not st.is_community_build():
                    st.show(dut, "show system status", skip_error_check=True,
                             skip_tmpl=True)
        utils.exec_foreach(True, st.get_dut_names(), f)

def apis_register():
    from apis.common.hooks import api_hooks_init
    return api_hooks_init()

def apis_common_init(scope, ref=None):
    """

    :param scope:
    :type scope:
    :param ref:
    :type ref:
    :return:
    :rtype:
    """
    from spytest import st, utils
    if scope == "session":
        return _api_common_session_begin()

    if scope == "module":
        st.debug ("---- common module {} begin ----".format(ref))
    elif scope == "function":
        st.debug ("---- common test {} begin ----".format(ref))
        if not os.getenv("SPYTEST_SKIP_INIT_COMMANDS"):
            def f(dut):
                if st.get_device_type(dut) in ["sonic", "vsonic"]:
                    if not st.is_community_build():
                        st.show(dut, "show system status", skip_error_check=True,
                                skip_tmpl=True)
            utils.exec_foreach(True, st.get_dut_names(), f)

def apis_common_clean(scope, ref=None):
    """

    :param scope:
    :type scope:
    :param ref:
    :type ref:
    :return:
    :rtype:
    """
    from spytest import st
    if scope == "session":
        st.debug ("---- common session end ----")
    elif scope == "module":
        st.debug ("---- common module end ----")
    elif scope == "function":
        st.debug ("---- common test {} end ----".format(ref))

