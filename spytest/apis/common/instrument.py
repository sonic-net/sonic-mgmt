
from spytest import st, ftrace_prefix
from utilities.common import logargs, make_list

ident = "TODO-INSTRUMENT: "

feat_names = ["config-session", "config-replace"]
cache_names = ["in-function-epilog", "in-function-prolog"]
cache_names.extend(["in-module-epilog", "in-module-prolog"])
cache_names.extend(["st_config_count", "commit_after_st_config"])
cache_names.extend(["in-config-callback"])
cache_names.extend(["in-verify-topology"])
cache_names.extend(["in-fetch-support"])
cache_names.extend(["conf_session"])

commit_after_st_config_default = 0


def bldmsg(data):
    lines = []
    for line in data.split("\n"):
        lines.append("{}{}".format(ident, line))
    return "\n".join(lines)


def trace(*args, **kwargs):
    data = logargs(*args, **kwargs)
    ftrace_prefix("instrument", st.get_logger().bld(data))


def log(data):
    ftrace_prefix("instrument", st.get_logger().bld(data))
    st.log(bldmsg(data))


def get_cache_duts():
    retval = [None]
    for dut in st.get_dut_names():
        retval.append(dut)
    return retval


def features_debug():
    features = []
    for name in feat_names:
        features.append("{}={}".format(name, st.is_feature_supported(name)))
    return " Features({})".format(", ".join(features))


def cache_debug(dut_list):
    cache = []
    for name in cache_names:
        for dut in dut_list:
            val = st.get_cache(name, dut=dut)
            if val is None:
                pass
            elif dut is None:
                cache.append("{}={}".format(name, val))
            else:
                cache.append("{}({})={}".format(name, dut, val))
    return " Cache({})".format(", ".join(cache))


def todo(scope, *args, **kwargs):
    kwargs.pop("_output_", None)
    data = []
    data.append(features_debug())
    data.append(cache_debug(get_cache_duts()))
    trace("{}({}) {}".format(scope, logargs(*args, **kwargs), " ".join(data)))


def change_cache(val, *args, dut=None):
    for arg in args:
        st.set_cache(arg, val, dut=dut)


def commit(phase, dut=None, clear=None):
    if not st.is_feature_supported("config-session"):
        return

    kwargs = {"type": "klish", "conf_session": True, "instrument": False}
    for d in make_list(dut or st.get_dut_names()):
        if st.get_cache("in-fetch-support", default=0, dut=dut):
            log("skip {} commit during fetching support in dut={}".format(phase, dut))
            continue
        log("calling commit {} in dut={} {}".format(phase, d, cache_debug([d, None])))
        # st.config(d, "configure session", exec_mode="mgmt-user", expect_mode="mgmt-config", **kwargs)
        st.config(d, "commit", expect_mode="mgmt-user", exec_mode="mgmt-config", **kwargs)
        # reset config call count after previous commit
        if not clear or clear == d:
            change_cache(0, "st_config_count", dut=d)


def config_session(mode=1, dut=None):
    if not st.is_feature_supported("config-session"):
        return
    config_mode = 'session' if mode == 1 else 'terminal'
    st.log('Setting configure mode: {}'.format(config_mode))
    for d in make_list(dut or st.get_dut_names()):
        change_cache(mode, "conf_session", dut=d)
        st.set_module_params(dut=d, conf_session=mode)


def apis_instrument(scope, *args, **kwargs):
    if not st.is_feature_supported("config-session") and \
       not st.is_feature_supported("config-replace"):
        return
    if scope in ["session-init-start", "session-init-end"]:
        pass
    elif scope in ["session-clean-start", "session-clean-end"]:
        pass
    elif scope in ["init-config-start", "init-config-end"]:
        pass
    elif scope in ["apply-base-config-dut-start", "apply-base-config-dut-end"]:
        pass
    elif scope in ["testcase", "function", "session-prolog", "session-epilog"]:
        pass
    elif scope in ["fetch-support-start"]:
        change_cache(1, "in-fetch-support", dut=kwargs.get("dut", None))
        todo(scope, *args, **kwargs)
    elif scope in ["fetch-support-end"]:
        change_cache(0, "in-fetch-support", dut=kwargs.get("dut", None))
        todo(scope, *args, **kwargs)
    elif scope in ["pre-verify-topology"]:
        change_cache(1, "in-verify-topology")
        todo(scope, *args, **kwargs)
    elif scope in ["post-verify-topology"]:
        change_cache(0, "in-verify-topology")
        todo(scope, *args, **kwargs)
    elif scope in ["pre-module-prolog"]:
        change_cache(1, "in-module-prolog")
        change_cache(0, "in-function-prolog", "in-function-epilog")
        todo(scope, *args, **kwargs)
        config_session(mode=1)
    elif scope in ["post-module-prolog"]:
        change_cache(0, "in-module-prolog")
        todo(scope, *args, **kwargs)
        commit(scope)
        config_session(mode=0)
    elif scope in ["pre-module-epilog"]:
        change_cache(1, "in-module-epilog")
        todo(scope, *args, **kwargs)
        config_session(mode=1)
    elif scope in ["post-module-epilog"]:
        change_cache(0, "in-module-epilog")
        change_cache(0, "in-function-prolog", "in-function-epilog")
        change_cache(0, "in-module-prolog", "in-module-epilog")
        todo(scope, *args, **kwargs)
        commit(scope)
        config_session(mode=0)
    elif scope in ["pre-function-prolog"]:
        change_cache(1, "in-function-prolog")
        todo(scope, *args, **kwargs)
    elif scope in ["post-function-prolog"]:
        change_cache(0, "in-function-prolog")
        for dut in st.get_dut_names():
            change_cache(commit_after_st_config_default, "commit_after_st_config", dut=dut)
        todo(scope, *args, **kwargs)
        commit(scope)
    elif scope in ["pre-function-epilog"]:
        change_cache(1, "in-function-epilog")
        todo(scope, *args, **kwargs)
    elif scope in ["post-function-epilog"]:
        change_cache(0, "in-function-epilog")
        for dut in st.get_dut_names():
            change_cache(commit_after_st_config_default, "commit_after_st_config", dut=dut)
        todo(scope, *args, **kwargs)
        commit(scope)
    elif scope in ["pre-class-prolog"]:
        todo(scope, *args, **kwargs)
    elif scope in ["post-class-prolog"]:
        todo(scope, *args, **kwargs)
    elif scope in ["pre-class-epilog"]:
        todo(scope, *args, **kwargs)
    elif scope in ["post-class-epilog"]:
        todo(scope, *args, **kwargs)
    elif scope in ["pre-st.config"]:
        # todo(scope, *args, **kwargs)
        pass
    elif scope in ["post-st.config"]:
        if len(args) < 2:
            return  # valid st.config will have at least two arguments
        dut = args[0]
        if st.get_cache("in-config-callback", default=0, dut=dut):
            return  # already running
        cli_type = kwargs.get("type", "click")
        if cli_type != "klish":
            log("skip {} commit as ui type={} for dut={}".format(scope, cli_type, dut))
            return  # no need to handle non klish commands
        todo(scope, *args, **kwargs)
        st_config_count = st.get_cache("st_config_count", default=0, dut=dut) + 1
        if st.is_feature_supported("config-session"):
            change_cache(st_config_count, "st_config_count", dut=dut)
        if not st.get_cache("commit_after_st_config", default=commit_after_st_config_default, dut=dut):
            log("skip {} commit as commit_after_st_config=0 st_config_count={} in dut={}".format(scope, st_config_count, dut))
            return
        change_cache(1, "in-config-callback", dut=dut)
        commit("{}({})".format(scope, logargs(*args)), dut=dut)
        change_cache(0, "in-config-callback", dut=dut)
    elif scope in ["pre-st.show"]:
        if len(args) < 2:
            return  # valid st.show will have at least two arguments
        dut = args[0]
        if st.get_cache("in-verify-topology", default=0):
            log("skip {} commit during topo verification in dut={}".format(scope, dut))
            return  # no need to call during topology verification
        if not st.get_cache("conf_session", default=0, dut=dut):
            log("skip {} commit as conf_session({})=0".format(scope, dut))
            return  # conf_session is not enabled yet
        todo(scope, *args, **kwargs)
        if not st.get_cache("st_config_count", default=0, dut=dut):
            log("skip {} commit as there are no uncommited config calls in dut={}".format(scope, dut))
            return  # no config calls made after last commit
        if st.getenv("SPYTEST_CONCURRENT_CONFIG_LOCK", "0") != "0":
            commit("{}({})".format(scope, logargs(*args)), dut=None, clear=dut)  # commit all duts
            change_cache(0, "st_config_count", dut=dut)
        else:
            commit("{}({})".format(scope, logargs(*args)), dut=dut)
    elif scope in ["post-st.show"]:
        # todo(scope, *args, **kwargs)
        pass
    else:
        todo(scope, "Unknown: ", *args, **kwargs)
