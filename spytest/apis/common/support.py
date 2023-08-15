
import traceback

from spytest import st, ftrace_prefix

import utilities.common as utils

tech_cfg_always = {
    "global": True,
    "system-not-ready": True,
    "portlist-not-ready": True,
    "console_hang": True,
    "port-status": True,
    "port-status-module": True,
    "port-status-function": True,
    "pre-module-prolog": False,
    "post-module-prolog": False,
    "pre-module-epilog": False,
    "post-module-epilog": False,
    "pre-function-prolog": False,
    "post-function-prolog": False,
    "pre-function-epilog": False,
    "post-function-epilog": False,
    "session-epilog": False,
}

tech_cfg_fail = {
    "pre-module-prolog": False,
    "post-module-prolog": False,
    "pre-module-epilog": False,
    "post-module-epilog": False,
    "pre-function-prolog": False,
    "post-function-prolog": False,
    "pre-function-epilog": False,
    "post-function-epilog": False,
    "function": False,
    "testcase": False,
}

core_cfg_always = {
    "global": True,
    "system-not-ready": False,
    "portlist-not-ready": False,
    "console_hang": True,
    "port-status": False,
    "port-status-module": False,
    "port-status-function": False,

    "pre-module-prolog": False,
    "post-module-prolog": False,
    "pre-module-epilog": False,
    "post-module-epilog": False,
    "pre-function-prolog": False,
    "post-function-prolog": False,
    "pre-function-epilog": False,
    "post-function-epilog": False,
    "session-epilog": False,
}

core_cfg_fail = {
    "pre-module-prolog": False,
    "post-module-prolog": False,
    "pre-module-epilog": False,
    "post-module-epilog": False,
    "pre-function-prolog": False,
    "post-function-prolog": False,
    "pre-function-epilog": False,
    "post-function-epilog": False,
    "function": False,
    "testcase": False,
}

sysinfo_cfg = {
    "global": True,
    "pre-module-prolog": False,
    "post-module-prolog": False,
    "pre-module-epilog": False,
    "post-module-epilog": False,
    "pre-function-prolog": False,
    "post-function-prolog": False,
    "pre-function-epilog": False,
    "post-function-epilog": False,
}

sairedis_cfg = {
    "global": True,
    "pre-module-prolog": False,
    "post-module-prolog": False,
    "pre-module-epilog": False,
    "post-module-epilog": False,
    "pre-function-prolog": False,
    "post-function-prolog": False,
    "pre-function-epilog": False,
    "post-function-epilog": False,
}

syslog_cfg = {
    "global": True,
    "pre-module-prolog": True,
    "post-module-prolog": True,
    "pre-module-epilog": True,
    "post-module-epilog": True,
    "pre-function-prolog": True,
    "post-function-prolog": False,
    "pre-function-epilog": False,
    "post-function-epilog": True,
}

config_db_cfg = {
    "global": True,
    "pre-module-prolog": True,
    "post-module-prolog": True,
    "pre-module-epilog": True,
    "post-module-epilog": True,
    "pre-function-prolog": False,
    "post-function-prolog": False,
    "pre-function-epilog": False,
    "post-function-epilog": False,
    "post-session-prolog": True,
}

show_run_cfg = {
    "global": True,
    "pre-module-prolog": True,
    "post-module-prolog": True,
    "pre-module-epilog": True,
    "post-module-epilog": True,
    "pre-function-prolog": False,
    "post-function-prolog": False,
    "pre-function-epilog": False,
    "post-function-epilog": False,
}


def trace(*args, **kwargs):
    ftrace_prefix("support", utils.logcall(None, *args, **kwargs))


def dut_log(dut, msg):
    ftrace_prefix("support", "{}: {}".format(dut, msg))
    st.log(msg, dut=dut)


class Support(object):
    def __init__(self, hooks, cfg, dut=None):

        self.hooks = hooks
        self.cfg = cfg

        # link to config - tech support
        runopt = utils.csv2list(cfg.get_tech_support)
        self._config(tech_cfg_always, runopt, "none", False, "global")
        self._config(tech_cfg_always, runopt, "session", True, "session-epilog")
        self._config(tech_cfg_always, runopt, "always", True, "pre-function-epilog")
        self._config(tech_cfg_fail, runopt, "onfail-epilog", True,
                     "post-function-prolog", "pre-function-epilog",
                     "post-module-prolog", "post-class-prolog",
                     "post-function-epilog")

        # link to config - core
        runopt = utils.csv2list(cfg.fetch_core_files)
        self._config(core_cfg_always, runopt, "none", False, "global")
        self._config(core_cfg_always, runopt, "session", True, "session-epilog")
        self._config(core_cfg_always, runopt, "always", True, "pre-function-epilog")
        self._config(core_cfg_fail, runopt, "onfail-epilog", True,
                     "post-function-prolog", "pre-function-epilog",
                     "post-module-prolog", "post-class-prolog",
                     "post-function-epilog")

        # link to config - sysinfo
        runopt = utils.csv2list(cfg.sysinfo_check)
        self._config(sysinfo_cfg, runopt, "none", False, "global")
        self._config(sysinfo_cfg, runopt, "module", True,
                     "pre-module-prolog", "post-module-prolog",
                     "pre-module-epilog", "post-module-epilog")
        self._config(sysinfo_cfg, runopt, "function", True,
                     "pre-function-prolog", "post-function-prolog",
                     "pre-function-epilog", "post-function-epilog")

        # link to config - sairedis
        runopt = utils.csv2list(cfg.save_sairedis)
        self._config(sairedis_cfg, runopt, "none", False, "global")
        self._config(sairedis_cfg, runopt, "module", True,
                     "pre-module-prolog", "post-module-epilog")
        self._config(sairedis_cfg, runopt, "function", True,
                     "pre-function-prolog", "post-function-epilog")

        # link to config - config-db.json
        runopt = utils.csv2list(cfg.save_config_db_json)
        self._config(config_db_cfg, runopt, "none", False, "global")
        self._config(config_db_cfg, runopt, "session", True,
                     "post-session-prolog")
        self._config(config_db_cfg, runopt, "module", True,
                     "pre-module-prolog", "post-module-prolog")
        self._config(config_db_cfg, runopt, "function", True,
                     "pre-function-prolog", "post-function-prolog")

        # link to config - running-config.txt
        runopt = utils.csv2list(cfg.save_running_config)
        self._config(show_run_cfg, runopt, "none", False, "global")
        self._config(show_run_cfg, runopt, "module", True,
                     "pre-module-prolog", "post-module-prolog")
        self._config(show_run_cfg, runopt, "function", True,
                     "pre-function-prolog", "post-function-prolog")

        # link to config - syslog
        runopt = utils.csv2list(cfg.syslog_check)
        self._config(syslog_cfg, runopt, "none", False, "global")

        # link to feature names
        self._feature(dut, tech_cfg_always, "tech-support-port-status-fail",
                      "port-status", "port-status-module", "port-status-function")
        self._feature(dut, tech_cfg_fail, "tech-support-function", "function")
        self._feature(dut, tech_cfg_fail, "tech-support-testcase", "testcase")

        # disable the collection in hooks if needed
        if tech_cfg_fail["function"]:
            for phase in ["pre-module-prolog", "post-module-prolog",
                          "pre-module-epilog", "post-module-epilog",
                          "pre-function-prolog", "post-function-prolog",
                          "pre-function-epilog", "post-function-epilog"]:
                tech_cfg_fail[phase] = False

        # dump the configuration
        self._dump("tech_cfg_always", tech_cfg_always)
        self._dump("tech_cfg_fail", tech_cfg_fail)
        self._dump("core_cfg_always", core_cfg_always)
        self._dump("core_cfg_fail", core_cfg_fail)
        self._dump("sysinfo_cfg", sysinfo_cfg)
        self._dump("sairedis_cfg", sairedis_cfg)
        self._dump("syslog_cfg", syslog_cfg)
        self._dump("config_db_cfg", config_db_cfg)
        self._dump("show_run_cfg", show_run_cfg)

    def _dump(self, name, d):
        for key, value in d.items():
            st.verbose("{} {} = {}".format(name, key, value))

    def _config(self, d, runopt, src, val, *args):
        for name in args:
            if src in runopt:
                d[name] = val

    def _feature(self, dut, d, feature, *args):
        for name in args:
            d[name] = st.is_feature_supported(feature, dut)

    def _chk(self, scope, d, res=None, desc=None):
        rv = bool(scope in d and d[scope])
        if not rv or not res:
            return rv
        fails = ["fail", "dutfail", "configfail", "cmdfail", "tgenfail"]
        return res.lower() in fails

    def _skip(self, dut, msg, isfail=False):
        if isfail:
            st.warn("SKIP {}".format(msg), dut=dut)
        else:
            st.verbose("SKIP {}".format(msg), dut=dut)
        trace("{}: SKIP {}".format(dut, msg))
        return None

    def _bldmsg(self, which, scope, res, desc, name):
        return " ".join([which, scope, name, res])
        # return " ".join([which, scope, name, res, "'{}'".format(desc)])

    def tech(self, dut, scope, res, desc, name):
        scope_name = "{}-{}".format(scope, name)
        en = self._chk("global", tech_cfg_always)
        msg = self._bldmsg("generating tech-support", scope, res, desc, name)
        if en and self._chk(scope, tech_cfg_fail, res, desc):
            dut_log(dut, msg)
            st.generate_tech_support(dut, scope_name)
        elif en and self._chk(scope, tech_cfg_always):
            dut_log(dut, msg)
            st.generate_tech_support(dut, scope_name)
        elif res.lower() in ["pass", ""]:
            self._skip(dut, msg)
        else:
            self._skip(dut, msg, True)

    def core(self, dut, scope, res, desc, name):
        scope_name = "{}-{}".format(scope, name)
        en = self._chk("global", core_cfg_always)
        msg = self._bldmsg("collect core-files", scope, res, desc, name)
        if en and self._chk(scope, core_cfg_fail, res, desc):
            dut_log(dut, msg)
            st.collect_core_files(dut, scope_name)
        elif en and self._chk(scope, core_cfg_always):
            dut_log(dut, msg)
            st.collect_core_files(dut, scope_name)
        elif res.lower() in ["pass", ""]:
            self._skip(dut, msg)
        else:
            self._skip(dut, msg, True)

    def fetch(self, dut, scope, res, desc, name, ts=True, core=True):
        if res in ["DepFail"]:
            return
        self.config_db(dut, scope, res, desc, name)
        self.show_run(dut, scope, res, desc, name)
        failmsg = self.syslog(dut, scope, res, desc, name)
        res, desc, clear_core, clear_kdump = self.override_result(dut, scope, res, desc, failmsg)
        if scope == "session-epilog":
            try:
                from apis.common.coverage import generate_msg_coverage_report
                dut_list = st.get_dut_names()
                if dut_list and dut == dut_list[0]:
                    if st.is_feature_supported("gnmi", dut):
                        generate_msg_coverage_report()
            except Exception as exp_error_msg:
                st.warn("Failed to collect message coverage report")
                st.exception(exp_error_msg)
                traceback.print_exc()

        res0 = res
        for i in range(2):
            if ts:
                self.tech(dut, scope, res, desc, name)
            if core:
                self.core(dut, scope, res, desc, name)
            if clear_core:
                self.hooks.clear_core_files(dut)
            if clear_kdump:
                self.hooks.clear_kdump_files(dut)
            res, desc = self.hooks.verify_config_replace(dut, scope, res, desc)
            if i != 0 or res0 == res:
                break
            # fetch again
            name = "{}-post-config-replace".format(name)
        self.sai_redis(dut, scope, res, desc, name)
        d = self.sysinfo(dut, scope, res, desc, name)
        if d:
            st.report_sysinfo(dut, scope,
                              d.get("MemAvailable", "ERROR"),
                              d.get("CpuUtilization", "ERROR"),
                              d.get("output", ""))
        return res, desc

    def sysinfo(self, dut, scope, res, desc, name, trace_log=3):
        msg = self._bldmsg("generating sysinfo", scope, res, desc, name)
        if not self._chk("global", sysinfo_cfg):
            return self._skip(dut, msg)
        if not self._chk(scope, sysinfo_cfg):
            return self._skip(dut, msg)

        dut_log(dut, msg)
        return self.hooks.read_sysinfo(dut, scope, name)

    def sai_redis(self, dut, scope, res, desc, name):
        msg = self._bldmsg("saving sai_redis", scope, res, desc, name)
        if not self._chk("global", sairedis_cfg):
            return self._skip(dut, msg)
        if not self._chk(scope, sairedis_cfg):
            return self._skip(dut, msg)
        dut_log(dut, msg)
        clear = bool(scope in ["pre-module-prolog", "pre-function-prolog"])
        st.save_sairedis(dut, name, clear)

    def syslog(self, dut, scope, res, desc, name):
        msg = self._bldmsg("saving syslog", scope, res, desc, name)
        if not self._chk("global", syslog_cfg):
            return self._skip(dut, msg)
        if not self._chk(scope, syslog_cfg):
            return self._skip(dut, msg)
        if res in ["DepFail"]:
            return
        dut_log(dut, msg)

        if scope in ["pre-module-prolog", "pre-function-prolog"]:
            lvl = "none"
        else:
            lvl = self.cfg.syslog_check
        return st.syslog_check(dut, scope, lvl, name)

    # returns original/modified result
    def override_result(self, dut, scope, res, desc, failmsg):
        clear_core, clear_kdump = False, False
        if failmsg:
            res = "dutfail"
            desc = st.report("unexpected_syslog_msg", failmsg, dut=dut, support=False, abort=False, type=res)
        check_kdump_files = bool(st.getenv("SPYTEST_VERIFY_KDUMP_BEFORE_RESULT", "0") != "0")
        check_core_files = bool(st.getenv("SPYTEST_VERIFY_CORE_BEFORE_RESULT", "0") != "0")
        if not check_kdump_files and not check_core_files:
            pass
        elif scope in ["pre-module-prolog"]:
            if check_kdump_files:
                self.hooks.clear_kdump_files(dut)
            if check_core_files:
                self.hooks.clear_core_files(dut)
        elif scope in ["post-function-epilog"]:
            if check_kdump_files and self.hooks.check_kdump_files(dut):
                clear_kdump = True
                res = "dutfail"
                desc = st.report("unexpected_kdump_seen", "", dut=dut, support=False, abort=False, type=res)
            elif check_core_files and self.hooks.check_core_files(dut):
                clear_core = True
                res = "dutfail"
                desc = st.report("unexpected_cores_seen", "", dut=dut, support=False, abort=False, type=res)
        return res, desc, clear_core, clear_kdump

    def config_db(self, dut, scope, res, desc, name):
        msg = self._bldmsg("saving config_db", scope, res, desc, name)
        if not self._chk("global", config_db_cfg):
            return self._skip(dut, msg)
        if not self._chk(scope, config_db_cfg):
            return self._skip(dut, msg)
        dut_log(dut, msg)
        self.hooks.save_config_db(dut, scope, name)

    def show_run(self, dut, scope, res, desc, name):
        msg = self._bldmsg("saving running config", scope, res, desc, name)
        if not self._chk("global", show_run_cfg):
            return self._skip(dut, msg)
        if not self._chk(scope, show_run_cfg):
            return self._skip(dut, msg)
        dut_log(dut, msg)
        self.hooks.save_running_config(dut, scope, name)
