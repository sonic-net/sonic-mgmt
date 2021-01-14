import os

from spytest.logger import Logger
import spytest.env as env

def get_file_path(suffix, extn, prefix=None, consolidated=False, dot="."):
    file_prefix = env.get("SPYTEST_FILE_PREFIX", "results")
    results_prefix = env.get("SPYTEST_RESULTS_PREFIX", file_prefix)
    if results_prefix: results_prefix = "{}_".format(results_prefix)
    if not consolidated:
        filename = "{}{}{}{}".format(results_prefix, suffix, dot, extn)
    elif suffix:
        filename = "{}{}_all{}{}".format(results_prefix, suffix, dot, extn)
    else:
        filename = "{}all{}{}".format(results_prefix, dot, extn)
    if prefix:
        filename = os.path.join(prefix, filename)
    return filename

def get_results_name(consolidated=False):
    return "functions_all" if consolidated else "functions"

def get_session_log_name():
    return "logs.log"

def get_session_log(prefix=None):
    return get_file_path("logs", "log", prefix)

def get_results_txt(prefix=None, consolidated=False):
    return get_file_path("functions", "txt", prefix, consolidated)

def get_results_csv(prefix=None, consolidated=False):
    return get_file_path("functions", "csv", prefix, consolidated)

def get_results_htm(prefix=None, consolidated=False):
    return get_file_path("functions", "html", prefix, consolidated)

def get_results_png(prefix=None, consolidated=False):
    return get_file_path("functions", "png", prefix, consolidated)

def get_tc_results_csv(prefix=None, consolidated=False):
    return get_file_path("testcases", "csv", prefix, consolidated)

def get_tc_results_htm(prefix=None, consolidated=False):
    return get_file_path("testcases", "html", prefix, consolidated)

def get_tc_results_png(prefix=None, consolidated=False):
    return get_file_path("testcases", "png", prefix, consolidated)

def get_syslog_csv(prefix=None, consolidated=False):
    return get_file_path("syslog", "csv", prefix, consolidated)

def get_syslog_htm(prefix=None, consolidated=False):
    return get_file_path("syslog", "html", prefix, consolidated)

def get_sysinfo_csv(prefix=None, consolidated=False):
    return get_file_path("sysinfo", "csv", prefix, consolidated)

def get_sysinfo_htm(prefix=None, consolidated=False):
    return get_file_path("sysinfo", "html", prefix, consolidated)

def get_stats_csv(prefix=None, consolidated=False):
    return get_file_path("stats", "csv", prefix, consolidated)

def get_stats_htm(prefix=None, consolidated=False):
    return get_file_path("stats", "html", prefix, consolidated)

def get_stats_txt(prefix=None, consolidated=False):
    return get_file_path("stats", "txt", prefix, consolidated)

def get_report_txt(prefix=None, consolidated=False):
    return get_file_path("summary", "txt", prefix, consolidated)

def get_report_htm(prefix=None, consolidated=False):
    return get_file_path("summary", "html", prefix, consolidated)

def get_modules_csv(prefix=None, consolidated=False):
    return get_file_path("modules", "csv", prefix, consolidated)

def get_modules_htm(prefix=None, consolidated=False):
    return get_file_path("modules", "html", prefix, consolidated)

def get_features_csv(prefix=None, consolidated=False):
    return get_file_path("features", "csv", prefix, consolidated)

def get_features_htm(prefix=None, consolidated=False):
    return get_file_path("features", "html", prefix, consolidated)

def get_analisys_csv(prefix=None, consolidated=False):
    return get_file_path("analisys", "csv", prefix, consolidated)

def get_alerts_log(prefix=None, consolidated=False):
    return get_file_path("alerts", "log", prefix, consolidated)

def get_defaults_htm(prefix=None, consolidated=False):
    return get_file_path("defaults", "htm", prefix, consolidated)

def get_devfeat_htm(prefix=None, consolidated=False):
    return get_file_path("devfeat", "htm", prefix, consolidated)

def get_cli_log(module=None, prefix=None, consolidated=False):
    log_name = get_mlog_name(module) if module else ""
    return get_file_path(log_name, "cli", prefix, consolidated)

def get_cli_type_log(module=None, prefix=None, consolidated=False):
    log_name = get_mlog_name(module) if module else ""
    return get_file_path(log_name, "cli_type", prefix, consolidated)

def get_dlog_path(dut, prefix=None):
    log_name = Logger.get_dlog_name(dut)
    return get_file_path(log_name, "", prefix, dot="")

def get_mlog_basename(nodeid):
    module = nodeid.split(':')[0]
    if env.get("SPYTEST_REPEAT_MODULE_SUPPORT", "0") != "0":
        module = os.path.basename(module)
    return module

def get_mlog_name(module):
    module = get_mlog_basename(module)
    log_name = "mlog/{}".format(module.replace(".py", ""))
    return log_name.replace("/", "_")

def get_mlog_path(module, prefix=None):
    log_name = get_mlog_name(module)
    return get_file_path(log_name, "log", prefix)

def get_stdout_log(prefix=None):
    return get_file_path("stdout", "log", prefix)

def get_pid_log(prefix=None):
    return get_file_path("pid", "txt", prefix)

def parse_nodeid(nodeid):
    try:
        module, func = nodeid.split("::", 1)
        module = get_mlog_basename(module)
    except Exception:
        module, func = "", nodeid
        func = get_mlog_basename(func)
    return module, func

