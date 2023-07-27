import os

from spytest.logger import Logger
from spytest import env


def _get_file_path(results_prefix, suffix, extn, prefix=None, consolidated=False, dot="."):
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


def get_file_path(suffix, extn, prefix=None, consolidated=False, dot="."):
    file_prefix = env.get("SPYTEST_FILE_PREFIX", "results")
    results_prefix = env.get("SPYTEST_RESULTS_PREFIX", file_prefix)
    return _get_file_path(results_prefix, suffix, extn, prefix, consolidated, dot)


def get_csv_file_path(suffix, prefix=None, consolidated=False, dot="."):
    return get_file_path(suffix, "csv", prefix, consolidated, dot)


def get_htm_file_path(suffix, prefix=None, consolidated=False, dot="."):
    return get_file_path(suffix, "html", prefix, consolidated, dot)


def get_file_path_without_results_prefix(suffix, extn, prefix=None, consolidated=False, dot="."):
    return _get_file_path("", suffix, extn, prefix, consolidated, dot)


def get_results_name(consolidated=False):
    return "functions_all" if consolidated else "functions"


def get_session_log_name():
    return "logs.log"


def get_session_log(prefix=None):
    return get_file_path("logs", "log", prefix)


def get_functions_txt(prefix=None, consolidated=False):
    return get_file_path("functions", "txt", prefix, consolidated)


def get_functions_csv(prefix=None, consolidated=False):
    return get_file_path("functions", "csv", prefix, consolidated)


def get_functions_htm(prefix=None, consolidated=False):
    return get_file_path("functions", "html", prefix, consolidated)


def get_functions_png(prefix=None, consolidated=False):
    return get_file_path("functions", "png", prefix, consolidated)


def get_testcases_txt(prefix=None, consolidated=False):
    return get_file_path("testcases", "txt", prefix, consolidated)


def get_testcases_csv(prefix=None, consolidated=False):
    return get_file_path("testcases", "csv", prefix, consolidated)


def get_testcases_htm(prefix=None, consolidated=False):
    return get_file_path("testcases", "html", prefix, consolidated)


def get_testcases_png(prefix=None, consolidated=False):
    return get_file_path("testcases", "png", prefix, consolidated)


def get_results_txt(prefix=None, consolidated=False):
    return get_functions_txt(prefix, consolidated)


def get_results_csv(prefix=None, consolidated=False):
    return get_functions_csv(prefix, consolidated)


def get_results_htm(prefix=None, consolidated=False):
    return get_functions_htm(prefix, consolidated)


def get_results_png(prefix=None, consolidated=False):
    return get_functions_png(prefix, consolidated)


def get_tc_results_txt(prefix=None, consolidated=False):
    return get_testcases_txt(prefix, consolidated)


def get_tc_results_csv(prefix=None, consolidated=False):
    return get_testcases_csv(prefix, consolidated)


def get_tc_results_htm(prefix=None, consolidated=False):
    return get_testcases_htm(prefix, consolidated)


def get_tc_results_png(prefix=None, consolidated=False):
    return get_testcases_png(prefix, consolidated)


def get_syslog_csv(prefix=None, consolidated=False):
    return get_file_path("syslog", "csv", prefix, consolidated)


def get_syslog_htm(prefix=None, consolidated=False):
    return get_file_path("syslog", "html", prefix, consolidated)


def get_msysinfo_csv(prefix=None, consolidated=False):
    return get_file_path("msysinfo", "csv", prefix, consolidated)


def get_msysinfo_htm(prefix=None, consolidated=False):
    return get_file_path("msysinfo", "html", prefix, consolidated)


def get_fsysinfo_csv(prefix=None, consolidated=False):
    return get_file_path("fsysinfo", "csv", prefix, consolidated)


def get_fsysinfo_htm(prefix=None, consolidated=False):
    return get_file_path("fsysinfo", "html", prefix, consolidated)


def get_dsysinfo_csv(prefix=None, consolidated=False):
    return get_file_path("dsysinfo", "csv", prefix, consolidated)


def get_dsysinfo_htm(prefix=None, consolidated=False):
    return get_file_path("dsysinfo", "html", prefix, consolidated)


def get_stats_csv(prefix=None, consolidated=False):
    return get_file_path("stats", "csv", prefix, consolidated)


def get_stats_htm(prefix=None, consolidated=False):
    return get_file_path("stats", "html", prefix, consolidated)


def get_stats_txt(prefix=None, consolidated=False):
    return get_file_path("stats", "txt", prefix, consolidated)


def get_summary_txt(prefix=None, consolidated=False):
    return get_file_path("summary", "txt", prefix, consolidated)


def get_summary_htm(prefix=None, consolidated=False):
    return get_file_path("summary", "html", prefix, consolidated)


def get_coverage_csv(prefix=None, consolidated=False):
    return get_file_path("coverage", "csv", prefix, consolidated)


def get_coverage_htm(prefix=None, consolidated=False):
    return get_file_path("coverage", "html", prefix, consolidated)


def get_msg_coverage_htm(prefix="message_coverage", consolidated=False):
    return get_file_path_without_results_prefix("index", "html", prefix, False)


def get_audit_log(prefix=None, consolidated=False):
    return get_file_path("audit", "log", prefix, consolidated)


def get_audit_htm(prefix=None, consolidated=False):
    return get_file_path("audit", "html", prefix, consolidated)


def get_device_inventory_name():
    return "device_inventory"


def get_device_inventory_csv(prefix=None, consolidated=False):
    return get_csv_file_path(get_device_inventory_name(), prefix, consolidated)


def get_device_inventory_htm(prefix=None, consolidated=False):
    return get_htm_file_path(get_device_inventory_name(), prefix, consolidated)


def get_platform_inventory_name():
    return "platform_inventory"


def get_platform_inventory_csv(prefix=None, consolidated=False):
    return get_csv_file_path(get_platform_inventory_name(), prefix, consolidated)


def get_platform_inventory_htm(prefix=None, consolidated=False):
    return get_htm_file_path(get_platform_inventory_name(), prefix, consolidated)


def get_chip_inventory_name():
    return "chip_inventory"


def get_chip_inventory_csv(prefix=None, consolidated=False):
    return get_csv_file_path(get_chip_inventory_name(), prefix, consolidated)


def get_chip_inventory_htm(prefix=None, consolidated=False):
    return get_htm_file_path(get_chip_inventory_name(), prefix, consolidated)


def get_scale_csv(prefix=None, consolidated=False):
    return get_file_path("scale", "csv", prefix, consolidated)


def get_scale_htm(prefix=None, consolidated=False):
    return get_file_path("scale", "html", prefix, consolidated)


def get_featcov_csv(prefix=None, consolidated=False):
    return get_file_path("featcov", "csv", prefix, consolidated)


def get_featcov_htm(prefix=None, consolidated=False):
    return get_file_path("featcov", "html", prefix, consolidated)


def get_modules_csv(prefix=None, consolidated=False):
    return get_file_path("modules", "csv", prefix, consolidated)


def get_modules_htm(prefix=None, consolidated=False):
    return get_file_path("modules", "html", prefix, consolidated)


def get_features_summary_name():
    return "features_summary"


def get_features_summary_csv(prefix=None, consolidated=False):
    return get_csv_file_path(get_features_summary_name(), prefix, consolidated)


def get_features_summary_htm(prefix=None, consolidated=False):
    return get_htm_file_path(get_features_summary_name(), prefix, consolidated)


def get_features_csv(prefix=None, consolidated=False):
    return get_file_path("features", "csv", prefix, consolidated)


def get_features_htm(prefix=None, consolidated=False):
    return get_file_path("features", "html", prefix, consolidated)


def get_new_features_csv(prefix=None, consolidated=False):
    return get_file_path("new_features", "csv", prefix, consolidated)


def get_new_features_htm(prefix=None, consolidated=False):
    return get_file_path("new_features", "html", prefix, consolidated)


def get_regression_features_csv(prefix=None, consolidated=False):
    return get_file_path("regression_features", "csv", prefix, consolidated)


def get_regression_features_htm(prefix=None, consolidated=False):
    return get_file_path("regression_features", "html", prefix, consolidated)


def get_analisys_csv(prefix=None, consolidated=False):
    return get_file_path("analisys", "csv", prefix, consolidated)


def get_analisys_htm(prefix=None, consolidated=False):
    return get_file_path("analisys", "html", prefix, consolidated)


def get_alerts_log(prefix=None, consolidated=False):
    return get_file_path("alerts", "log", prefix, consolidated)


def get_defaults_htm(prefix=None, consolidated=False):
    return get_file_path("defaults", "htm", prefix, consolidated)


def get_devfeat_htm(prefix=None, consolidated=False):
    return get_file_path("devfeat", "htm", prefix, consolidated)


def get_rps_debug_log(prefix=None, consolidated=False):
    return _get_file_path("", "rps-debug", "log", prefix, consolidated)


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
    if env.get("SPYTEST_REPEAT_MODULE_SUPPORT") not in ["0", "1"]:
        module = os.path.basename(module)
    return module


def get_mlog_name(module):
    module = get_mlog_basename(module)
    log_name = "mlog/{}".format(module.replace(".py", ""))
    return log_name.replace("/", "_")


def get_mlog_path(module, prefix=None):
    log_name = get_mlog_name(module)
    return get_file_path(log_name, "log", prefix)


def get_mtgen_path(module, prefix=None):
    log_name = get_mlog_name(module)
    return get_file_path(log_name, "tgen", prefix)


def get_stdout_log(prefix=None):
    return get_file_path("stdout", "log", prefix)


def get_stderr_log(prefix=None):
    return get_file_path("stderr", "log", prefix)


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
