#!/bin/sh

''':'
exec $(dirname $0)/../bin/python "$0" "$@"
'''

import os
import sys
import glob
import shutil
import traceback
from operator import itemgetter
from collections import OrderedDict

from spytest import cmdargs
from spytest import paths
from spytest import env
from spytest import batch
from spytest import compare
from spytest import tcmap
from spytest import mail

import utilities.common as utils

from spytest.result import Result, ReportType
from spytest.template import Template
from spytest.item_utils import collect_items
from spytest.ftrace import print_ftrace

g_results_map = OrderedDict([
    ("", ""),
    ("PASS", "Pass"),
    ("FAIL", "Fail"),
    ("DUTFAIL", "Dut Fail"),
    ("TGENFAIL", "TGen Fail"),
    ("SCRIPTERROR", "Script Error"),
    ("CMDFAIL", "Cmd Fail"),
    ("UNSUPPORTED", "Not Supported"),
    ("CONFIGFAIL", "Config Fail"),
    ("ENVFAIL", "Env Fail"),
    ("DEPFAIL", "Dep Fail"),
    ("SKIPPED", "Skipped"),
    ("TIMEOUT", "Timeout"),
    ("TOPOFAIL", "Topo Fail"),
])

report_cols = ["Execution Started", "Execution Completed", "Execution Time", \
               "Session Init Time", "Tests Time"]
report_cols.extend(["Module Count", "Function Count", "Test Count", \
                   "SysLog Count", "GCOV Count", "DUT Count", "Pass Count", \
                    "Pass Rate", "Software Versions"])
#######################################################
# No need for individual fail counts in summary
# report_cols.extend(sorted(results_map.keys()))
#######################################################
report_total_col = "====TOTAL===="
report_total_col = ""


def get_results_map():
    cmd_fail_support = env.get("SPYTEST_CMD_FAIL_RESULT_SUPPORT", "0")
    if cmd_fail_support == "0":
        if "CMDFAIL" in g_results_map:
            del g_results_map["CMDFAIL"]
    return g_results_map


def get_rate(val, total):
    if total:
        return '{:.2%}'.format(val * 1.0 / total)
    return "0.00%"


def read_all_result_names(logs_path, suffix, extn, dot="."):

    def result_base_file(val):
        val = os.path.basename(val)
        return val

    # get all the result file paths
    prefix = batch.get_node_prefix()
    suffix = "_{}".format(suffix) if suffix else ""
    fmt = "{}/{}*/*{}{}{}".format(logs_path, prefix, suffix, dot, extn)
    files = glob.glob(fmt)

    files.sort(key=result_base_file)

    return files


def read_all_results(logs_path, suffix, rmindex=True):

    csv_files = read_all_result_names(logs_path, suffix, "csv")
    results = []
    for csv_file in csv_files:
        gw_name = os.path.basename(os.path.dirname(csv_file))
        for row in Result.read_report_csv(csv_file, rmindex):
            row.insert(0, gw_name)
            results.append(row)

    return results


def concat_files(target, files, add_prefix=True):
    lines = []
    for fp in files:
        for line in utils.read_lines(fp):
            prefix = "{},".format(os.path.basename(fp)) if add_prefix else ""
            lines.append("{}{}".format(prefix, line))
    utils.write_file(target, "\n".join(lines))
    return lines


def get_header_info(index, cols, is_batch=True):
    links, indexes = {}, {}
    hdr = Result.get_header(index, is_batch)
    for col in cols: links[col] = []
    for col in cols: indexes[col] = hdr.index(col) - 1
    return links, indexes


def _get_ts_count(name):
    wa = get_work_area()
    if not wa: return 0
    return wa.get_ts_count(name)


def _get_module_ui(name, cfg=None):
    if not cfg:
        wa = get_work_area()
        cfg = wa.cfg if wa else {}

    # per-module UI type takes precedence over
    ui_type = cfg.get("ui_type", "click").strip().lower()
    if ui_type in ["click-fallback", "klish-fallback"]:
        fallback = True
        module_ui = tcmap.get_module_info(name).uitype if name else ""
        if not module_ui:
            ui_type = ui_type.replace("-fallback", "")
        else:
            ui_type = module_ui
    else:
        fallback = False

    return fallback, ui_type


def _get_module_random(name, cfg=None):
    if not cfg:
        wa = get_work_area()
        cfg = wa.cfg if wa else {}

    global_ro = cfg.get("random_order", 1)
    if global_ro != 3:
        return global_ro, global_ro
    ro_module = tcmap.get_module_info(name).random
    return global_ro, ro_module


def get_work_area():
    from spytest.framework import get_work_area as get_work_area_impl
    return get_work_area_impl()


def _get_logs_path():
    from spytest.framework import _get_logs_path as _get_logs_path_impl
    return _get_logs_path_impl()


def set_mail_build(value):
    from spytest.framework import set_mail_build as set_mail_build_impl
    return set_mail_build_impl(value)


def defaults_report(logs_path):
    rows = []
    for name, value in cmdargs.get_default_all():
        rows.append([name, value])
    for name, value in env.get_default_all():
        rows.append([name, value])
    defaults_htm = paths.get_defaults_htm(logs_path)
    align = {col: True for col in ["Name", "Value"]}
    Result.write_report_html(defaults_htm, rows, ReportType.DEFAULTS, False, align=align)


def devfeats_report(logs_path, feature):
    rows = []
    for name, value in feature.get_all():
        rows.append([name, value])
    devfeat_htm = paths.get_devfeat_htm(logs_path)
    align = {col: True for col in ["Name", "Value"]}
    Result.write_report_html(devfeat_htm, rows, ReportType.DEFAULTS, False, align=align)


def compare_results(src, dst, cmp_csv, printerr, src_suffix=None, dst_suffix=None, url_prefix=None):
    err, cols, rows, addl_cols = compare.results(src, dst, src_suffix, dst_suffix)
    if err:
        printerr("Failed to create results comparison\n{}".format(err))
        return False

    colors = {}
    for col in cols:
        colors[col] = []

    for row in rows:
        for index, col in enumerate(cols):
            if "CMP" in col:
                if row[index] == "Superior":
                    colors[col].append("green")
                elif row[index] == "Inferior":
                    colors[col].append("red")
                else:
                    colors[col].append("white")
            elif "Pass Rate" in col:
                if url_prefix and "href" not in rows[0][index]:
                    if src_suffix and src_suffix in col:
                        rows[0][index] = "<a href='{}{}/dashboard.html'>{}</a>".format(url_prefix, src, rows[0][index])
                    elif rows[0][index]:
                        rows[0][index] = "<a href='{}{}/dashboard.html'>{}</a>".format(url_prefix, dst, rows[0][index])
                    else:
                        rows[0][index] = "<a href='{}{}/dashboard.html'>NA Yet</a>".format(url_prefix, dst)
                colors[col].append(Result.get_color(row[index]))
            else:
                colors[col].append("white")

    utils.ensure_parent(cmp_csv)
    utils.write_csv_file(cols, rows, cmp_csv)
    html_file = os.path.splitext(cmp_csv)[0] + '.html'
    align = {col: True for col in ["Module Name", ""]}
    utils.write_html_table3(cols, rows, html_file, colors=colors, align=align, total=True, addl_cols=addl_cols)
    printerr("{}{}".format(url_prefix, html_file))

    return True


def compare_syslogs(src, dst, cmp_csv, printerr, src_suffix=None, dst_suffix=None, url_prefix=None):
    err, cols, rows, addl_cols = compare.syslogs(src, dst, src_suffix, dst_suffix)
    if err:
        printerr("Failed to create syslog comparison\n{}".format(err))
        return False

    colors = {}
    for col in cols:
        colors[col] = []

    for row in rows:
        total = rows[-1]
        for index in range(1, 3):
            if url_prefix and "href" not in str(total[index]):
                if index == 1:
                    total[index] = "<a href='{}{}/results_modules_all.html'>{}</a>".format(url_prefix, src, total[index])
                elif index == 2:
                    total[index] = "<a href='{}{}/results_modules_all.html'>{}</a>".format(url_prefix, dst, total[index])
        for index, col in enumerate(cols):
            if "CMP" in col:
                if row[index] == "Superior":
                    colors[col].append("green")
                elif row[index] == "Inferior":
                    colors[col].append("red")
                else:
                    colors[col].append("white")
            else:
                colors[col].append("white")

    utils.ensure_parent(cmp_csv)
    utils.write_csv_file(cols, rows, cmp_csv)
    html_file = os.path.splitext(cmp_csv)[0] + '.html'
    align = {col: True for col in ["Module Name", ""]}
    utils.write_html_table3(cols, rows, html_file, colors=colors, align=align, total=True, addl_cols=addl_cols)
    printerr("{}{}".format(url_prefix, html_file))

    return True


def compare_report(url_prefix=None):
    wa = get_work_area()
    _, logs_path, worker_id = _get_logs_path()
    if worker_id or not wa or not wa.cfg.results_compare:
        return False

    cmp_path = os.path.join(logs_path, "compare")
    cmp_csv = paths.get_file_path("modules", "csv", cmp_path)
    return compare_results(wa.cfg.results_compare, logs_path, cmp_csv, wa.error, url_prefix=url_prefix)


def email_report_files(files, nodes, report_html):
    results_map = get_results_map()
    count = len(files)
    reports_header = ["Stat"]
    if not nodes:
        reports_header.append("Value")
    else:
        for node in nodes:
            reports_header.append(node)

    if count > 1:
        reports_header.append("Consolidated")

    report_data = OrderedDict()
    for key in report_cols:
        row = [key]  # stat name
        for index in range(0, count):
            row.append("0")  # node stat
        if count > 1:
            row.append("0")  # total
        if key:
            report_data[key] = row

    all_reports = []

    # fill the stat values
    for index in range(0, count):
        report_file = files[index]
        if os.path.exists(report_file):
            lines = utils.read_lines(report_file)
            for line in lines:
                if "=" not in line: continue
                (key, val) = line.split('=')
                key = key.strip()
                val = val.strip()
                if key == "Software Version":
                    set_mail_build(val)
                if key in report_data:
                    report_data[key][index + 1] = val

    # compute totals
    pass_count, tc_count = 0, 0
    for key in report_cols:
        if count <= 1 or key not in report_data:
            pass
        elif "Execution Started" in key:
            first_started = "NA"
            for ele in report_data[key][1:]:
                date_time_obj = utils.date_parse(ele)
                if date_time_obj is None:
                    continue
                if first_started == "NA" or date_time_obj < first_started:
                    first_started = date_time_obj
            report_data[key][count + 1] = str(first_started)
        elif "Execution Completed" in key:
            last_completed = "NA"
            for ele in report_data[key][1:]:
                date_time_obj = utils.date_parse(ele)
                if date_time_obj is None:
                    continue
                if last_completed == "NA" or date_time_obj > last_completed:
                    last_completed = date_time_obj
            report_data[key][count + 1] = str(last_completed)
        elif "Execution Time" in key:
            first_started = report_data["Execution Started"][count + 1]
            last_completed = report_data["Execution Completed"][count + 1]
            try:
                first_started = utils.date_parse(first_started)
                last_completed = utils.date_parse(last_completed)
                exec_time = utils.time_diff(first_started, last_completed, True)
                report_data[key][count + 1] = str(exec_time)
            except Exception:
                report_data[key][count + 1] = "NA"
        elif "Session Init Time" in key:
            max_init_time = 0
            for ele in report_data[key][1:]:
                if ele != "0" and ele != "":
                    (h, m, s) = ele.split(':')
                    tmp_secs = int(h) * 3600 + int(m) * 60 + int(s)
                    if tmp_secs > max_init_time:
                        max_init_time = tmp_secs
            report_data[key][count + 1] = utils.time_format(max_init_time)
        elif "Tests Time" in key:
            total_secs = 0
            for ele in report_data[key][1:]:
                if ele != "0" and ele != "":
                    (h, m, s) = ele.split(':')
                    total_secs += int(h) * 3600 + int(m) * 60 + int(s)
            report_data[key][count + 1] = utils.time_format(total_secs)
        elif key in results_map or key == "Module Count":
            total = sum([int(i) for i in report_data[key][1:]])
            report_data[key][count + 1] = total
        elif key in results_map or key == "Function Count":
            total = sum([int(i) for i in report_data[key][1:]])
            report_data[key][count + 1] = total
        elif key in results_map or key == "Test Count":
            tc_count = sum([int(i) for i in report_data[key][1:]])
            report_data[key][count + 1] = tc_count
        elif key in results_map or key == "Pass Count":
            pass_count = sum([int(i) for i in report_data[key][1:]])
            report_data[key][count + 1] = pass_count
        elif key in results_map or key == "Pass Rate":
            report_data[key][count + 1] = get_rate(pass_count, tc_count)
        elif key in results_map or key == "SysLog Count":
            total = sum([int(i) for i in report_data[key][1:]])
            report_data[key][count + 1] = total
        elif key in results_map or key == "GCOV Count":
            total = sum([int(i) for i in report_data[key][1:]])
            report_data[key][count + 1] = total
        elif key in results_map or key == "DUT Count":
            total = sum([int(i) for i in report_data[key][1:]])
            report_data[key][count + 1] = total
        else:
            report_data[key][count + 1] = "NA"

    for key in report_cols:
        if key in report_data:
            all_reports.append(report_data[key])

    if len(all_reports) < len(reports_header):
        rows, cols = [], [""]
        for row in all_reports: cols.append(row[0])
        for col_index in range(1, len(reports_header)):
            new_row = [reports_header[col_index]]
            for row in all_reports:
                new_row.append(row[col_index])
            rows.append(new_row)
        report_status = utils.write_html_table2(cols, rows)
    else:
        report_status = utils.write_html_table2(reports_header, all_reports)
    with open(report_html, "w") as ofh:
        ofh.write("\n\n{}\n".format(report_status))


def email_report(count=None):
    _, logs_path, worker_id = _get_logs_path()
    if worker_id:
        return

    count = batch.get_member_count() if count is None else count
    if count <= 1 and not batch.is_batch():
        report_txt = paths.get_summary_txt(logs_path)
        report_htm = paths.get_summary_htm(logs_path)
        email_report_files([report_txt], [], report_htm)
        return

    files, nodes, report_txt = [], [], paths.get_summary_txt()
    for index in range(0, count):
        node = batch.build_node_name(index)
        report_file = os.path.join(logs_path, node, report_txt)
        files.append(report_file)
        nodes.append(node)

    report_htm = paths.get_summary_htm(logs_path, True)
    email_report_files(files, nodes, report_htm)


def module_report(func_rows, tc_rows, results_csv, tcresults_csv,
                  offset=0, tsfiles=None, modules_csv=None, modules_htm=None,
                  module_col_name="Module Name"):
    results_map = get_results_map()
    [_, logs_path, _] = _get_logs_path()
    modules_csv = modules_csv or paths.get_modules_csv(logs_path, bool(offset))
    modules_htm = modules_htm or paths.get_modules_htm(logs_path, bool(offset))
    syslog_htm = paths.get_syslog_htm(None, bool(offset))
    func_rows = func_rows or Result.read_report_csv(results_csv)
    module_logs = OrderedDict()
    tgen_logs = OrderedDict()
    tgen_urls = OrderedDict()
    ts_links = OrderedDict()
    sys_logs = OrderedDict()
    modules = OrderedDict()
    tsfiles = tsfiles or {}

    tc_all, tc_pass = OrderedDict(), OrderedDict()
    tc_rows = tc_rows or Result.read_report_csv(tcresults_csv)
    for row in tc_rows:
        module = row[offset + 7]
        res = row[offset + 2]
        tc_all[module] = tc_all.get(module, 0) + 1
        pass_incr = 1 if res == "Pass" else 0
        tc_pass[module] = tc_pass.get(module, 0) + pass_incr

    def init_module(name, fallback, ro_global):
        module = OrderedDict()
        module["TC Pass Rate"] = 0
        module["TC Count"] = tc_all.get(name, 0)
        module["TC Pass"] = tc_pass.get(name, 0)
        module["Sys Logs"] = 0
        module["CDT"] = 0
        module["FCLI"] = 0
        module["TSSH"] = 0
        module["DCNT"] = 0
        if ro_global == 3:
            module["RO"] = 1
        if fallback:
            module["UI"] = ""
        module["Prolog Time"] = 0
        module["Epilog Time"] = 0
        module["Func Time"] = 0
        module["Exec Time"] = 0
        module["Pass Rate"] = 0
        module["FCNT"] = 0
        for res in results_map.values():
            if res: module[res] = 0
        if offset:
            module["Node"] = ""
            module["TS"] = 0
        else:
            module["TS"] = _get_ts_count(name)
        return module

    def tgen_log_get(name, path=None):
        if path not in tgen_urls:
            tgen_urls[path] = None
            filepath = os.path.join(logs_path, "tgen.txt")
            if os.path.exists(filepath):
                ipaddr = utils.read_lines(filepath)
                if ipaddr:
                    url = "http://{}/tmp/scapy-tgen/logs/current/"
                    tgen_urls[path] = url.format(ipaddr)
        log = paths.get_mtgen_path(name, path)
        filepath = os.path.join(logs_path, log)
        if os.path.exists(filepath):
            return log
        if tgen_urls[path]:
            return tgen_urls[path] + log
        return None

    for row in func_rows:
        name = row[offset]
        fallback, ui_type = _get_module_ui(name)
        ro_global, ro_module = _get_module_random(name)
        if name not in modules:
            if offset == 0:
                module_logs[name] = paths.get_mlog_path(name)
                tgen_logs[name] = tgen_log_get(name)
                ts_links[name] = None
                sys_logs[name] = paths.get_syslog_htm()
            else:
                module_logs[name] = paths.get_mlog_path(name, row[0])
                tgen_logs[name] = tgen_log_get(name, row[0])
                html_link = paths.get_modules_htm(row[0])
                html_file = os.path.join(logs_path, html_link)
                ts_links[name] = html_link if os.path.exists(html_file) else None
                sys_logs[name] = paths.get_syslog_htm(row[0])
            modules[name] = init_module(name, fallback, ro_global)
        res = row[offset + 2].upper()
        res = results_map.get(res, "")
        secs = utils.time_parse(row[offset + 3])
        syslogs = utils.integer_parse(row[offset + 5]) or 0
        fcli = utils.integer_parse(row[offset + 6])
        tryssh = utils.integer_parse(row[offset + 7])
        num_duts = utils.integer_parse(row[offset + 8])
        desc = row[offset + 9]
        module = modules[name]
        if offset:
            module["Node"] = row[0].replace(batch.get_node_prefix(), "")
            module["TS"] = tsfiles.get(name, 0)
        if res in module:
            module[res] = module[res] + 1
            module["Sys Logs"] = module["Sys Logs"] + syslogs
            module["Func Time"] = module["Func Time"] + secs
            module["FCNT"] = module["FCNT"] + 1
            module["Pass Rate"] = get_rate(module["Pass"], module["FCNT"])
            module["TC Pass Rate"] = get_rate(module["TC Pass"], module["TC Count"])
        else:
            if "Prolog" in desc:
                module["Prolog Time"] = module["Prolog Time"] + secs
                module["FCLI"] = fcli
                module["TSSH"] = tryssh
                module["DCNT"] = num_duts
                if ro_global == 3:
                    module["RO"] = ro_module
                if fallback:
                    module["UI"] = ui_type
            else:
                module["Epilog Time"] = module["Epilog Time"] + secs
            module["Sys Logs"] = module["Sys Logs"] + syslogs

    total = OrderedDict()
    for module in modules.values():
        module["Exec Time"] = module["Func Time"] + module["Prolog Time"] + module["Epilog Time"]
        module["CDT"] = module["Exec Time"] * module["DCNT"]
        for col in module:
            try:
                if col not in total: total[col] = module[col]
                elif col in ["UI", "RO", "Node"]: total[col] = ""
                else: total[col] = total[col] + module[col]
            except Exception: pass
        total["Pass Rate"] = get_rate(total["Pass"], total["FCNT"])
        total["TC Pass Rate"] = get_rate(total["TC Pass"], total["TC Count"])

    def sort_func(y):
        try:
            PassRate = float(str(y[1]["Pass Rate"]).replace("%", ""))
            func_count = int(y[1]["FCNT"])
            return (PassRate, 100000 - func_count)
        except Exception:
            return 0

    # sort the modules on total execution time
    last_row_total = False
    sorted_modules = OrderedDict(sorted(modules.items(), key=sort_func))
    if not last_row_total:
        modules = OrderedDict()
        modules[report_total_col] = OrderedDict()
        for module in sorted_modules:
            modules[module] = sorted_modules[module]
    else:
        modules = sorted_modules
        modules[report_total_col] = OrderedDict()

    if not total: total = init_module(report_total_col, False, False)
    modules[report_total_col] = total
    module_logs[report_total_col] = None
    tgen_logs[report_total_col] = None
    ts_links[report_total_col] = None
    sys_logs[report_total_col] = syslog_htm

    rows, cols, links = [], [], {"Module Name": [], "Sys Logs": [], "Node": [],
                                 "TS": [], "TGen Fail": []}
    colors = {"Pass Rate": [], "TC Pass Rate": [], "Script Error": [], "Not Supported": [],
              "Env Fail": [], "Topo Fail": [], "TGen Fail": [], "Skipped": [],
              "Config Fail": [], "Dep Fail": [], "Cmd Fail": []}
    align = {col: True for col in ["Module Name"]}
    for name, module in modules.items():
        for col in ["Prolog Time", "Epilog Time", "Func Time", "Exec Time", "CDT"]:
            module[col] = utils.time_format(int(module[col]))
        links["Sys Logs"].append(sys_logs[name] if module["Sys Logs"] else None)
        links["Module Name"].append(module_logs[name])
        links["TS"].append(ts_links[name])
        links["Node"].append(os.path.dirname(module_logs[name]) if module_logs[name] else None)
        links["TGen Fail"].append(tgen_logs[name])
        row = [name]
        row.extend(module.values())
        rows.append(row)
        cols = list(module.keys())
        cols.insert(0, module_col_name)
        for c in colors:
            if c not in module:
                pass
            elif c in ["TC Pass Rate"]:
                colors[c].append(Result.get_color(module[c]))
            elif c in ["Pass Rate"]:
                colors[c].append(Result.get_color(module[c]))
            else:
                colors[c].append(Result.get_color_red(module[c]))
    utils.write_html_table3(cols, rows, modules_htm, links=links, colors=colors, align=align, total=last_row_total)
    utils.write_csv_file(cols, rows, modules_csv)

    # create mini module report to be used in e-mail report
    mini_report_cols = [0, 1, 2, 3, 12, 13, 14, 15, 20]
    for index in reversed(range(len(cols))):
        if index not in mini_report_cols:
            cols.pop(index)
            for row in rows:
                row.pop(index)
    mini_modules_htm = modules_htm.replace(".html", "-mini.html")
    utils.write_html_table3(cols, rows, mini_modules_htm, links=links, colors=colors, align=align, total=last_row_total)

    return modules


def consolidated_results(logs_path, add_nes=False):

    neid = "--NE--"

    # read modules to get TS count
    results = read_all_results(logs_path, "modules", False)
    tsfiles = {}
    for row in results:
        if row[1].endswith(".py"):
            tsfiles[row[1]] = utils.integer_parse(row[-1], 0)

    nes_rows = []
    if add_nes and env.get("SPYTEST_REPORTS_ADD_NES", "1") != "0":
        all_rows, already_added = [], []
        all_rows.extend(utils.read_csv(os.path.join(logs_path, "batch_nes.csv")))
        all_rows.extend(utils.read_csv(os.path.join(logs_path, "batch_pending.csv")))
        for row in all_rows:
            # ID,Module,Function,TestCase,Node,Type
            func, testcase = row[2], row[3]
            if testcase == "--no-mapped-testcases--":
                testcase = func
            if testcase not in already_added:
                already_added.append(testcase)
                nes_rows.append(row)

    # functions
    results = read_all_results(logs_path, "functions")
    consolidated = sorted(results, key=itemgetter(5))
    if nes_rows and results:
        # ID,Module,TestFunction,Result,TimeTaken,ExecutedOn,Syslogs,FCLI,TSSH,DCNT,Description,Devices,KnownIssue
        tmp = results[0][:]  # use the fist row as template
        tmp[0], tmp[3], tmp[4], tmp[5], tmp[10], tmp[11] = \
            "", neid, "0:00:00", "2022-01-03 14:20:27", neid, ""
        already_added = []
        for nes_row in nes_rows:
            nes_id, nes_module, nes_func, nes_testcase, nes_node = nes_row[0:5]
            if nes_id == "#": continue
            if nes_func in already_added: continue
            already_added.append(nes_func)
            try: nes_node = nes_node.split(">")[-2].split("<")[0]
            except Exception: pass
            tmp2 = tmp[:]; tmp2[0], tmp2[1], tmp2[2] = nes_node, nes_module, nes_func
            if nes_node:
                tmp2[10] = "{} Check if {} is Dead".format(neid, nes_node)
            else:
                tmp2[10] = "{} Check if nodes are available".format(neid)
            consolidated.append(tmp2)

    results_csv = paths.get_results_csv(logs_path, True)
    Result.write_report_csv(results_csv, consolidated, ReportType.FUNCTIONS)
    ############## REMOVE ME ##########################
    results_csv2 = paths.get_file_path("result", "csv", logs_path, True)
    shutil.copy2(results_csv, results_csv2)
    ###################################################
    links, indexes = get_header_info(ReportType.FUNCTIONS, ["Node", "Module", "Result", "Syslogs"])
    for row in consolidated:
        node_name = row[indexes["Node"]]
        results_htm = paths.get_results_htm(node_name)
        syslog_htm = paths.get_syslog_htm(node_name)
        mlog = paths.get_mlog_path(row[indexes["Module"]], node_name)
        links["Node"].append(results_htm)
        links["Module"].append(mlog)
        links["Result"].append(mlog)
        links["Syslogs"].append(syslog_htm)
    results_htm = paths.get_results_htm(logs_path, True)
    align = {col: True for col in ["Module", "TestFunction", "Description", "Devices", "Doc"]}
    Result.write_report_html(results_htm, consolidated, ReportType.FUNCTIONS, True, 4, links=links, align=align)
    save_failed_function_list(results_csv, 1)
    wa = get_work_area()
    if wa and wa._context:
        wa._context.run_progress_report(len(consolidated))

    # modules
    tcresults_csv = paths.get_tc_results_csv(logs_path, True)
    module_report(None, None, results_csv, tcresults_csv, 1, tsfiles)

    # testcases
    results = read_all_results(logs_path, "testcases")
    consolidated = sorted(results, key=itemgetter(5))
    tcdict = {}
    for row in consolidated:
        tcdict[row[2]] = row
    if nes_rows and results:
        # ID,Feature,TestCase,Result,ResultType,ExecutedOn,Description,Function,Module,Devices,KnownIssue
        tmp = results[0][:]  # use the fist row as template
        tmp[0], tmp[1], tmp[3], tmp[5], tmp[6], tmp[9] = \
            "", neid, neid, "2022-01-03 14:20:27", neid, ""
        for nes_row in nes_rows:
            nes_id, nes_module, nes_func, nes_testcase, nes_node = nes_row[0:5]
            if nes_id == "#": continue
            if nes_testcase in tcdict: continue
            try: nes_node = nes_node.split(">")[-2].split("<")[0]
            except Exception: pass
            tmp2 = tmp[:]; tmp2[0], tmp2[2], tmp2[7], tmp2[8] = nes_node, nes_testcase, nes_func, nes_module
            if nes_node:
                tmp2[6] = "{} Check if {} is Dead".format(neid, nes_node)
            else:
                tmp2[6] = "{} Check if nodes are available".format(neid)
            consolidated.append(tmp2)
    tcresults_csv = paths.get_tc_results_csv(logs_path, True)
    Result.write_report_csv(tcresults_csv, consolidated, ReportType.TESTCASES)
    ############## REMOVE ME ##########################
    tcresults_csv2 = paths.get_file_path("tcresult", "csv", logs_path, True)
    shutil.copy2(tcresults_csv, tcresults_csv2)
    ###################################################
    links, indexes = get_header_info(ReportType.TESTCASES, ["Node", "Result", "Module", "ResultType", "ExecutedOn", "KnownIssue"])
    for row in consolidated:
        node_name = row[indexes["Node"]]
        results_htm = paths.get_tc_results_htm(node_name)
        mlog = paths.get_mlog_path(row[indexes["Module"]], node_name)
        links["Node"].append(results_htm)
        links["Module"].append(mlog)
        links["Result"].append(mlog)
    results_htm = paths.get_tc_results_htm(logs_path, True)
    align = {col: True for col in ["Feature", "TestCase", "Description", "Function", "Module", "Devices"]}
    Result.write_report_html(results_htm, consolidated, ReportType.TESTCASES, True, 4, links=links, align=align)

    # features
    cols, new_tc_list = features_report(None, None, results_csv, tcresults_csv, 1, logs_path=logs_path)

    # sub reports
    srs = sub_reports(logs_path, True)

    # feature summary
    features_summary(logs_path, cols, 1, srs)

    # analysis - reuse from testcases report
    try:
        links = {"Module": []}
        for row in consolidated:
            node_name = row[indexes["Node"]]
            module_name = row[indexes["Module"]]
            engineer = tcmap.get_owner(module_name)
            mlog = paths.get_mlog_path(module_name, node_name)
            jobid = env.get("SPYTEST_JENKINS_JOB", "").strip()
            if jobid:
                mlog = "{}/{}".format(jobid, mlog)
            result_url_base = env.get("SPYTEST_RESULTS_BASE_URL", "<MODIFY-THIS>").strip()
            if result_url_base:
                mlog = "{}/{}".format(result_url_base, mlog)
            links["Module"].append(mlog)
            row.pop(indexes["KnownIssue"])
            row.pop(indexes["ExecutedOn"])
            row.pop(indexes["ResultType"])
            row.pop(indexes["Node"])
            row.append("")  # Analisis
            row.append("")  # DUT Defect ID
            row.append("")  # SQA Defect ID
            row.append(engineer)
            if new_tc_list is None:
                row.insert(1, "")
            elif row[1] in new_tc_list:
                row.insert(1, "No")
            else:
                row.insert(1, "Yes")
            row.append("")  # Only Pending
        analisys_csv = paths.get_analisys_csv(logs_path, True)
        Result.write_report_csv(analisys_csv, consolidated, ReportType.ANALYSIS, row_index=False)
        analisys_htm = paths.get_analisys_htm(logs_path, True)
        Result.write_report_html(analisys_htm, consolidated, ReportType.ANALYSIS, True, row_index=False, links=links)
    except Exception:
        if wa: wa.error("Failed to generate analisys report")
        else: print("Failed to generate analisys report")

    # syslogs
    results = read_all_results(logs_path, "syslog")
    consolidated = sorted(results, key=itemgetter(5))
    links, indexes = get_header_info(ReportType.SYSLOGS, ["Node", "Device", "Module"])
    for row in consolidated:
        node_name = row[indexes["Node"]]
        syslog_htm = paths.get_syslog_htm(node_name)
        dlog = paths.get_dlog_path(row[indexes["Device"]], node_name)
        mlog = paths.get_mlog_path(row[indexes["Module"]], node_name)
        links["Node"].append(syslog_htm)
        links["Device"].append(dlog)
        links["Module"].append(mlog)
    syslog_csv = paths.get_syslog_csv(logs_path, True)
    Result.write_report_csv(syslog_csv, consolidated, ReportType.SYSLOGS)
    syslog_htm = paths.get_syslog_htm(logs_path, True)
    align = {col: True for col in ["Module", "TestFunction", "LogMessage"]}
    Result.write_report_html(syslog_htm, consolidated, ReportType.SYSLOGS, True, links=links, align=align)

    # save syslog excel report
    try: generate_excel_syslog_report(syslog_csv)
    except Exception as exp: print(exp)

    # stats
    consolidated = read_all_results(logs_path, "stats")
    stats_csv = paths.get_stats_csv(logs_path, True)
    Result.write_report_csv(stats_csv, consolidated, ReportType.STATS)
    links, indexes = get_header_info(ReportType.STATS, ["Node", "Module", "TECH SUPPORT"])
    for row in consolidated:
        node_name = row[indexes["Node"]]
        stats_htm = paths.get_stats_htm(node_name)
        links["Node"].append(stats_htm)
        mlog = paths.get_mlog_path(row[indexes["Module"]], node_name)
        links["Module"].append(mlog)
        links["TECH SUPPORT"].append(node_name)
    stats_htm = paths.get_stats_htm(logs_path, True)
    align = {col: True for col in ["Module", "Function", "Description"]}
    Result.write_report_html(stats_htm, consolidated, ReportType.STATS, True, links=links, align=align)

    # msysinfo
    consolidated = read_all_results(logs_path, "msysinfo")
    msysinfo_csv = paths.get_msysinfo_csv(logs_path, True)
    Result.write_report_csv(msysinfo_csv, consolidated, ReportType.MSYSINFO)
    links, indexes = get_header_info(ReportType.MSYSINFO, ["Node", "Module", "DUTs"])
    for row in consolidated:
        node_name = row[indexes["Node"]]
        msysinfo_htm = paths.get_msysinfo_htm(node_name)
        links["Node"].append(msysinfo_htm)
        mlog = paths.get_mlog_path(row[indexes["Module"]], node_name)
        links["Module"].append(mlog)
        slog = paths.get_session_log(node_name)
        links["DUTs"].append(slog)
    msysinfo_htm = paths.get_msysinfo_htm(logs_path, True)
    align = {col: True for col in ["Module"]}
    Result.write_report_html(msysinfo_htm, consolidated, ReportType.MSYSINFO, True, links=links, align=align)

    # fsysinfo
    consolidated = read_all_results(logs_path, "fsysinfo")
    fsysinfo_csv = paths.get_fsysinfo_csv(logs_path, True)
    Result.write_report_csv(fsysinfo_csv, consolidated, ReportType.FSYSINFO)
    links, indexes = get_header_info(ReportType.FSYSINFO, ["Node", "Module", "Function", "DUTs"])
    for row in consolidated:
        node_name = row[indexes["Node"]]
        fsysinfo_htm = paths.get_fsysinfo_htm(node_name)
        links["Node"].append(fsysinfo_htm)
        mlog = paths.get_mlog_path(row[indexes["Module"]], node_name)
        links["Module"].append(mlog)
        slog = paths.get_session_log(node_name)
        links["DUTs"].append(slog)
    fsysinfo_htm = paths.get_fsysinfo_htm(logs_path, True)
    align = {col: True for col in ["Module", "Function"]}
    Result.write_report_html(fsysinfo_htm, consolidated, ReportType.FSYSINFO, True, links=links, align=align)

    # dsysinfo
    consolidated = read_all_results(logs_path, "dsysinfo")
    dsysinfo_csv = paths.get_dsysinfo_csv(logs_path, True)
    Result.write_report_csv(dsysinfo_csv, consolidated, ReportType.DSYSINFO)
    links, indexes = get_header_info(ReportType.DSYSINFO, ["Node", "Module", "Function", "DUT"])
    for row in consolidated:
        node_name = row[indexes["Node"]]
        dsysinfo_htm = paths.get_dsysinfo_htm(node_name)
        links["Node"].append(dsysinfo_htm)
        mlog = paths.get_mlog_path(row[indexes["Module"]], node_name)
        links["Module"].append(mlog)
        slog = paths.get_session_log(node_name)
        links["DUT"].append(slog)
    dsysinfo_htm = paths.get_dsysinfo_htm(logs_path, True)
    align = {col: True for col in ["Module", "Function"]}
    Result.write_report_html(dsysinfo_htm, consolidated, ReportType.DSYSINFO, True, links=links, align=align)

    # coverage
    consolidated = read_all_results(logs_path, "coverage")
    coverage_csv = paths.get_coverage_csv(logs_path, True)
    Result.write_report_csv(coverage_csv, consolidated, ReportType.COVERAGE)
    links, indexes = get_header_info(ReportType.COVERAGE, ["Node", "Module"])
    for row in consolidated:
        node_name = row[indexes["Node"]]
        coverage_htm = paths.get_coverage_htm(node_name)
        links["Node"].append(coverage_htm)
        mlog = paths.get_mlog_path(row[indexes["Module"]], node_name)
        links["Module"].append(mlog)
    coverage_htm = paths.get_coverage_htm(logs_path, True)
    align = {col: True for col in ["Module", "Devices", "Models", "Chips"]}
    Result.write_report_html(coverage_htm, consolidated, ReportType.COVERAGE, True, links=links, align=align)

    # read coverage report
    coverage_rows = Result.read_report_csv(coverage_csv)
    platform_tests, chip_tests = {}, {}
    for row in coverage_rows:
        platforms, chips = row[3], row[4]
        count = utils.integer_parse(row[6]) or 0
        for platform in platforms.split(","):
            platform = platform.strip()
            old = platform_tests.get(platform, 0)
            platform_tests[platform] = old + count
        for chip in chips.split(","):
            chip = chip.strip()
            old = chip_tests.get(chip, 0)
            chip_tests[chip] = old + count

    # inventory - devices
    inventory_name = paths.get_device_inventory_name()
    consolidated = read_all_results(logs_path, inventory_name)
    inventory_csv = paths.get_device_inventory_csv(logs_path, True)
    rows, duts = [], {}
    for row in consolidated:
        dut, platform, chip, build = row[1:]
        platform_tests.setdefault(platform, 0)
        chip_tests.setdefault(chip, 0)
        if dut not in duts:
            duts[dut] = 1
            rows.append([dut, platform, chip, build])
    inventory_htm = paths.get_device_inventory_htm(logs_path, True)
    align = {col: True for col in ["Model", "Build"]}
    Result.write_report_csv(inventory_csv, rows, ReportType.DEVICE_INVENTORY)
    Result.write_report_html(inventory_htm, rows, ReportType.DEVICE_INVENTORY, True, align=align)

    # inventory - platform
    inventory_name = paths.get_platform_inventory_name()
    rows, uncovered = [], []
    for platform, count in platform_tests.items():
        rows.append([platform, count])
        if count == 0:
            uncovered.append(platform)
    align = {col: True for col in ["Platform"]}
    inventory_csv = paths.get_platform_inventory_csv(logs_path, True)
    Result.write_report_csv(inventory_csv, rows, ReportType.PLATFORM_INVENTORY)
    inventory_htm = paths.get_platform_inventory_htm(logs_path, True)
    Result.write_report_html(inventory_htm, rows, ReportType.PLATFORM_INVENTORY, True, align=align)
    os.environ["SPYTEST_UNCOVERED_PLATFORMS"] = ",".join(uncovered)

    # inventory - chip
    inventory_name = paths.get_chip_inventory_name()
    rows, uncovered = [], []
    for chip, count in chip_tests.items():
        rows.append([chip, count])
        if count == 0:
            uncovered.append(chip)
    align = {col: True for col in ["Chip"]}
    inventory_csv = paths.get_chip_inventory_csv(logs_path, True)
    Result.write_report_csv(inventory_csv, rows, ReportType.CHIP_INVENTORY)
    inventory_htm = paths.get_chip_inventory_htm(logs_path, True)
    Result.write_report_html(inventory_htm, rows, ReportType.CHIP_INVENTORY, True, align=align)
    os.environ["SPYTEST_UNCOVERED_CHIPS"] = ",".join(uncovered)

    # scale
    consolidated = read_all_results(logs_path, "scale")
    scale_csv = paths.get_scale_csv(logs_path, True)
    scale_htm = paths.get_scale_htm(logs_path, True)
    align = {col: True for col in ["Name", "Platform", "Build", "Module", "Function"]}
    Result.write_report_csv(scale_csv, consolidated, ReportType.SCALE)
    Result.write_report_html(scale_htm, consolidated, ReportType.SCALE, True, align=align)

    # featcov
    consolidated = read_all_results(logs_path, "featcov")
    featcov_csv = paths.get_featcov_csv(logs_path, True)
    featcov_htm = paths.get_featcov_htm(logs_path, True)
    align = {col: True for col in ["Name", "Platform", "Build", "Module", "Function"]}
    Result.write_report_csv(featcov_csv, consolidated, ReportType.FEATCOV)
    Result.write_report_html(featcov_htm, consolidated, ReportType.FEATCOV, True, align=align)

    # CLI files
    all_file = paths.get_cli_log("", logs_path, True)
    files = read_all_result_names(logs_path, "", "cli")
    concat_files(all_file, files, False)

    # CLI type files
    all_file = paths.get_cli_type_log("", logs_path, True)
    files = read_all_result_names(logs_path, "", "cli_type")
    lines = concat_files(all_file, files)
    ui_types = OrderedDict()

    # per UI specific files
    for line in lines:
        module, func, ui_type = line.split(",")
        if ui_type not in ui_types:
            ui_types[ui_type] = []
        ui_types[ui_type].append(",".join([module, func]))
    for ui_type, lines in ui_types.items():
        filepath = "{}.{}".format(all_file, ui_type)
        utils.write_file(filepath, "\n".join(lines))

    # alert files
    all_file = paths.get_alerts_log(logs_path, True)
    files = read_all_result_names(logs_path, "alerts", "log")
    concat_files(all_file, files, False)

    # audit files
    all_file = paths.get_audit_log(logs_path, True)
    files = read_all_result_names(logs_path, "audit", "log")
    rows = []
    for f in files:
        node_name = os.path.basename(os.path.dirname(f))
        rows.append([node_name])
    links, indexes = get_header_info(ReportType.AUDIT, ["Node"])
    for row in rows:
        node_name = row[indexes["Node"]]
        audit_log = paths.get_audit_log(node_name)
        links["Node"].append(audit_log)
    audit_htm = paths.get_audit_htm(logs_path, True)
    Result.write_report_html(audit_htm, rows, ReportType.AUDIT, True, links=links)

    # Generate consolidated message stats report
    try:
        from apis.common.coverage import generate_msg_coverage_report
        generate_msg_coverage_report(consolidated=True, logs_path=logs_path)
    except Exception as exp_error_msg:
        print("Failed to collect consolidated message coverage report")
        print(exp_error_msg)
        traceback.print_exc()

    # template samples
    fpaths = Template.get_samples(logs_path)
    if fpaths:
        dst = os.path.join(logs_path, "templates")
        for fpath in fpaths:
            if not fpath.startswith(dst):
                utils.copyfile(fpath, dst)


save_function_list_supported = False


def save_function_list(items, logs_path):
    if not save_function_list_supported:
        return
    func_list = []
    for item in items:
        func_list.append(item.location[2])
    out_file = paths.get_results_txt(logs_path)
    utils.write_file(out_file, "\n".join(func_list))


save_failed_function_list_supported = False


def save_failed_function_list(csv_file, offset=0):
    if not save_failed_function_list_supported:
        return
    func_list = []
    for row in Result.read_report_csv(csv_file):
        res = row[offset + 2].upper()
        if not res in ["", "PASS"]:
            func_list.append(row[offset + 1])
    out_file = os.path.splitext(csv_file)[0] + '_fails.txt'
    utils.write_file(out_file, "\n".join(func_list))


def features_report_int(func_rows, tc_rows, offset, features_csv,
                        features_htm, feature_col_name):
    modules = OrderedDict()
    func_time = dict()
    func_syslogs = dict()
    tcmodmap = dict()

    for row in func_rows:
        name = row[offset]
        func = row[offset + 1]
        secs = utils.time_parse(row[offset + 3])
        syslogs = utils.integer_parse(row[offset + 5]) or 0
        num_duts = utils.integer_parse(row[offset + 8])
        desc = row[offset + 9]
        if name not in modules:
            modules[name] = OrderedDict()
            module = modules[name]
            module["PrologTime"] = 0
            module["EpilogTime"] = 0
            module["SysLogs"] = 0
            module["DCNT"] = num_duts
        else:
            module = modules[name]

        if not func:
            if "Prolog" in desc:
                module["PrologTime"] = module["PrologTime"] + secs
            else:
                module["EpilogTime"] = module["EpilogTime"] + secs
            module["SysLogs"] = module["SysLogs"] + syslogs
        else:
            tcmodmap[func] = name
            func_time[func] = secs
            func_syslogs[func] = syslogs

    components = OrderedDict()
    total_executed = 0
    total_pass_count = 0
    total_pass_rate = 0.00
    total_effective_rate = 0.00
    total_envfail_count = 0
    total_envfail_rate = 0.00
    total_skipped_count = 0
    total_skipped_rate = 0.00
    total_script_error_count = 0
    total_script_error_rate = 0.00
    total_unsupported_count = 0
    total_unsupported_rate = 0.00
    total_time_taken = 0
    total_dut_time = 0
    total_syslog_count = 0
    for row in tc_rows:
        tc = row[offset + 1]
        res = row[offset + 2].upper()
        name = tcmap.get_comp(tc, row[offset])
        func = tcmap.get_func(tc, row[offset + 6])

        if name not in components:
            components[name] = OrderedDict()
            component = components[name]
            component["Pass Rate"] = 0.00
            component["Executed"] = 0
            component["Pass"] = 0
            component["Non Pass"] = 0
            component["Not Run"] = 0
            component["Effective Pass Rate"] = 0.00
            component["Exec Time"] = 0
            component["SysLogs"] = 0
            component["EnvFail"] = 0
            component["Env Fail Rate"] = 0.00
            component["Skipped"] = 0
            component["Skipped Rate"] = 0.00
            component["ScriptError"] = 0
            component["Script Error Rate"] = 0.00
            component["Unsupported"] = 0
            component["Unsupported Rate"] = 0.00
            component["CDT"] = 0
        else:
            component = components[name]
        if res == "PASS":
            component["Pass"] = component["Pass"] + 1
            total_pass_count = total_pass_count + 1
        elif res == "UNSUPPORTED":
            component["Unsupported"] = component["Unsupported"] + 1
            total_unsupported_count = total_unsupported_count + 1
        elif res in ["SKIPPED"]:
            component["Skipped"] = component["Skipped"] + 1
            total_skipped_count = total_skipped_count + 1
        elif res in ["SCRIPT ERROR", "CMD FAIL"]:
            component["ScriptError"] = component["ScriptError"] + 1
            total_script_error_count = total_script_error_count + 1
        elif res in ["ENVFAIL", "TOPOFAIL", "TGENFAIL", "--NE--"]:
            component["EnvFail"] = component["EnvFail"] + 1
            total_envfail_count = total_envfail_count + 1
        try:
            func_secs = func_time[func]
            syslogs = func_syslogs[func]
        except Exception:
            # print("=========== Failed to find function {} time -- ignore".format(func))
            func_secs = 0
            syslogs = 0
        try:
            module = modules[tcmodmap[func]]
            prolog_secs = module["PrologTime"]
            epilog_secs = module["EpilogTime"]
            module_syslogs = module["SysLogs"]
            num_duts = module["DCNT"]
        except Exception:
            # print("=========== Failed to find module {} time -- ignore".format(func))
            prolog_secs = 0
            epilog_secs = 0
            module_syslogs = 0
            num_duts = 1
        all_secs = func_secs + prolog_secs + epilog_secs
        component["Executed"] = component["Executed"] + 1
        component["Non Pass"] = component["Executed"] - component["Pass"]
        component["Pass Rate"] = get_rate(component["Pass"], component["Executed"])
        not_run = component["Unsupported"] + component["EnvFail"]
        effective_executed = component["Executed"] - not_run
        component["Not Run"] = not_run
        component["Effective Pass Rate"] = get_rate(component["Pass"], effective_executed)
        component["Exec Time"] = component["Exec Time"] + all_secs
        component["SysLogs"] = component["SysLogs"] + syslogs + module_syslogs
        component["Env Fail Rate"] = get_rate(component["EnvFail"], component["Executed"])
        component["Skipped Rate"] = get_rate(component["Skipped"], component["Executed"])
        component["Script Error Rate"] = get_rate(component["ScriptError"], component["Executed"])
        component["Unsupported Rate"] = get_rate(component["Unsupported"], component["Executed"])
        component["CDT"] = component["CDT"] + all_secs * num_duts
        total_executed = total_executed + 1
        total_pass_rate = get_rate(total_pass_count, total_executed)
        effective_executed = total_executed - total_unsupported_count - total_envfail_count
        total_effective_rate = get_rate(total_pass_count, effective_executed)
        total_time_taken = total_time_taken + all_secs
        total_dut_time = total_dut_time + all_secs * num_duts
        total_syslog_count = total_syslog_count + syslogs + module_syslogs
        total_envfail_rate = get_rate(total_envfail_count, total_executed)
        total_skipped_rate = get_rate(total_skipped_count, total_executed)
        total_script_error_rate = get_rate(total_script_error_count, total_executed)
        total_unsupported_rate = get_rate(total_unsupported_count, total_executed)
        if func_secs:
            func_time[func] = 0
        if syslogs:
            func_syslogs[func] = 0
        if prolog_secs:
            module["PrologTime"] = 0
        if epilog_secs:
            module["EpilogTime"] = 0
        module["SysLogs"] = 0

    def sort_func(y):
        try:
            PassRate = float(str(y[1]["Pass Rate"]).replace("%", ""))
            Executed = int(y[1]["Executed"])
            return (PassRate, 100000 - Executed)
        except Exception:
            return 0

    last_row_total = False
    sorted_components = OrderedDict(sorted(components.items(), key=sort_func))
    if not last_row_total:
        components = OrderedDict()
        components[report_total_col] = OrderedDict()
        for component in sorted_components:
            components[component] = sorted_components[component]
    else:
        components = sorted_components
        components[report_total_col] = OrderedDict()

    component = components[report_total_col]
    component["Pass Rate"] = total_pass_rate
    component["Executed"] = total_executed
    component["Pass"] = total_pass_count
    component["Non Pass"] = total_executed - total_pass_count
    component["Not Run"] = total_unsupported_count + total_envfail_count
    component["Effective Pass Rate"] = total_effective_rate
    component["Exec Time"] = total_time_taken
    component["SysLogs"] = total_syslog_count
    component["EnvFail"] = total_envfail_count
    component["Env Fail Rate"] = total_envfail_rate
    component["Skipped"] = total_skipped_count
    component["Skipped Rate"] = total_skipped_rate
    component["ScriptError"] = total_script_error_count
    component["Script Error Rate"] = total_script_error_rate
    component["Unsupported"] = total_unsupported_count
    component["Unsupported Rate"] = total_unsupported_rate
    component["CDT"] = total_dut_time

    # remove the columns that are not needed
    for name, component in components.items():
        del component["EnvFail"]
        del component["Skipped"]
        del component["ScriptError"]
        del component["Unsupported"]

    syslog_htm = paths.get_syslog_htm(None, bool(offset))
    rows, cols, links = [], [], {"SysLogs": []}
    colors = {"Pass Rate": [], "Effective Pass Rate": [], "Env Fail Rate": [], "Skipped Rate": [],
              "Script Error Rate": [], "Unsupported Rate": []}
    align = {col: True for col in [feature_col_name, "New {}".format(feature_col_name),
                                   "Regression {}".format(feature_col_name)]}
    for name, component in components.items():
        links["SysLogs"].append(syslog_htm if component["SysLogs"] else None)
        component["Exec Time"] = utils.time_format(int(component["Exec Time"]))
        component["CDT"] = utils.time_format(int(component["CDT"]))
        row = [name]
        row.extend(component.values())
        rows.append(row)
        cols = list(component.keys())
        cols.insert(0, feature_col_name)
        colors["Pass Rate"].append(Result.get_color(component["Pass Rate"]))
        colors["Effective Pass Rate"].append(Result.get_color(component["Effective Pass Rate"]))
        colors["Env Fail Rate"].append(Result.get_color_red(component["Env Fail Rate"]))
        colors["Skipped Rate"].append(Result.get_color_red(component["Skipped Rate"]))
        colors["Script Error Rate"].append(Result.get_color_red(component["Script Error Rate"]))
        colors["Unsupported Rate"].append(Result.get_color_red(component["Unsupported Rate"]))

    utils.write_html_table3(cols, rows, features_htm, links=links, colors=colors, align=align, total=last_row_total)
    utils.write_csv_file(cols, rows, features_csv)

    return cols, total_pass_count, total_executed, total_pass_rate


def features_summary(logs_path, cols, offset, srs={}):

    names, fpaths = ["OverAll"], [paths.get_features_csv(logs_path, bool(offset))]
    if tcmap.get_current_releases() is not None:
        names.extend(["New", "Legacy"])
        fpaths.append(paths.get_new_features_csv(logs_path, bool(offset)))
        fpaths.append(paths.get_regression_features_csv(logs_path, bool(offset)))

    for name, fpath in srs.items():
        names.append(name); fpaths.append(fpath)

    totals = []
    for name, fpath in zip(names, fpaths):
        rows = Result.read_report_csv(fpath, False)
        if len(rows) > 1:
            totals.append(rows[1])
            totals[-1][0] = name
    cols[0] = "Feature Type"
    align = {"Feature Type": True}
    colors = {}
    for row in totals:
        for col, val in zip(cols, row):
            if col in ["Pass Rate", "Effective Pass Rate"]:
                colors.setdefault(col, []).append(Result.get_color(val))
            elif col in ["Env Fail Rate", "Skipped Rate"]:
                colors.setdefault(col, []).append(Result.get_color_red(val))
            elif col in ["Script Error Rate", "Unsupported Rate"]:
                colors.setdefault(col, []).append(Result.get_color_red(val))
    report_csv = paths.get_features_summary_csv(logs_path, bool(offset))
    report_htm = paths.get_features_summary_htm(logs_path, bool(offset))
    utils.write_csv_file(cols, totals, report_csv)
    utils.write_html_table3(cols, totals, report_htm, align=align, colors=colors, total=None)


def features_report(func_rows, tc_rows, results_csv, tcresults_csv, offset=0,
                    features_csv=None, features_htm=None,
                    new_features_csv=None, new_features_htm=None,
                    regression_features_csv=None, regression_features_htm=None,
                    logs_path=None, feature_col_name="Feature Name"
                    ):
    if logs_path is None:
        logs_path = _get_logs_path()[1]

    tc_rows = tc_rows or Result.read_report_csv(tcresults_csv)
    func_rows = func_rows or Result.read_report_csv(results_csv)

    # create the all features report
    features_csv = features_csv or paths.get_features_csv(logs_path, bool(offset))
    features_htm = features_htm or paths.get_features_htm(logs_path, bool(offset))
    cols, total_pass_count, total_executed, total_pass_rate = \
        features_report_int(func_rows, tc_rows, offset, features_csv, features_htm, feature_col_name)
    utils.write_file(features_csv + ".passrate", str(total_pass_rate))
    os.environ["SPYTEST_CURRENT_TOTAL_PASSRATE"] = str(total_pass_rate)
    os.environ["SPYTEST_CURRENT_TOTAL_EXECUTED"] = str(total_executed)
    os.environ["SPYTEST_CURRENT_TOTAL_PASS_CNT"] = str(total_pass_count)

    # check if split features is asked for
    if tcmap.get_current_releases() is None:
        return cols, None

    # create new and regression tc-rows
    tc_rows_new, tc_rows_regression = [], []
    tc_new_dbg, tc_regression_dbg = [], []
    for row in tc_rows:
        tcid = row[offset + 1]
        if tcmap.is_regression_tc(tcid):
            tc_rows_regression.append(row)
            tc_regression_dbg.append(tcid)
        else:
            tc_rows_new.append(row)
            tc_new_dbg.append(tcid)

    # create the new features report
    new_features_csv = new_features_csv or paths.get_new_features_csv(logs_path, bool(offset))
    new_features_htm = new_features_htm or paths.get_new_features_htm(logs_path, bool(offset))
    features_report_int(func_rows, tc_rows_new, offset,
                        new_features_csv, new_features_htm, "New {}".format(feature_col_name))

    # create the regression features report
    regression_features_csv = regression_features_csv or paths.get_regression_features_csv(logs_path, bool(offset))
    regression_features_htm = regression_features_htm or paths.get_regression_features_htm(logs_path, bool(offset))
    features_report_int(func_rows, tc_rows_regression, offset,
                        regression_features_csv, regression_features_htm,
                        "Regression {}".format(feature_col_name))

    return cols, tc_new_dbg


def update_reports(execution_start, execution_end, session_init_time,
                   total_tc_time, dut_count, logs_path=None):

    if logs_path is None:
        logs_path = _get_logs_path()[1]

    tcresults_csv = paths.get_tc_results_csv(logs_path)
    tcresults_htm = paths.get_tc_results_htm(logs_path)
    results_csv = paths.get_results_csv(logs_path)
    results_htm = paths.get_results_htm(logs_path)
    syslog_csv = paths.get_syslog_csv(logs_path)
    stats_csv = paths.get_stats_csv(logs_path)
    msysinfo_csv = paths.get_msysinfo_csv(logs_path)
    fsysinfo_csv = paths.get_fsysinfo_csv(logs_path)
    dsysinfo_csv = paths.get_dsysinfo_csv(logs_path)
    coverage_csv = paths.get_coverage_csv(logs_path)
    scale_csv = paths.get_scale_csv(logs_path)
    featcov_csv = paths.get_featcov_csv(logs_path)

    # read files
    tc_rows = Result.read_report_csv(tcresults_csv)
    func_rows = Result.read_report_csv(results_csv)
    syslog_rows = Result.read_report_csv(syslog_csv)
    stats_rows = Result.read_report_csv(stats_csv)
    msysinfo_rows = Result.read_report_csv(msysinfo_csv)
    fsysinfo_rows = Result.read_report_csv(fsysinfo_csv)
    dsysinfo_rows = Result.read_report_csv(dsysinfo_csv)
    coverage_rows = Result.read_report_csv(coverage_csv)
    scale_rows = Result.read_report_csv(scale_csv)
    featcov_rows = Result.read_report_csv(featcov_csv)

    # features
    features_report(func_rows, tc_rows, results_csv, tcresults_csv, logs_path=logs_path)

    # failed functions
    save_failed_function_list(results_csv)

    # modules
    modules = module_report(func_rows, tc_rows, results_csv, tcresults_csv)

    # test cases
    links, indexes = get_header_info(ReportType.TESTCASES, ["Result", "Module"], False)
    for row in tc_rows:
        mlog = paths.get_mlog_path(row[indexes["Module"]])
        links["Module"].append(mlog)
        links["Result"].append(mlog)
    align = {col: True for col in ["Feature", "TestCase", "Description", "Function", "Module", "Devices"]}
    Result.write_report_html(tcresults_htm, tc_rows, ReportType.TESTCASES, False, links=links, align=align)

    # functions
    links, indexes = get_header_info(ReportType.FUNCTIONS, ["Module", "Result", "Syslogs"], False)
    for row in func_rows:
        syslog_htm = paths.get_syslog_htm()
        mlog = paths.get_mlog_path(row[indexes["Module"]])
        links["Module"].append(mlog)
        links["Result"].append(mlog)
        links["Syslogs"].append(syslog_htm)
    align = {col: True for col in ["Module", "TestFunction", "Description", "Devices", "Doc"]}
    Result.write_report_html(results_htm, func_rows, ReportType.FUNCTIONS, False, links=links, align=align)

    # syslogs
    syslog_htm = paths.get_syslog_htm(logs_path)
    links, indexes = get_header_info(ReportType.SYSLOGS, ["Device", "Module"], False)
    for row in syslog_rows:
        dlog = paths.get_dlog_path(row[indexes["Device"]])
        mlog = paths.get_mlog_path(row[indexes["Module"]])
        links["Device"].append(dlog)
        links["Module"].append(mlog)
    align = {col: True for col in ["Module", "TestFunction", "LogMessage"]}
    Result.write_report_html(syslog_htm, syslog_rows, ReportType.SYSLOGS, False, links=links, align=align)

    # stats
    links, indexes = get_header_info(ReportType.STATS, ["Module"], False)
    for row in stats_rows:
        mlog = paths.get_mlog_path(row[indexes["Module"]])
        links["Module"].append(mlog)
    stats_htm = paths.get_stats_htm(logs_path)
    align = {col: True for col in ["Module", "Function", "Description"]}
    Result.write_report_html(stats_htm, stats_rows, ReportType.STATS, False, links=links, align=align)

    # msysinfo
    links, indexes = get_header_info(ReportType.MSYSINFO, ["Module", "DUTs"], False)
    for row in msysinfo_rows:
        mlog = paths.get_mlog_path(row[indexes["Module"]])
        links["Module"].append(mlog)
        slog = paths.get_session_log()
        links["DUTs"].append(slog)
    msysinfo_htm = paths.get_msysinfo_htm(logs_path)
    align = {col: True for col in ["Module"]}
    Result.write_report_html(msysinfo_htm, msysinfo_rows, ReportType.MSYSINFO, False, links=links, align=align)

    # fsysinfo
    links, indexes = get_header_info(ReportType.FSYSINFO, ["Module", "DUTs"], False)
    for row in fsysinfo_rows:
        mlog = paths.get_mlog_path(row[indexes["Module"]])
        links["Module"].append(mlog)
        slog = paths.get_session_log()
        links["DUTs"].append(slog)
    fsysinfo_htm = paths.get_fsysinfo_htm(logs_path)
    align = {col: True for col in ["Module", "Function"]}
    Result.write_report_html(fsysinfo_htm, fsysinfo_rows, ReportType.FSYSINFO, False, links=links, align=align)

    # dsysinfo
    links, indexes = get_header_info(ReportType.DSYSINFO, ["Module", "DUT"], False)
    for row in dsysinfo_rows:
        mlog = paths.get_mlog_path(row[indexes["Module"]])
        links["Module"].append(mlog)
        slog = paths.get_session_log()
        links["DUT"].append(slog)
    dsysinfo_htm = paths.get_dsysinfo_htm(logs_path)
    align = {col: True for col in ["Module", "Function"]}
    Result.write_report_html(dsysinfo_htm, dsysinfo_rows, ReportType.DSYSINFO, False, links=links, align=align)

    # coverage
    links, indexes = get_header_info(ReportType.COVERAGE, ["Module"], False)
    for row in coverage_rows:
        module = modules.get(row[0], None)
        if module:
            tc_count, tc_pass, time = module["TC Count"], module["TC Pass"], module["Exec Time"]
        else:
            tc_count, tc_pass, time = "", "", ""
        pass_rate = get_rate(tc_pass, tc_count)
        if len(row) <= 5: row.extend(["", "", "", ""])
        row[5], row[6], row[7], row[8] = tc_count, tc_pass, pass_rate, time
        mlog = paths.get_mlog_path(row[indexes["Module"]])
        links["Module"].append(mlog)
    Result.write_report_csv(coverage_csv, coverage_rows, ReportType.COVERAGE, False)
    coverage_htm = paths.get_coverage_htm(logs_path)
    align = {col: True for col in ["Module"]}
    Result.write_report_html(coverage_htm, coverage_rows, ReportType.COVERAGE, False, links=links, align=align)

    # scale
    Result.write_report_csv(scale_csv, scale_rows, ReportType.SCALE, False)
    scale_htm = paths.get_scale_htm(logs_path)
    align = {col: True for col in ["Name", "Platform", "Build", "Module", "Function"]}
    Result.write_report_html(scale_htm, scale_rows, ReportType.SCALE, False, links=None, align=align)

    # featcov
    Result.write_report_csv(featcov_csv, featcov_rows, ReportType.FEATCOV, False)
    featcov_htm = paths.get_featcov_htm(logs_path)
    align = {col: True for col in ["Name", "Platform", "Build", "Module", "Function"]}
    Result.write_report_html(featcov_htm, featcov_rows, ReportType.FEATCOV, False, links=None, align=align)

    # summary
    results_map = get_results_map()
    tc_result_dict = {}
    for key in results_map:
        if key:
            tc_result_dict[key] = 0
    total_tcs = 0
    for row in tc_rows:
        col_result = str(row[2])
        if col_result != "" and col_result is not None:
            col_result = col_result.upper()
            if col_result in tc_result_dict:
                tc_result_dict[col_result] += 1
                total_tcs += 1
            else:
                print(col_result, " is not found in tc results ")

    func_result_dict = {}
    for key in results_map:
        if key:
            func_result_dict[key] = 0
    modules = dict()
    total_funcs = 0
    total_syslogs = 0
    for row in func_rows:
        modules[row[0]] = 1
        col_result = str(row[2])
        syslogs = utils.integer_parse(row[5])
        syslogs = syslogs if syslogs else 0
        total_syslogs = total_syslogs + syslogs
        if col_result:
            col_result = col_result.upper()
            if col_result in func_result_dict:
                func_result_dict[col_result] += 1
                total_funcs += 1
            else:
                print(col_result, " is not found in results ")

    total_gcovs = len(glob.glob("{}/*_gcov.tar.gz".format(logs_path)))

    data = ""
    start_time = execution_start.replace(microsecond=0)
    end_time = execution_end.replace(microsecond=0)
    data = "{}\nExecution Started = {}".format(data, start_time)
    data = "{}\nExecution Completed = {}".format(data, end_time)
    exec_time = utils.time_diff(execution_start, execution_end, True)
    data = "{}\nExecution Time = {}".format(data, exec_time)
    data = "{}\nSession Init Time = {}".format(data, session_init_time)
    data = "{}\nTests Time = {}".format(data, total_tc_time)

    for item, value in func_result_dict.items():
        data = "{}\n{} = {}".format(data, item, value)
    data = "{}\nFunction Count = {}".format(data, total_funcs)
    data = "{}\nModule Count = {}".format(data, len(modules))
    data = "{}\nTest Count = {}".format(data, total_tcs)
    data = "{}\nPass Count = {}".format(data, tc_result_dict["PASS"])
    data = "{}\nPass Rate = {}".format(data, get_rate(tc_result_dict["PASS"], total_tcs))
    data = "{}\nSysLog Count = {}".format(data, total_syslogs)
    data = "{}\nGCOV Count = {}".format(data, total_gcovs)
    data = "{}\nDUT Count = {}".format(data, dut_count)

    return data


def _build_sub_report_items(spec):
    include, include_items = spec.get("include", None), None
    if include:
        folders = include.get("folders", None)
        if folders:
            include_items = collect_items(None, [], [], *folders)

    exclude, exclude_items = spec.get("exclude", None), None
    if exclude:
        folders = exclude.get("folders", None)
        if folders:
            exclude_items = collect_items(None, [], [], *folders)

    return include_items, exclude_items


def sub_reports(logs_path, consolidated=True):

    retval = OrderedDict()
    wa = get_work_area()
    if not wa or not wa.cfg.sub_report:
        return retval

    for name, spec in wa.cfg.sub_report.items():
        if not spec.get("items", None):
            spec["items"] = _build_sub_report_items(spec)
        dst_log_path = batch.sub_report_path(logs_path, name)
        try:
            features_csv = sub_report(logs_path, dst_log_path, consolidated,
                                      spec["items"][0], spec["items"][1], name)
            retval[name] = features_csv
        except Exception as exp:
            print_ftrace("Failed to create sub-reports: {}".format(exp))
            for msg in utils.stack_trace(None, True):
                print_ftrace(msg)
    return retval


def sub_report(src_log_path, dst_log_path=None, consolidated=False,
               include=None, exclude=None, name=None):
    tcresults_csv = paths.get_tc_results_csv(src_log_path, consolidated)
    results_csv = paths.get_results_csv(src_log_path, consolidated)
    tc_rows = Result.read_report_csv(tcresults_csv)
    func_rows = Result.read_report_csv(results_csv)

    offset = 1 if consolidated else 0
    if include is not None:
        func_rows_filtered = []
        for row in func_rows:
            func = row[offset + 1]
            if not func or func in include:
                func_rows_filtered.append(row)
        func_rows = func_rows_filtered

        tc_rows_filtered = []
        for row in tc_rows:
            tc = row[offset + 1]
            func = tcmap.get_func(tc, row[offset + 6])
            if not func or func in include:
                tc_rows_filtered.append(row)
        tc_rows = tc_rows_filtered

    if exclude is not None:
        func_rows_filtered = []
        for row in func_rows:
            func = row[offset + 1]
            if not func or func not in exclude:
                func_rows_filtered.append(row)
        func_rows = func_rows_filtered

        tc_rows_filtered = []
        for row in tc_rows:
            tc = row[offset + 1]
            func = tcmap.get_func(tc, row[offset + 6])
            if not func or func not in exclude:
                tc_rows_filtered.append(row)
        tc_rows = tc_rows_filtered

    dst_log_path = dst_log_path or src_log_path
    features_csv = paths.get_features_csv(dst_log_path, consolidated)
    features_htm = paths.get_features_htm(dst_log_path, consolidated)
    feature_name = "{} Feature Name".format(name or "")
    features_report_int(func_rows, tc_rows, offset, features_csv, features_htm, feature_name)
    tcresults_csv = paths.get_tc_results_csv(dst_log_path, consolidated)
    Result.write_report_csv(tcresults_csv, tc_rows, ReportType.TESTCASES, is_batch=consolidated)

    modules_csv = paths.get_modules_csv(dst_log_path, consolidated)
    modules_htm = paths.get_modules_htm(dst_log_path, consolidated)
    module_report(func_rows, tc_rows, None, None, 1, modules_csv=modules_csv, modules_htm=modules_htm)

    return features_csv


def combined_report(dst_log_path, src_log_paths, consolidated=True):
    tc_rows, func_rows, report_files = {}, {}, OrderedDict()
    offset = 1 if consolidated else 0
    allstr = "_all" if consolidated else ""
    tc_rows[None], func_rows[None], report_files[None] = [], [], None
    for name, src_log_path in src_log_paths:
        tcresults_csv = paths.get_tc_results_csv(src_log_path, consolidated)
        results_csv = paths.get_results_csv(src_log_path, consolidated)
        tc_rows[name] = Result.read_report_csv(tcresults_csv)
        tc_rows[None].extend(tc_rows[name])
        func_rows[name] = Result.read_report_csv(results_csv)
        func_rows[None].extend(func_rows[name])

    for name, ent in func_rows.items():
        prefix = name or "Combined"
        all_features_csv = os.path.join(dst_log_path, "{}{}_features.csv".format(prefix, allstr))
        all_features_htm = os.path.join(dst_log_path, "{}{}_features.htm".format(prefix, allstr))
        new_features_csv = os.path.join(dst_log_path, "{}_new_features.csv".format(prefix))
        new_features_htm = os.path.join(dst_log_path, "{}_new_features.htm".format(prefix))
        reg_features_csv = os.path.join(dst_log_path, "{}_new_reg_features.csv".format(prefix))
        reg_features_htm = os.path.join(dst_log_path, "{}_new_reg_features.htm".format(prefix))
        features_report(ent, tc_rows[name], None, None, offset, all_features_csv, all_features_htm,
                        new_features_csv, new_features_htm, reg_features_csv, reg_features_htm,
                        None, "{} Feature Name".format(prefix))
        modules_csv = os.path.join(dst_log_path, "{}{}_modules.csv".format(prefix, allstr))
        modules_htm = os.path.join(dst_log_path, "{}{}_modules.htm".format(prefix, allstr))
        module_report(ent, tc_rows[name], None, None, offset, modules_csv=modules_csv,
                      modules_htm=modules_htm, module_col_name="{} Module Name".format(prefix))
        report_files[name] = [all_features_htm, new_features_htm, reg_features_htm, modules_htm]

    return report_files


def script_dev_report():
    filename = "rel400_schedule_legacy_breakdown.csv,rel400_schedule_weekly_breakdown.csv"
    rows = tcmap._load_csvs("SPYTEST_SCHEDULE_BREAKDOWN", filename)
    for row in rows[1:]:
        print(row)


def constraints_report(runs, is_chip_constraints):
    module_constraints = {}
    for _, logs_path in runs:
        for row in utils.read_csv(os.path.join(logs_path, "results_coverage_all.csv")):
            module, platforms, chips = row[2], row[4], row[5]
            platforms = [platform.strip() for platform in platforms.split(",") if platform.strip()]
            chips = [chip.strip() for chip in chips.split(",") if chip.strip()]
            if not module or len(platforms) != len(chips):
                # print("Error: Invalid line {}".format(row))
                continue
            constraints = []
            for i, (platform, chip) in enumerate(zip(platforms, chips)):
                if not is_chip_constraints:
                    constraints.append("D{}MODEL={}".format(i + 1, platform))
                else:
                    constraints.append("D{}CHIP={}".format(i + 1, chip))
            module_constraints[module] = " ".join(constraints)
    for module, constraint in module_constraints.items():
        print("--change-modules-csv {},{} --noop".format(module, constraint))


def generate_excel_syslog_report(csv_file):
    pivot_messages, uniq_messages, total, lvls = {}, {}, 1, []
    for row in utils.read_csv(csv_file):
        lvl, module, msg = row[7:10]
        if lvl == "LogLevel": continue
        if lvl not in lvls: lvls.append(lvl)
        module = module.split("[")[0]
        pivot_messages.setdefault(module, {})
        pivot_messages[module].setdefault(lvl, 0)
        pivot_messages[module][lvl] += 1
        uniq_messages.setdefault(msg, 0)
        uniq_messages[msg] += 1
        total += 1

    uniq_messages = sorted(uniq_messages.items(), key=lambda x: x[1], reverse=True)
    uniq_cols, uniq_rows = ["Message", "Occurances", "Percentage"], []
    for key, value in uniq_messages:
        uniq_rows.append([key, value, get_rate(value, total)])

    pivot_cols, pivot_rows = lvls, []
    for module, d in pivot_messages.items():
        pivot_row, total = [module], 0
        for lvl in lvls:
            count = d.get(lvl, 0)
            total += count
            pivot_row.append(count)
        pivot_row.append(total)
        pivot_rows.append(pivot_row)
    pivot_cols = ["Module"]
    pivot_cols.extend(lvls)
    pivot_cols.append("Total")

    from utilities import excel
    wb = excel.create_workbook()
    excel.create_sheet(wb, "pivot", pivot_cols, pivot_rows)
    excel.create_sheet(wb, "unique", uniq_cols, uniq_rows)
    wb.save(os.path.splitext(csv_file)[0] + '.xlsx')


def combine_results(args):
    if not args.path:
        print("--path is needed for combined report")
        return
    is_combined_input = env.match("SPYTEST_GENERATE_COMBINED_INPUT", "1", "1")
    report_files = combined_report(args.path, args.run, is_combined_input)
    if not args.email: return
    server = {"sendor": args.email_from, "host": args.email_host}
    recipients = utils.split_byall(args.email)
    subject, body = "Combined Report: ", ""
    for name, src_log_path in args.run:
        binfo = utils.read_build_info(os.path.join(src_log_path, "build.txt"))
        build = binfo.get("build", "UNKNOWN")
        subject = "{} {}: {}".format(subject, name, build)
        if args.url_prefix:
            name = "<a href='{}{}/dashboard.html'>{}</a>".format(args.url_prefix, src_log_path, name)
        text = "{}: {}".format(name, build)
        from spytest.framework import append_email_body
        body = append_email_body(body, None, text)
    body = append_email_body(body, None, "")
    for name, htm_list in report_files.items():
        if args.email_few_reports and name is not None:
            continue
        for htm in htm_list:
            body = append_email_body(body, htm)
    subject = args.email_subject or subject
    mail.send(server, recipients, subject, body, [], True)


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Generate SPyTest reports.')
    parser.add_argument("--run", action="append", default=None, nargs=2,
                        help="<name> <path>", required=True)
    parser.add_argument("--path", action="store", default=None)
    parser.add_argument("--email", action="store")
    parser.add_argument("--email-subject", action="store")
    parser.add_argument("--email-from", action="store", default="SpyTest@broadcom.com")
    parser.add_argument("--email-host", action="store", default="mailhost.broadcom.net")
    parser.add_argument("--url-prefix", action="store")
    parser.add_argument("--add-nes", action="store_true")
    parser.add_argument("--email-few-reports", action="store_true")
    actions = ["combine", "consolidate", "scriptdev", "compare", "constraints",
               "constraints-platform", "constraints-chip", "syslog-excel"]
    parser.add_argument("--action", action="store", default="combine", choices=actions)

    args, unknown = parser.parse_known_args()
    if unknown: parser.error("unknown arguments: {}".format(unknown))

    tcmap.load()

    if args.action == "scriptdev":
        script_dev_report()
        sys.exit(0)

    if args.action in ["constraints", "constraints-platform"]:
        constraints_report(args.run, False)
        sys.exit(0)

    if args.action == "constraints-chip":
        constraints_report(args.run, True)
        sys.exit(0)

    if args.action == "syslog-excel":
        for _, logs_path in args.run:
            fin = os.path.join(logs_path, "results_syslog_all.csv")
            generate_excel_syslog_report(fin)
        sys.exit(0)

    if args.action == "compare":
        if len(args.run) != 2:
            print("Need two --run arguments for comparision")
            rv1 = rv2 = False
        else:
            [name1, path1], [name2, path2] = args.run[0], args.run[1]
            cmp_path0 = args.path or os.getenv("SPYTEST_COMPARE_REPORT_DIR", "")
            cmp_path0 = cmp_path0 or os.path.join(path1, "compare")
            cmp_csv = paths.get_file_path("modules", "csv", cmp_path0)

            def trace(a):
                print(a)
            rv1 = compare_results(path1, path2, cmp_csv, trace, name1, name2, args.url_prefix)
            cmp_csv = paths.get_file_path("syslogs", "csv", cmp_path0)
            rv2 = compare_syslogs(path1, path2, cmp_csv, trace, name1, name2, args.url_prefix)
        sys.exit(0 if rv1 and rv2 else 1)

    if args.action == "consolidate":
        for _, src_log_path in args.run:
            consolidated_results(src_log_path, add_nes=args.add_nes)
        sys.exit(0)

    if args.action == "combine":
        combine_results(args)
        sys.exit(0)


if __name__ == "__main__":
    main()
