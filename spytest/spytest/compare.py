import os
import sys
import glob
import csv

import utilities.common as utils


def cmp_pass_rate(old, new):
    try:
        old = float(old.replace("%", ""))
        new = float(new.replace("%", ""))
        if new > old:
            return "Superior"
        if new < old:
            return "Inferior"
    except Exception:
        pass
    return ""


def time_parse(timestr):
    try:
        (h, m, s) = timestr.split(':')
        secs = int(h) * 3600 + int(m) * 60 + int(s)
    except Exception:
        secs = 0
    return secs


def cmp_exec_time(old, new):
    old = time_parse(old)
    new = time_parse(new)
    if (new - old) > 60:
        return "Inferior"
    if (old - new) > 60:
        return "Superior"
    return ""


def cmp_int(old, new):
    try:
        old = int(old)
    except Exception:
        old = 0
    try:
        new = int(new)
    except Exception:
        new = 0
    if (new - old) > 0:
        return "Inferior"
    if (old - new) > 0:
        return "Superior"
    return ""


cmp_funcs = {
    'Pass Rate': cmp_pass_rate, 'Exec Time': cmp_exec_time,
    'Script Error': cmp_int, 'Sys Logs': cmp_int, 'Dut Fail': cmp_int,
    'TC Count': cmp_int, 'TC Pass': cmp_int
}
include_cols = ['Pass Rate', 'Exec Time', 'Script Error', 'Sys Logs', 'Dut Fail', 'TC Count', 'TC Pass']
include_cols = ['Pass Rate', 'TC Count']
compare_cols = ['Pass Rate']


def _read(csv_file):
    cols, rows = [], []
    with open(csv_file, 'r') as read_obj:
        csv_reader = csv.reader(read_obj)
        list_of_rows = list(csv_reader)
        if list_of_rows:
            cols = list_of_rows[0]
            col_indexes = {'': 0}
            for index, col in enumerate(cols):
                if col in include_cols:
                    col_indexes[col] = index
            for row in list_of_rows[1:-1]:
                new_row = [row[0]]
                for col in include_cols:
                    new_row.append(row[col_indexes[col]])
                rows.append(new_row)
    return cols, rows


def results(old, new, old_suffix=None, new_suffix=None):
    if not os.path.isdir(old):
        return "{} is not folder".format(old), None, None, None
    if not os.path.isdir(new):
        return "{} is not folder".format(new), None, None, None
    old_bldf = "{}/build.txt".format(old)
    old_fmt1 = "{}/*_modules_all.csv".format(old)
    old_fmt2 = "{}/*_modules.csv".format(old)
    old_file1 = glob.glob(old_fmt1)
    old_file2 = glob.glob(old_fmt2)
    old_file = old_file1 or old_file2
    new_bldf = "{}/build.txt".format(new)
    new_fmt1 = "{}/*_modules_all.csv".format(new)
    new_fmt2 = "{}/*_modules.csv".format(new)
    new_file1 = glob.glob(new_fmt1)
    new_file2 = glob.glob(new_fmt2)
    new_file = new_file1 or new_file2
    if not old_file:
        return "{} or {} not found".format(old_fmt1, old_fmt2), None, None, None
    if not new_file:
        return "{} or {} not found".format(new_fmt1, new_fmt2), None, None, None

    old_file_rows = _read(old_file[0])[1]
    new_file_rows = _read(new_file[0])[1]
    old_build_info = utils.read_build_info(old_bldf)
    new_build_info = utils.read_build_info(new_bldf)
    modules = {}

    for row in old_file_rows:
        name, props = row[0], list(row[1:])
        modules[name] = props
        for _ in range(len(props)):
            modules[name].append('')

    for row in new_file_rows:
        name, props = row[0], list(row[1:])
        if name not in modules:
            modules[name] = []
            for _ in range(len(props)):
                modules[name].append('')
        else:
            for _ in range(len(props)):
                modules[name].pop()
        modules[name].extend(props)

    cols, report_rows = ["Module Name"], []
    for name, props in modules.items():
        report_row = [name]
        report_row.extend(props)
        for index, col in enumerate(include_cols):
            if col in compare_cols:
                old_val = props[index]
                new_val = props[index + len(include_cols)]
                cmp_val = cmp_funcs[col](old_val, new_val)
                report_row.append(cmp_val)
        report_rows.append(report_row)

    # add total row
    report_row = report_rows.pop(0)
    report_rows.append(report_row)

    for suffix in [old_suffix or "1", new_suffix or "2"]:
        for col in include_cols:
            cols.append(col + " " + suffix)
    for col in include_cols:
        if col in compare_cols:
            cols.append(col + " CMP")

    old_build = old_build_info.get("build", old_suffix or "1")
    new_build = new_build_info.get("build", new_suffix or "2")
    addl_cols = []
    addl_cols.append(["", "1"])
    addl_cols.append([old_build, len(include_cols)])
    addl_cols.append([new_build, len(include_cols)])
    addl_cols.append(["", "1"])

    return None, cols, report_rows, addl_cols


def syslogs(old, new, old_suffix=None, new_suffix=None):
    if not os.path.isdir(old):
        return "{} is not folder".format(old), None, None, None
    if not os.path.isdir(new):
        return "{} is not folder".format(new), None, None, None
    old_bldf = "{}/build.txt".format(old)
    old_fmt1 = "{}/*_syslog_all.csv".format(old)
    old_fmt2 = "{}/*_syslog.csv".format(old)
    old_file1 = glob.glob(old_fmt1)
    old_file2 = glob.glob(old_fmt2)
    old_file = old_file1 or old_file2
    new_bldf = "{}/build.txt".format(new)
    new_fmt1 = "{}/*_syslog_all.csv".format(new)
    new_fmt2 = "{}/*_syslog.csv".format(new)
    new_file1 = glob.glob(new_fmt1)
    new_file2 = glob.glob(new_fmt2)
    new_file = new_file1 or new_file2
    if not old_file:
        return "{} or {} not found".format(old_fmt1, old_fmt2), None, None, None
    if not new_file:
        return "{} or {} not found".format(new_fmt1, new_fmt2), None, None, None

    old_file_rows = utils.read_csv(old_file[0])[1:]
    new_file_rows = utils.read_csv(new_file[0])[1:]
    old_build_info = utils.read_build_info(old_bldf)
    new_build_info = utils.read_build_info(new_bldf)
    modules, levels, old_modules, new_modules = {}, {}, {}, {}

    # read old module counts
    for row in old_file_rows:
        name, level = row[3], row[7]
        module = old_modules.setdefault(name, {})
        module[level] = module.setdefault(level, 0) + 1
        module = old_modules.setdefault(None, {})
        module[level] = module.setdefault(level, 0) + 1
        levels[level] = 1
        modules[name] = []
        levels[level] = 1
        modules[name] = []

    # read new module counts
    for row in new_file_rows:
        name, level = row[3], row[7]
        module = new_modules.setdefault(name, {})
        module[level] = module.setdefault(level, 0) + 1
        module = new_modules.setdefault(None, {})
        module[level] = module.setdefault(level, 0) + 1
        levels[level] = 1
        modules[name] = []

    # create report rows
    report_rows = []
    for module, params in modules.items():
        report_row = [module]
        for level in levels:
            c1 = old_modules.get(module, {}).get(level, 0)
            c2 = new_modules.get(module, {}).get(level, 0)
            params.extend([c1, c2, bool(c1 > c2)])
            report_row.extend([c1, c2, cmp_int(c1, c2)])
        report_rows.append(report_row)

    # create report columns
    cols = ["Module Name"]
    for col in levels:
        cols.append(col + " " + old_suffix or "1")
        cols.append(col + " " + new_suffix or "1")
        cols.append(col + " CMP")

    # create total row
    report_row = [""]
    for level in levels:
        c1 = old_modules.get(None, {}).get(level, 0)
        c2 = new_modules.get(None, {}).get(level, 0)
        report_row.extend([c1, c2, cmp_int(c1, c2)])
    report_rows.append(report_row)

    # create additional header
    old_build = old_build_info.get("build", old_suffix or "1")
    new_build = new_build_info.get("build", new_suffix or "2")
    addl_cols = [["{} Vs {}".format(old_build, new_build), str(len(cols))]]

    return None, cols, report_rows, addl_cols


if __name__ == "__main__":
    old = sys.argv[1]
    new = sys.argv[2]
    result = sys.argv[3]
    err, cols, rows, _ = results(old, new)
    utils.write_csv_file(cols, rows, result)
