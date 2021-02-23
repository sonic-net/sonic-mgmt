import os
import sys
import glob
import csv
import utilities.common as utils

def cmp_pass_rate(old, new):
    try:
        old = float(old.replace("%", ""))
        new = float(new.replace("%", ""))
        if new > old: return "+"
        if new < old: return "-"
    except Exception: pass
    return ""

def time_parse(timestr):
    try:
        (h,m,s) = timestr.split(':')
        secs = int(h) * 3600 + int(m) * 60 + int(s)
    except Exception:
        secs = 0
    return secs

def cmp_exec_time(old, new):
    old = time_parse(old)
    new = time_parse(new)
    if (new - old) > 60: return "-"
    if (old - new) > 60: return "+"
    return ""

def cmp_int(old, new):
    try: old = int(old)
    except Exception: old = 0
    try: new = int(new)
    except Exception: new = 0
    if (new - old) > 0: return "-"
    if (old - new) > 0: return "+"
    return ""

cmp_funcs = {
    'Pass Rate': cmp_pass_rate, 'Exec Time': cmp_exec_time,
    'Script Error': cmp_int, 'Sys Logs': cmp_int, 'Dut Fail': cmp_int
}
include_cols = ['Pass Rate', 'Exec Time', 'Script Error', 'Sys Logs', 'Dut Fail']

def _read(csv_file):
    cols, rows = [], []
    with open(csv_file, 'r') as read_obj:
        csv_reader = csv.reader(read_obj)
        list_of_rows = list(csv_reader)
        if list_of_rows:
            cols = list_of_rows[0]
            col_indexes = {'' : 0}
            for index, col in enumerate(cols):
                if col in include_cols:
                    col_indexes[col] = index
            for row in list_of_rows[1:-1]:
                new_row = [row[0]]
                for col in include_cols:
                    new_row.append(row[col_indexes[col]])
                rows.append(new_row)
    return cols, rows

def folders(old, new):
    if not os.path.isdir(old): return "{} is not folder".format(old), None, None
    if not os.path.isdir(new): return "{} is not folder".format(new), None, None
    old_fmt1 = "{}/*_result_all_modules.csv".format(old)
    old_fmt2 = "{}/*_result_modules.csv".format(old)
    old_file1 = glob.glob(old_fmt1)
    old_file2 = glob.glob(old_fmt2)
    old_file = old_file1 or old_file2
    new_fmt1 = "{}/*_result_all_modules.csv".format(new)
    new_fmt2 = "{}/*_result_modules.csv".format(new)
    new_file1 = glob.glob(new_fmt1)
    new_file2 = glob.glob(new_fmt2)
    new_file = new_file1 or new_file2
    if not old_file: return "{} or {} not found".format(old_fmt1, old_fmt2), None, None
    if not new_file: return "{} or {} not found".format(new_fmt1, new_fmt2), None, None

    _, old_file_rows = _read(old_file[0])
    _, new_file_rows = _read(new_file[0])
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

    cols, report_rows = [""], []
    for name, props in modules.items():
        report_row = [name]
        report_row.extend(props)
        for index, col in enumerate(include_cols):
            old_val = props[index]
            new_val = props[index + len(include_cols)]
            cmp_val = cmp_funcs[col](old_val, new_val)
            report_row.append(cmp_val)
        report_rows.append(report_row)

    for i in range(1, 3):
        for col in include_cols:
            cols.append(col + " " + str(i))
    for col in include_cols:
        cols.append(col + " CMP")
    return None, cols, report_rows

if __name__ == "__main__":
    old = sys.argv[1]
    new = sys.argv[2]
    result = sys.argv[3]
    err, cols, rows = folders(old, new)
    utils.write_csv_file(cols, rows, result)

