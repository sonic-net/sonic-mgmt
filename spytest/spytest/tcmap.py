import os
import re
import csv
import threading
from functools import cmp_to_key
from collections import OrderedDict

from spytest.dicts import SpyTestDict
from spytest import env

import utilities.common as utils

_tcm = SpyTestDict()
g_lock = threading.Lock()


def get(reload=False):
    if not _tcm or reload:
        load()
    return _tcm


def get_tclist(func):
    if func in _tcm.tclist:
        return _tcm.tclist[func]
    parts = func.split("[")
    if len(parts) == 1:
        return []
    if parts[0] not in _tcm.tclist:
        return []
    retval = []
    for tc in _tcm.tclist[parts[0]]:
        retval.append("{}[{}".format(tc, parts[1]))
    return retval


def get_current_releases():
    return env.get("SPYTEST_TCMAP_CURRENT_RELEASES", None)


def is_regression_tc(tcid):
    releases = get_current_releases()
    if not releases:
        return None
    if tcid not in _tcm.release:
        return False
    if _tcm.release[tcid] in utils.csv2list(releases):
        return False
    return True


def get_comp(tcid, default=None):
    tcid2 = tcid.split("[")[0]
    if tcid2 in _tcm.comp:
        return _tcm.comp[tcid2]
    return default


def get_func(tcid, default=None):
    tcid2 = tcid.split("[")[0]
    if tcid2 in _tcm.func:
        return _tcm.func[tcid2]
    return default


def get_owner(name):
    return _tcm.owners.get(name, "")


def get_module_info(path, onload=False):
    name = os.path.basename(path)
    if g_lock: g_lock.acquire()
    rv = SpyTestDict()
    rv.name = name
    rv.uitype = ""
    rv.fcli = 0
    rv.fcli = env.getint("SPYTEST_TCMAP_DEFAULT_FASTER_CLI", "0")
    rv.tryssh = env.getint("SPYTEST_TCMAP_DEFAULT_TRYSSH", "0")
    rv.random = 0
    rv.maxtime = 0
    rv.ts = 1
    rv.path = path
    if name not in _tcm.module_info:
        if "--" in name and not onload:
            name = name.split("--")[0] + ".py"
    if name in _tcm.module_info:
        rv = _tcm.module_info[name]
    else:
        _tcm.module_info[name] = rv
    if g_lock: g_lock.release()
    return rv


def get_function_info(name):
    if g_lock: g_lock.acquire()
    if "function_info" not in _tcm:
        _tcm.function_info = OrderedDict()
    if name not in _tcm.function_info:
        rv = SpyTestDict()
        rv.maxtime = 0
        _tcm.function_info[name] = rv
    if g_lock: g_lock.release()
    return _tcm.function_info[name]


def _add_entry(release, comp, tcid, func, marker=False):
    if tcid in _tcm.release:
        msg = "duplicate test case id {}"
        _tcm.errors.append(msg.format(tcid))
    if func not in _tcm.tclist:
        _tcm.tclist[func] = []
    if tcid not in _tcm.tclist[func]:
        _tcm.tclist[func].append(tcid)
    elif tcid not in _tcm.release:
        # duplicate error message not yet added
        msg = "duplicate test case id {}."
        _tcm.errors.append(msg.format(tcid))

    _tcm.marker[tcid] = "".join([_tcm.marker.get(tcid, ""), "N" if marker else "O"])
    _tcm.release[tcid] = release
    _tcm.comp[tcid] = comp
    _tcm.func[tcid] = func


def _load_csv(csv_file, path):
    if path is not None:
        path = os.path.join(os.path.dirname(__file__), '..', path)
        csv_file = os.path.join(os.path.abspath(path), csv_file)

    if os.path.exists(csv_file):
        filepath = csv_file
    else:
        return []
    rows = []
    with open(filepath, 'r') as fd:
        for row in csv.reader(fd):
            rows.append(row)
        fd.close()
    return rows


def _load_csv_files(csv_files):
    rows = []
    for csv_file in csv_files.split(","):
        for row in _load_csv(csv_file, "reporting"):
            rows.append(row)
    return rows


def _load_csvs(name, default):
    csv_files = env.get(name, default)
    return _load_csv_files(csv_files)


def load(do_verify=True, items=None, tcmap_csv=None):
    _tcm.tclist = OrderedDict()
    _tcm.marker = OrderedDict()
    _tcm.release = OrderedDict()
    _tcm.comp = OrderedDict()
    _tcm.func = OrderedDict()
    _tcm.modules = OrderedDict()
    _tcm.owners = OrderedDict()
    _tcm.module_info = OrderedDict()
    _tcm.function_info = OrderedDict()
    _tcm.errors = []
    _tcm.warnings = []
    _tcm.non_mapped = []

    _tcm.platform_info = read_platform_info()

    for row in _load_csvs("SPYTEST_MODULE_OWNERS_CSV_FILENAME", "owners.csv"):
        if len(row) < 2: continue
        name, owner = row[0].strip(), ",".join(row[1:])
        if name.startswith("#"): continue
        _tcm.owners[name] = owner

    # Module,UIType,FasterCLI,TrySSH,MaxTime,TS
    for row in _load_csvs("SPYTEST_MODULE_INFO_CSV_FILENAME", "module_info.csv"):
        if len(row) < 6: continue
        name, uitype, fcli, tryssh, random, maxtime = [str(i).strip() for i in row[:6]]
        if name.strip().startswith("#"): continue
        ts = "1" if len(row) < 7 else row[6]
        ent = get_module_info(name, True)
        ent.uitype = uitype
        ent.fcli = utils.integer_parse(fcli, env.getint("SPYTEST_TCMAP_DEFAULT_FASTER_CLI", "0"))
        ent.tryssh = utils.integer_parse(tryssh, env.getint("SPYTEST_TCMAP_DEFAULT_TRYSSH", "0"))
        ent.random = utils.integer_parse(random, 0)
        ent.maxtime = utils.integer_parse(maxtime, 0)
        ent.ts = utils.integer_parse(ts, 1)

    # Function,MaxTime
    for row in _load_csvs("SPYTEST_FUNCTION_INFO_CSV_FILENAME", "function_info.csv"):
        if len(row) < 2: continue
        name, maxtime = [str(i).strip() for i in row[:2]]
        if name.strip().startswith("#"): continue
        ent = _tcm.get_function_info(name)
        ent.maxtime = utils.integer_parse(maxtime, 0)

    csv_files = tcmap_csv or env.get("SPYTEST_TCMAP_CSV_FILENAME", "tcmap.csv")
    for row in _load_csv_files(csv_files):
        # Release,Feature,TestCaseID,FunctionName
        if len(row) == 3:
            #  TODO treat the data as module
            release, comp, name0 = row[0], row[1], row[2]
            if release.strip().startswith("#"):
                continue
            for name in utils.list_files(name0, "*.py"):
                if name in _tcm.modules:
                    msg = "duplicate module {}"
                    _tcm.errors.append(msg.format(name))
                    continue
                module = SpyTestDict()
                module.release = release
                module.comp = comp
                module.name = name
                _tcm.modules[name] = module
            continue
        if len(row) < 4:
            if row and not row[0].strip().startswith("#"):
                print("Invalid line", row)
            continue
        release, comp, tcid, func = row[0], row[1], row[2], row[3]
        if release.strip().startswith("#"):
            continue
        _add_entry(release, comp, tcid, func)

    # verify the tcmap if required
    if do_verify: verify(items)

    return _tcm


def verify(items=None):

    items = items or []

    # create hashes to search module
    fspath_map, basename_map = {}, {}
    for name, module in _tcm.modules.items():
        fspath = os.path.join(os.path.dirname(__file__), '..', 'tests', name)
        fspath = os.path.abspath(fspath)
        fspath_map[fspath] = module
        basename_map[os.path.basename(name)] = module

    # expand the modules
    for item in items:
        module = _tcm.modules.get(item.location[0], None)
        module = module or basename_map.get(item.location[0], None)
        module = module or fspath_map.get(item.fspath.strpath, None)
        if not module: continue
        func = item.location[2]
        _add_entry(module.release, module.comp, func, func)

    # check if any function mapped in multiple releases
    for func, tcid_list in _tcm.tclist.items():
        releases = dict()
        for tcid in tcid_list:
            releases[_tcm.release[tcid]] = 1
        if len(releases) > 1:
            msg = "function {} is mapped to {} testcases in multiple releases {}"
            _tcm.errors.append(msg.format(func, len(tcid_list), releases))

    # check if any function mapped in multiple components
    for func, tcid_list in _tcm.tclist.items():
        components = dict()
        for tcid in tcid_list:
            components[_tcm.comp[tcid]] = 1
        if len(components) > 1:
            msg = "function {} is mapped to {} testcases in multiple components {}"
            # TODO: enable this once the issues are fixed in tcmap.csv
            # _tcm.errors.append(msg.format(func, len(tcid_list), components.keys()))
            _tcm.warnings.append(msg.format(func, len(tcid_list), components.keys()))

    # find items without tcmap entry
    for item in items:
        func = item.location[2]
        tclist = get_tclist(func)
        count = len(tclist)
        if count > 1: continue
        if count == 0 or tclist[0] == func:
            _tcm.non_mapped.append(func)


def parse_module_csv_row(row):
    if not row or row[0].startswith("#"):
        return "#", 0, 0, 0

    if len(row) == 2:
        # happens when --change-module-csv with just
        # module name and additional constraints
        return 0, 0, row[0], [row[1]]

    if len(row) < 3:
        print("1. invalid module params: {}".format(row))
        return "#", 0, 0, 0

    tpref = utils.integer_parse(row[2])
    if tpref is not None: row.pop(2)
    if len(row) < 3:
        print("2. invalid module params: {}".format(row))
        return "#", 0, 0, 0
    topo = row[3:] if len(row) > 3 else []

    bucket, order, name0 = [str(i).strip() for i in row[:3]]
    if bucket.startswith("#"): return "#", 0, 0, 0
    return bucket, order, name0, topo


def get_module_csv_path(module_csv):
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    reporting = os.path.join(root, "reporting")
    retval = []
    for filepath in module_csv.split(","):
        csv_file = filepath
        if not os.path.exists(filepath):
            csv_file = os.path.join(reporting, filepath)
            if not os.path.exists(csv_file):
                print("module csv {} not found".format(filepath))
                continue
            retval.append(csv_file)
    return retval


def read_module_csv(append_modules_csv=None, change_modules_csv=None,
                    module_csv=None):
    module_csv = module_csv or env.get("SPYTEST_MODULE_CSV_FILENAME", "modules.csv")
    module_rows, repeated, rows = [], {}, []

    # read the csv files
    for csv_file in get_module_csv_path(module_csv):
        with open(csv_file, 'r') as fd:
            for row in csv.reader(fd):
                rows.append(row)
            fd.close()

    # append augmented lines
    for line in append_modules_csv or []:
        line2 = " ".join(utils.make_list(line))
        for row in csv.reader([line2]):
            rows.append(row)

    # rows dict
    row_dict = {}
    for row in rows:
        bucket, order, name0, topo = parse_module_csv_row(row)
        if not bucket.startswith("#"):
            row_dict[name0] = [bucket, order, name0, topo]

    # parse changed lines
    change_modules1, change_modules2, renamed = {}, {}, {}
    for line in change_modules_csv or []:
        line2 = " ".join(utils.make_list(line))
        for row in csv.reader([line2]):
            bucket, order, name0, topo = parse_module_csv_row(row)

            # use module name even when the repeat name is specified
            parts = name0.split(".py.")
            name = "{}.py".format(parts[0]) if len(parts) > 1 else name0
            if name0 not in row_dict:
                # repeat name is specified
                renamed[name] = name0

            # when only constraints are specified order will be 0
            if order != 0:
                change_modules1[name] = bucket, order, name, topo
            else:
                change_modules2[name] = topo

    # parse the rows
    for row in rows:
        bucket, order, name0, topo = parse_module_csv_row(row)
        if bucket.startswith("#"):
            continue
        if name0 in change_modules1:
            bucket, order, name0, topo = change_modules1[name0]
        elif name0 in change_modules2:
            topo[-1] = " ".join([topo[-1], change_modules2[name0][0]])

        # get the repeat name if specified with --change-module-csv
        name0 = renamed.get(name0, name0)
        parts = name0.split(".py.")
        if len(parts) > 1:
            if env.get("SPYTEST_REPEAT_MODULE_SUPPORT") == "0":
                continue
            name = "{}--{}.py".format(parts[0], parts[1])
            module_row = [bucket, order, name]
            pname = "{}.py".format(parts[0])
            if pname not in repeated:
                repeated[pname] = []
            found = False
            for data in repeated[pname]:
                if data.repeat_name == parts[1]:
                    found = True
                    break
            if found:
                continue
            data = SpyTestDict(repeat_name=parts[1],
                               repeat_topo=",".join(topo))
            repeated[pname].append(data)
        else:
            module_row = [bucket, order, name0]
        module_row.extend(topo)
        module_rows.append(module_row)

    return module_csv, module_rows, repeated, renamed


def read_platform_info():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    csv_file = os.path.join(root, "reporting", "platform-info.csv")

    retval = {}
    if os.path.exists(csv_file):
        with open(csv_file, 'r') as fd:
            for row in csv.reader(fd):
                if len(row) < 4 or "#" in row[0]:
                    continue
                platform, nos, chip, rev = row[0:4]
                retval[platform] = SpyTestDict()
                retval[platform].nos = nos
                retval[platform].chip = chip
                retval[platform].chip_rev = rev
                retval[platform].chip_disp = get_chip_disp(chip, rev)
                platform_disp = platform if len(row) == 4 else row[4]
                retval[platform].platform_disp = platform_disp
            fd.close()

    return retval


def get_all_chips():
    all_chips = []
    all_chips.append(["TH", "NA", "TH"])
    all_chips.append(["TH2", "NA", "TH2"])
    all_chips.append(["TH3", "NA", "TH3"])
    all_chips.append(["TD2", "NA", "TD2"])
    all_chips.append(["TD3", "X2", "TD3-X2"])
    all_chips.append(["TD3", "X3", "TD3-X3"])
    all_chips.append(["TD3", "X5", "TD3-X5"])
    all_chips.append(["TD3", "X7", "TD3-X7"])
    all_chips.append(["TD4", "X9", "TD4-X9"])
    all_chips.append(["TD4", "X11", "TD4-X11"])
    all_chips.append(["TH4", "NA", "TH4"])
    return all_chips


def validate_chip_disp(chip):
    chip = chip.replace("-NA", "")
    chip = chip.replace("TH3-X7", "TH3")
    if chip == "TH1": return "TH"
    return chip.strip()


def get_chip_disp(chip, chip_rev):
    if chip and chip_rev and chip_rev not in ["NA", "UNKNOWN"]:
        retval = "{}-{}".format(chip, chip_rev)
    else:
        retval = chip
    return validate_chip_disp(retval)


def get_all_chips_new():
    return list(get().platform_info.values())


def get_all_platforms():
    return list(get().platform_info.keys())


def get_platform_info(platform):
    return get().platform_info.get(platform, {})


def get_chip_platforms(chip_disp):
    retval = []
    for platform, data in get().platform_info.items():
        if chip_disp == data.chip_disp:
            retval.append(platform)
    return retval


def inventory(func, tcid, release, feature):
    _add_entry(release, feature, tcid, func, True)


def read_coverage_history(csv_file):
    cols, rows = None, []
    if os.path.exists(csv_file):
        fd = open(csv_file, 'r')
        for row in csv.reader(fd):
            if not cols:
                cols = row
            else:
                rows.append(row)
        fd.close()

    chip_cov, platform_cov = {}, {}
    platform_start, chip_start = -1, -1
    if cols:
        if "Platform CV" in cols:
            platform_start = cols.index("Platform CV") + 1
        if "CHIP CV" in cols:
            chip_start = cols.index("CHIP CV") + 1
        elif "Chip CV" in cols:
            chip_start = cols.index("Chip CV") + 1
    if platform_start < 0 or chip_start < 0:
        return chip_cov, platform_cov

    for row in rows:
        module = row[0]
        chip_cov[module] = {}
        platform_cov[module] = {}
        for index, col in enumerate(cols):
            if index < chip_start or index == platform_start - 1:
                continue
            elif index < platform_start:
                chip_cov[module][col] = row[index]
            else:
                platform_cov[module][col] = row[index]
    return chip_cov, platform_cov


def _print_msg(msg):
    print(msg)


def save(match="ON", filepath=None, printerr=None):
    printerr = printerr or _print_msg
    tcm = get()
    lines, funcs = [], []
    for func, testcases in tcm.tclist.items():
        if func in funcs:
            continue
        funcs.append(func)
        testcases = utils.find_duplicate(testcases)[1]
        for tc in testcases:
            marker = tcm.marker.get(tc, "O")
            if match == "O" and "O" != marker:
                continue
            if match == "N" and "N" != marker:
                continue
            release = tcm.release.get(tc, "") or ""
            release = release.replace(" ", "").replace("_", "")
            if not release:
                printerr("=========== no release {}".format(tc))
                continue
            try:
                lines.append(",".join([release, tcm.comp[tc], tc, func]))
            except Exception:
                printerr("=========== exception check {}".format(tc))

    def cmp_items(a, b):
        a = re.sub(r"^Buzznik,", "Buzznik1.0", a)
        b = re.sub(r"^Buzznik,", "Buzznik1.0", b)
        a = re.sub(r"^Buzznik\+,", "Buzznik2.0", a)
        b = re.sub(r"^Buzznik\+,", "Buzznik2.0", b)
        if a > b:
            return 1
        if a == b:
            return 0
        return -1
    lines.sort(key=cmp_to_key(cmp_items))
    lines.insert(0, "#Release,Feature,TestCaseID,FunctionName")
    if filepath:
        utils.write_file(filepath, "\n".join(lines))
    return lines
