
import os
import csv
from collections import OrderedDict
import threading

import utilities.common as utils
from spytest.dicts import SpyTestDict
import spytest.env as env

tcmap = SpyTestDict()
repeat_info = False
g_lock = threading.Lock()

def get():
    if not tcmap:
        load()
    return tcmap

def get_repeated():
    if not repeat_info:
        return {}
    if env.get("SPYTEST_REPEAT_MODULE_SUPPORT", "0") == "0":
        return {}
    return get().repeated

def get_tclist(func):
    if func in tcmap.tclist:
        return tcmap.tclist[func]
    parts = func.split("[")
    if len(parts) == 1:
        return []
    if parts[0] not in tcmap.tclist:
        return []
    retval = []
    for tc in tcmap.tclist[parts[0]]:
        retval.append("{}[{}".format(tc, parts[1]))
    return retval

def get_comp(tcid, default=None):
    tcid2 = tcid.split("[")[0]
    if tcid2 in tcmap.comp:
        return tcmap.comp[tcid2]
    return default

def get_func(tcid, default=None):
    tcid2 = tcid.split("[")[0]
    if tcid2 in tcmap.func:
        return tcmap.func[tcid2]
    return default

def get_module_info(path, repeat_name="", repeat_topo="", onload=False):
    name = os.path.basename(path)
    if g_lock: g_lock.acquire()
    rv = SpyTestDict()
    rv.name = name
    rv.uitype = ""
    rv.fcli = 0
    rv.tryssh = 0
    rv.random = 0
    rv.maxtime = 0
    rv.repeat_name = repeat_name
    rv.repeat_topo = repeat_topo
    rv.path = path
    if not repeat_info:
        if name not in tcmap.module_info:
            if "--" in name and not onload:
                name = name.split("--")[0] + ".py"
        if name in tcmap.module_info:
            rv = tcmap.module_info[name]
        else:
            tcmap.module_info[name] =  rv
    elif name not in tcmap.module_info:
        tcmap.module_info[name] =  rv
    elif not repeat_name:
        rv = tcmap.module_info[name]
    elif tcmap.module_info[name].repeat_name != repeat_name:
        if name not in tcmap.repeated:
            tcmap.repeated[name] = [tcmap.module_info[name]]
        tcmap.repeated[name].append(rv)
    if g_lock: g_lock.release()
    return rv

def get_function_info(name):
    if g_lock: g_lock.acquire()
    if "function_info" not in tcmap:
        tcmap.function_info = OrderedDict()
    if name not in tcmap.function_info:
        rv = SpyTestDict()
        rv.maxtime = 0
        tcmap.function_info[name] =  rv
    if g_lock: g_lock.release()
    return tcmap.function_info[name]

def _add_entry(age, cadence, comp, tcid, func):
    if tcid in tcmap.cadence:
        msg = "duplicate test case id {}"
        tcmap.errors.append(msg.format(tcid))
    if func not in tcmap.tclist:
        tcmap.tclist[func] = []
    if tcid not in tcmap.tclist[func]:
        tcmap.tclist[func].append(tcid)
    else:
        msg = "duplicate test case id {}"
        tcmap.errors.append(msg.format(tcid))
    tcmap.comp[tcid] = comp
    tcmap.cadence[tcid] = cadence
    tcmap.func[tcid] = func

def _load_csv(csv_file, path):
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

def load(do_verify=True, items=None):
    tcmap.tclist = OrderedDict()
    tcmap.comp = OrderedDict()
    tcmap.cadence = OrderedDict()
    tcmap.func = OrderedDict()
    tcmap.modules = OrderedDict()
    tcmap.module_info = OrderedDict()
    tcmap.function_info = OrderedDict()
    tcmap.repeated = OrderedDict()
    tcmap.errors = []
    tcmap.warnings = []
    tcmap.non_mapped = []

    #Module,UIType,FasterCLI,TrySSH,MaxTime
    info_csv = env.get("SPYTEST_MODULE_INFO_CSV_FILENAME", "module_info.csv")
    for row in _load_csv(info_csv, "reporting"):
        if len(row) < 6: continue
        name, uitype, fcli, tryssh, random, maxtime = [str(i).strip() for i in row[:6]]
        if name.strip().startswith("#"): continue
        repeat_name = "" if len(row) < 7 else row[6]
        repeat_topo = "" if len(row) < 8 else row[7]
        ent = get_module_info(name, repeat_name, repeat_topo, True)
        ent.uitype = uitype
        ent.fcli = utils.integer_parse(fcli, 0)
        ent.tryssh = utils.integer_parse(tryssh, 0)
        ent.random = utils.integer_parse(random, 0)
        ent.maxtime = utils.integer_parse(maxtime, 0)

    #Function,MaxTime
    info_csv = env.get("SPYTEST_FUNCTION_INFO_CSV_FILENAME", "function_info.csv")
    for row in _load_csv(info_csv, "reporting"):
        if len(row) < 2: continue
        name, maxtime = [str(i).strip() for i in row[:2]]
        if name.strip().startswith("#"): continue
        ent = tcmap.get_function_info(name)
        ent.maxtime = utils.integer_parse(maxtime, 0)

    tcmap_csv = env.get("SPYTEST_TCMAP_CSV_FILENAME", "tcmap.csv")
    for row in _load_csv(tcmap_csv, "reporting"):
        if len(row) == 4:
            #  TODO treat the data as module
            (age, cadence, comp, name0) = (row[0], row[1], row[2], row[3])
            for name in utils.list_files(name0, "test_*.py"):
                if name in tcmap.modules:
                    msg = "duplicate module {}"
                    tcmap.errors.append(msg.format(name))
                    continue
                module = SpyTestDict()
                module.age = age
                module.cadence = cadence
                module.comp = comp
                module.name = name
                tcmap.modules[name] = module
            continue
        if len(row) < 5:
            if row:
                print("Invalid line", row)
            continue
        (age, cadence, comp, tcid, func) = (row[0], row[1], row[2], row[3], row[4])
        if age.strip().startswith("#"):
            continue
        _add_entry(age, cadence, comp, tcid, func)

    # verify the tcmap if required
    if do_verify: verify(items)

    return tcmap

def verify(items=None):

    items = items or []

    # expand the modules
    for name, module in tcmap.modules.items():
        for item in items:
            if item.location[0] != name:
                if item.location[0] != os.path.basename(name):
                    continue
            func = item.location[2]
            # use function name for TC
            _add_entry(module.age, module.cadence, module.comp, func, func)

    # check if any function mapped in multiple cadences
    for func, tcid_list in tcmap.tclist.items():
        cadences = dict()
        for tcid in tcid_list:
            cadences[tcmap.cadence[tcid]] = 1
        if len(cadences) > 1:
            msg = "function {} is mapped to {} testcases in multiple cadences {}"
            tcmap.errors.append(msg.format(func, len(tcid_list), cadences))

    # check if any function mapped in multiple components
    for func, tcid_list in tcmap.tclist.items():
        components = dict()
        for tcid in tcid_list:
            components[tcmap.comp[tcid]] = 1
        if len(components) > 1:
            msg = "function {} is mapped to {} testcases in multiple components {}"
            #TODO: enable this once the issues are fixed in tcmap.csv
            #tcmap.errors.append(msg.format(func, len(tcid_list), components.keys()))
            tcmap.warnings.append(msg.format(func, len(tcid_list), components.keys()))

    # find items without tcmap entry
    for item in items:
        func = item.location[2]
        tclist = get_tclist(func)
        count = len(tclist)
        if count > 1: continue
        if count == 0 or tclist[0] == func:
            tcmap.non_mapped.append(func)

