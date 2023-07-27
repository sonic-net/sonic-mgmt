import os

import utilities.common as utils
from spytest import env
from spytest.ftrace import ftrace


def _parse(suites, fin, fex, tin, tex, section, is_exclude=False):
    path = os.path.dirname(__file__)
    path = os.path.join(path, '..', "reporting", "suites")

    errs, lines, args, sin, sex = [], [], [], [], []
    for suite in suites:
        if not suite: continue
        fname = os.path.join(os.path.abspath(path), suite)
        if not os.path.exists(fname):
            errs.append("Suite File {} is not found".format(fname))
            continue
        lines.extend(utils.read_lines(fname))

    if errs:
        print("Failed to find suite files")
        print("\n".join(errs))
        utils.abort_run(9)

    for line in lines:
        if not line or line.startswith("#"): continue
        if line.startswith("+tree:"):
            for file in utils.list_files(line[6:].strip(), "test_*.py"):
                utils.list_append(fin, file)
        elif line.startswith("-tree:"):
            for file in utils.list_files(line[6:].strip(), "test_*.py"):
                utils.list_append(fex, file)
        elif line.startswith("+dir:"):
            for file in utils.list_files(line[5:].strip(), "test_*.py", False):
                utils.list_append(fin, file)
        elif line.startswith("-dir:"):
            for file in utils.list_files(line[5:].strip(), "test_*.py", False):
                utils.list_append(fex, file)
        elif line.startswith("+suite:"):
            utils.list_append(sin, line[7:].strip())
        elif line.startswith("-suite:"):
            if not is_exclude:
                utils.list_append(sex, line[7:].strip())
        elif line.startswith("+file:"):
            utils.list_append(fin, line[6:].strip())
        elif line.startswith("-file:"):
            if not is_exclude:
                utils.list_append(fex, line[6:].strip())
        elif line.startswith("+test:"):
            utils.list_append(tin, line[6:].strip())
        elif line.startswith("-test:"):
            if not is_exclude:
                utils.list_append(tex, line[6:].strip())
        elif line.startswith("+tclist:"):
            for test in utils.read_lines(line[8:].strip()):
                utils.list_append(tin, test)
        elif line.startswith("-tclist:"):
            for test in utils.read_lines(line[8:].strip()):
                if not is_exclude:
                    utils.list_append(tex, test)
        elif line.startswith("+args:"):
            args.extend(line[6:].strip().split())
    if sin:
        _parse(sin, fin, fex, tin, tex, section, False)
    if sex:
        _parse(sex, fex, fin, tex, tin, section, True)
    return fin, fex, tin, tex, args


def parse(sin, sex, section=None, ume=False):
    fex, fin, tex, tin, _ = _parse(sex, [], [], [], [], section, True)
    fin, fex, tin, tex, opts = _parse(sin, fin, fex, tin, tex, section)

    infra_tests = ["test_spytest_infra_first", "test_spytest_infra_second"]
    infra_tests.append("test_spytest_infra_last")
    infra_file = "test_spytest_infra_1.py"

    # remove infra module from fin
    infra_module = None
    for f in fin:
        if infra_file in f:
            infra_module = f
            break
    if infra_module:
        fin.remove(infra_module)

    # ignore non infra modules
    ignore = []
    for f in fex:
        if infra_file not in f and f not in fin:
            if not ume:
                opts.extend(["--ignore", f])
            else:
                opts.extend(["--exclude-module", os.path.basename(f)])
            ignore.append(f)

    tclist_csv, tclist_csv_exclude = [], []
    include_modules = []
    use_include_modules = bool(env.match("SPYTEST_INCLUDE_MODULE_OPTION", "1", "0"))
    if not use_include_modules:
        use_include_modules = bool("--env SPYTEST_INCLUDE_MODULE_OPTION 1" in " ".join(opts))
    for t in tin:
        if t not in tex:
            if fin:
                if use_include_modules:
                    include_modules = fin
                    fin = []
                else:
                    # This is applicable only when files are not specified
                    continue
            tclist_csv.append(t)

    # include framework tests/modules
    if not infra_module:
        pass
    elif include_modules:
        include_modules.append(infra_module)
    elif tclist_csv:
        tclist_csv.extend(infra_tests)
    elif fin:
        fin.append(infra_module)

    for t in tex:
        if t not in infra_tests:
            tclist_csv_exclude.append(t)

    for module in include_modules: opts.extend(["--include-module", module])
    if tclist_csv: opts.extend(["--tclist-csv", ",".join(tclist_csv)])
    if tclist_csv_exclude: opts.extend(["--tclist-csv-exclude", ",".join(tclist_csv_exclude)])

    opts.append("--noop")
    for f in fin:
        if f not in fex or infra_file in f:
            opts.append(f)

    fin = include_modules or fin

    utils.banner("SUITE IN: {} EX: {}".format(sin, sex), func=ftrace)
    for f in fin: ftrace("+FILE: {}".format(f))
    for f in fex: ftrace("-FILE: {}".format(f))
    for t in tclist_csv: ftrace("+TEST: {}".format(t))
    for t in tclist_csv_exclude: ftrace("-TEST: {}".format(t))
    for i in ignore: ftrace(" IGN: {}".format(i))
    for o in opts: ftrace(" OPT: {}".format(o))
    utils.banner(None, func=ftrace)

    return opts, fin, ignore, tclist_csv, tclist_csv_exclude
