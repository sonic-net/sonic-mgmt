import os
import re
import sys
import time
import argparse
import pytest
import pyfiglet

from spytest.version import get_git_ver
from spytest.framework import parse_batch_args
from spytest.framework import parse_suite_files
from spytest import env
from spytest import cmdargs
from spytest.ftrace import print_ftrace, ftrace_reset
from spytest.ftrace import ftrace_prefix

import utilities.common as utils


def _banner():
    result = pyfiglet.figlet_format("SPyTest")
    print_ftrace(result)


def _print_git_ver():
    sha = get_git_ver()
    print_ftrace("\nVERSION: {}\n".format(sha))


def remove_arg(name, addl_args):
    if name in sys.argv:
        off, index = 2, sys.argv.index(name)
    else:
        off, index, name2 = 1, None, "{}=".format(name)
        for i, value in enumerate(sys.argv):
            if value.startswith(name2):
                index = i
                break
    if index:
        new_argv = []
        new_argv.extend(sys.argv[:index])
        new_argv.extend(addl_args)
        new_argv.extend(sys.argv[index + off:])
        sys.argv = new_argv


def _parse_args_early(pre_parse=False):

    # pytest hack to let it wotk with absolute paths for testbed and tclist
    parser = argparse.ArgumentParser(description='Process SPyTest arguments.',
                                     add_help=False, formatter_class=cmdargs.HelpFormatter)
    if pre_parse:
        parser.add_argument("--args-file", action="store", default=None,
                            help="spytest arguments from file path")
    parser.add_argument("--testbed-file", action="store", default=None,
                        help="testbed file path -- default: ./testbed.yaml")
    parser.add_argument("--test-suite", action="append",
                        default=[], help="test suites")
    parser.add_argument("--test-suite-section", action="store",
                        default=None, help="test suite section name")
    parser.add_argument("--test-suite-exclude", action="append",
                        default=[], help="tests that need to be excluded")
    parser.add_argument("--test-paths", action="append",
                        default=[], help="test paths")
    parser.add_argument("--tclist-file", action="append",
                        default=None, help="test case list file path")
    parser.add_argument("--logs-path", action="store",
                        default=None, help="logs folder -- default: .")
    parser.add_argument("--logs-level", action="store",
                        default="info", help="logs level -- default: info")
    parser.add_argument("--log-level", action="store", dest="logs_level",
                        default="info", help="logs level -- default: info")
    parser.add_argument("--results-prefix", action="store",
                        default=None, help="Prefix to be used for results.")
    parser.add_argument("--file-mode", action="store_true", default=False,
                        help="Execute in file mode -- default: false")
    parser.add_argument("-n", "--numprocesses", action="store", default=None,
                        type=int, help="number of preocessese")
    parser.add_argument("--tclist-bucket", action="append", default=None,
                        help="use test cases from buckets")
    for bucket in range(1, env.max_buckets + 1):
        parser.add_argument("--bucket-{}".format(bucket), action="store", default=None, nargs="*",
                            help="needed topology for bucket-{}.".format(bucket))
    parser.add_argument("--env", action=cmdargs.validate_env(), default={}, nargs='+',
                        metavar=("<name>=<value>"), help="environment variables")
    parser.add_argument("--max-time", action="append", default=[], nargs='+')
    parser.add_argument("--exclude-devices", action="store", default=None,
                        help="exclude given duts from testbed")
    parser.add_argument("--include-devices", action="store", default=None,
                        help="include given duts from testbed")
    parser.add_argument("--open-config-api", action="store", default='GNMI',
                        help="specified open-config request API type -- default: gNMI")
    parser.add_argument("--noop", action="store_true", default=False,
                        help="No operation, to be used while using optional arguments")
    parser.add_argument("--augment-modules-csv", action="append", default=[], nargs="*",
                        help="Add additional lines to modules.csv")
    parser.add_argument("--append-modules-csv", action="append", default=[], nargs="*",
                        help="Add additional lines to modules.csv")
    parser.add_argument("--change-modules-csv", action="append", default=[], nargs="*",
                        help="change lines in modules.csv")

    args, unknown = parser.parse_known_args()

    # set the environment early
    for name, value in args.env.items():
        os.environ[name] = value

    if args.logs_path:
        os.environ["SPYTEST_LOGS_PATH"] = args.logs_path

    return args, unknown


def _parse_args(pre_parse=False):

    args, unknown = _parse_args_early(pre_parse)

    # parse the bucket options
    argsdict = vars(args)
    if argsdict["tclist_bucket"]:
        utils.remove_duplicates(argsdict["tclist_bucket"])
    tclist_bucket_csv = ",".join(argsdict["tclist_bucket"] or "")
    bucket_list = []
    for bucket in range(1, env.max_buckets + 1):
        value = argsdict["bucket_{}".format(bucket)]
        if value is None:
            continue
        bucket_list.append(str(bucket))
        tclist_bucket_csv = ",".join(bucket_list)
        if not value:
            continue
        os.environ["SPYTEST_TOPO_{}".format(bucket)] = " ".join(value)

    # update sys.argv with arguments from suite args
    if args.test_suite or args.test_suite_exclude:
        dbg_msg = ""
        for test_suite in args.test_suite:
            dbg_msg = "{}+ {} ".format(dbg_msg, test_suite)
        for test_suite in args.test_suite_exclude:
            dbg_msg = "{}- {} ".format(dbg_msg, test_suite)
        os.environ["SPYTEST_SUITE_NAME_ARG"] = dbg_msg
        if args.test_suite:
            addl_args = parse_suite_files(args.test_suite, args.test_suite_exclude, args.test_suite_section)[0]
        else:
            addl_args = parse_suite_files([], args.test_suite_exclude, args.test_suite_section, ume=True)[0]
        if args.test_suite and args.test_suite_exclude:
            remove_arg("--test-suite", addl_args)
            remove_arg("--test-suite-exclude", [])
        elif args.test_suite:
            remove_arg("--test-suite", addl_args)
        elif args.test_suite_exclude:
            remove_arg("--test-suite-exclude", addl_args)
        print_ftrace("Suite Arguments {}".format(" ".join(addl_args)))
        print_ftrace("Expanded Arguments {}".format(" ".join(sys.argv)))
        os.environ["SPYTEST_SUITE_ARGS"] = " ".join(addl_args)
        return _parse_args(pre_parse=pre_parse)

    if pre_parse and args.args_file:
        # read arguments from file
        user_root = env.get("SPYTEST_USER_ROOT")
        if user_root and not os.path.isabs(args.args_file):
            filepath = os.path.join(user_root, args.args_file)
        else:
            filepath = args.args_file
        file_args = []
        for line in utils.read_lines(filepath):
            file_args.extend(utils.split_with_quoted_strings(line))

        # update sys.argv with arguments from file
        index = sys.argv.index("--args-file")
        new_argv = []
        new_argv.extend(sys.argv[:index])
        new_argv.extend(file_args)
        new_argv.extend(sys.argv[index + 2:])
        sys.argv = new_argv

        # update SPYTEST_CMDLINE_ARGS with arguments from file
        app_cmdline = env.get("SPYTEST_CMDLINE_ARGS", "")
        app_args = utils.split_with_quoted_strings(app_cmdline)
        index = app_args.index("--args-file")
        app_new_args = []
        app_new_args.extend(app_args[:index])
        for arg in file_args:
            app_new_args.append("'{}'".format(arg) if " " in arg else arg)
        app_new_args.extend(app_args[index + 2:])
        os.environ["SPYTEST_CMDLINE_ARGS"] = " ".join(app_new_args)

        return _parse_args()

    sys.argv = [sys.argv[0]]
    sys.argv.extend(unknown)

    for name, value in args.env.items():
        print_ftrace("setting environment {} = {}".format(name, value))
        os.environ[name] = value

    if args.exclude_devices:
        os.environ["SPYTEST_TESTBED_EXCLUDE_DEVICES"] = args.exclude_devices
        sys.argv.extend(["--exclude-devices", args.exclude_devices])
    if args.include_devices:
        os.environ["SPYTEST_TESTBED_INCLUDE_DEVICES"] = args.include_devices
        sys.argv.extend(["--include-devices", args.include_devices])
    if args.testbed_file:
        os.environ["SPYTEST_TESTBED_FILE"] = args.testbed_file
    if args.tclist_file:
        os.environ["SPYTEST_TCLIST_FILE"] = ",".join(args.tclist_file)
    if args.logs_path:
        os.environ["SPYTEST_LOGS_PATH"] = args.logs_path
    os.environ["SPYTEST_LOGS_LEVEL"] = args.logs_level

    if args.open_config_api:
        os.environ["SPYTEST_OPENCONFIG_API"] = args.open_config_api

    if args.test_paths:
        os.environ["SPYTEST_TEST_PATHS"] = ",".join(args.test_paths)

    prefix = ""
    prefix = "results"
    if args.results_prefix:
        file_prefix = args.results_prefix
    elif args.file_mode and prefix:
        file_prefix = prefix
    elif tclist_bucket_csv:
        file_prefix = prefix
    elif prefix:
        file_prefix = "{}_{}".format(prefix, time.strftime("%Y_%m_%d_%H_%M_%S"))
    else:
        file_prefix = "{}".format(time.strftime("%Y_%m_%d_%H_%M_%S"))
    os.environ["SPYTEST_FILE_PREFIX"] = file_prefix
    ftrace_reset()

    # filemode is needed in more places
    if args.file_mode:
        os.environ["SPYTEST_FILE_MODE"] = "1"
        sys.argv.append("--file-mode")

    for name, value in args.max_time:
        sys.argv.extend(["--max-time", name, value])

    for opt in args.append_modules_csv:
        sys.argv.extend(["--append-modules-csv", " ".join(opt)])
    for opt in args.augment_modules_csv:
        sys.argv.extend(["--augment-modules-csv", " ".join(opt)])
    for opt in args.change_modules_csv:
        sys.argv.extend(["--change-modules-csv", " ".join(opt)])

    append_modules_csv = args.append_modules_csv or args.augment_modules_csv
    addl_args = parse_batch_args(args.numprocesses, tclist_bucket_csv,
                                 append_modules_csv, args.change_modules_csv)
    sys.argv.extend(addl_args)

    try:
        version_tuple = [int(s) for s in re.findall(r'\d+', pytest.__version__)]
        if version_tuple[0] >= 7:
            os.environ["SPYTEST_USE_FULL_NODEID"] = "1"
    except Exception:
        pass

    seed = utils.get_random_seed()
    print_ftrace("SPYTEST_RANDOM_SEED used = {}".format(seed))
    return args


def trace_env():
    for x in os.environ:
        line = "export {} {}".format(x, os.getenv(x))
        ftrace_prefix("export", line)


def main(silent=False):
    _parse_args_early()
    if not silent:
        _banner()
    _parse_args(True)
    trace_env()
    if not silent:
        _print_git_ver()
    retval = pytest.main()
    return retval
