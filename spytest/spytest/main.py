import os
import sys
import time
import argparse
import random
import pytest
import pyfiglet

from spytest.version import get_git_ver
from spytest.framework import parse_batch_args
import utilities.common as utils

def _banner():
    result = pyfiglet.figlet_format("SPyTest")
    print(result)

def _print_git_ver():
    sha = get_git_ver()
    print("\nVERSION: {}\n".format(sha))

def _parse_args(pre_parse=False):
    # pytest hack to let it wotk with absolute paths for testbed and tclist
    parser = argparse.ArgumentParser(description='Process SpyTest arguments.',
                                     add_help=False)
    if pre_parse:
        parser.add_argument("--args-file", action="store", default=None,
                            help="spytest arguments from file path")
    parser.add_argument("--testbed-file", action="store", default=None,
                        help="testbed file path -- default: ./testbed.yaml")
    parser.add_argument("--tclist-file", action="store",
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
    parser.add_argument("--env", action="append", default=[],
                        nargs=2, help="environment variables")

    args, unknown = parser.parse_known_args()
    if pre_parse and args.args_file:
        # read arguments from file
        user_root = os.getenv("SPYTEST_USER_ROOT")
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
        new_argv.extend(sys.argv[index+2:])
        sys.argv = new_argv

        # update SPYTEST_CMDLINE_ARGS with arguments from file
        app_cmdline = os.getenv("SPYTEST_CMDLINE_ARGS", "")
        app_args = utils.split_with_quoted_strings(app_cmdline)
        index = app_args.index("--args-file")
        app_new_args = []
        app_new_args.extend(app_args[:index])
        for arg in file_args:
            app_new_args.append("'{}'".format(arg) if " " in arg else arg)
        app_new_args.extend(app_args[index+2:])
        os.environ["SPYTEST_CMDLINE_ARGS"] = " ".join(app_new_args)

        return _parse_args()

    sys.argv = [sys.argv[0]]
    sys.argv.extend(unknown)

    for name, value in args.env:
        print("setting environment {} = {}".format(name, value))
        os.environ[name] = value

    if args.testbed_file:
        os.environ["SPYTEST_TESTBED_FILE"] = args.testbed_file
    if args.tclist_file:
        os.environ["SPYTEST_TCLIST_FILE"] = args.tclist_file
    if args.logs_path:
        os.environ["SPYTEST_LOGS_PATH"] = args.logs_path
    os.environ["SPYTEST_LOGS_LEVEL"] = args.logs_level

    prefix="results"
    if args.results_prefix:
        file_prefix = args.results_prefix
        os.environ["SPYTEST_RESULTS_PREFIX"] = file_prefix
    else:
        file_prefix = "{0}_{1}".format(prefix, time.strftime("%Y_%m_%d_%H_%M"))
    os.environ["SPYTEST_FILE_PREFIX"] = file_prefix

    # filemode is needed in more places
    if args.file_mode:
        os.environ["SPYTEST_FILE_MODE"] = "1"
        sys.argv.append("--file-mode")

    addl_args = parse_batch_args(args.numprocesses, args.tclist_bucket)
    sys.argv.extend(addl_args)

    os.environ["SPYTEST_RAMDOM_SEED"] = str(random.randint(10000,20000))

def main(silent=False):
    if not silent:
        _banner()
    _parse_args(True)
    if not silent:
        _print_git_ver()
    pytest.main()


