#! /usr/bin/env python

import argparse
import datetime
import os

from mock_for_switch import get_duthost

from base_test import do_test_add_rack, backup_minigraph, restore_orig_minigraph
from helpers import *


def run_test(skip_load, skip_test, skip_generic):
    global data_dir, orig_db_dir, clet_db_dir, files_dir

    set_print()

    duthost = get_duthost()
    if not duthost:
        log_error("Wrapper for execution in SONiC switch only")
        return -1

    if not restore_orig_minigraph(duthost):
        backup_minigraph(duthost)
    else:
        skip_load = True

    do_test_add_rack(duthost, skip_test=skip_test, skip_generic=skip_generic,
        skip_load=skip_load)
    

def main():
    if os.geteuid() != 0:
        exit("You need Root user privileges")

    parser=argparse.ArgumentParser(description="Sample for argparse")
    parser.add_argument("-d", "--dir", help="Test Data dir", required=True)
    parser.add_argument("-l", "--skip-load", help="skip initial minigraph loading", 
            action='store_true', default=False)
    parser.add_argument("-s", "--skip-test", help="skip any testing; create clet files only", 
            action='store_true', default=False)
    parser.add_argument("-g", "--skip-generic", help="skip generic updater testing; executes clet test only", 
            action='store_true', default=False)

    args = parser.parse_args()

    if not os.path.exists(args.dir):
        print("dir does not exist")
        return -1

    work_dir = os.path.join(args.dir, datetime.datetime.now().strftime("%d_%m_%Y_%H_%M"))

    try:
        os.system("rm -rf {}".format(work_dir))
        os.mkdir(work_dir)
    except OSError as error:
        print("Failed to create {} with err:{}".format(work_dir, str(error)))
        return -1

    os.chdir(work_dir)

    print("Work dir for this run is {}".format(os.getcwd()))

    run_test(args.skip_load, args.skip_test, args.skip_generic)


if __name__ == "__main__":
    main()


