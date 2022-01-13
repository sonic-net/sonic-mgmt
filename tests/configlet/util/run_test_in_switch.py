#! /usr/bin/env python

import argparse
import datetime
import os

from mock_for_switch import get_duthost

from base_test import do_test_add_rack, backup_minigraph, restore_orig_minigraph
from helpers import *


def run_test(skip_load=False, skip_clet_test=False,
        skip_generic_add=False, skip_generic_rm=False,
        hack_apply=False, skip_prepare=False):
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

    do_test_add_rack(duthost, skip_load=skip_load,
            skip_clet_test=skip_clet_test,
            skip_generic_add=skip_generic_add,
            skip_generic_rm=skip_generic_rm,
            hack_apply=hack_apply,
            skip_prepare=skip_prepare)
    

def main():
    if os.geteuid() != 0:
        exit("You need Root user privileges")

    parser=argparse.ArgumentParser(description="Sample for argparse")
    parser.add_argument("-d", "--dir", help="Test Data dir", required=True)
    parser.add_argument("-w", "--use-exist", help="Use data dir as working dir", 
            action='store_true', default=False)
    parser.add_argument("-l", "--skip-load", help="skip initial minigraph loading", 
            action='store_true', default=False)
    parser.add_argument("-c", "--skip-clet-test",
            help="skip clet testing; create clet files only", 
            action='store_true', default=False)
    parser.add_argument("-a", "--skip-generic-add",
            help="skip add via generic updater testing", 
            action='store_true', default=False)
    parser.add_argument("-r", "--skip-generic-rm",
            help="skip remove via generic updater testing", 
            action='store_true', default=False)
    parser.add_argument("-k", "--hack-apply",
            help="skip any hack to cover generic-updater issues", 
            action='store_true', default=False)

    args = parser.parse_args()

    if not os.path.exists(args.dir):
        print("dir does not exist")
        return -1

    if not args.use_exist:
        work_dir = os.path.join(args.dir, datetime.datetime.now().strftime("%d_%m_%Y_%H_%M"))
        try:
            os.system("rm -rf {}".format(work_dir))
            os.mkdir(work_dir)
        except OSError as error:
            print("Failed to create {} with err:{}".format(work_dir, str(error)))
            return -1
    else:
        work_dir = args.dir
        skip_load = True

    os.chdir(work_dir)

    print("Work dir for this run is {}".format(os.getcwd()))

    run_test(skip_load=args.skip_load, skip_clet_test=args.skip_clet_test,
            skip_generic_add=args.skip_generic_add,
            skip_generic_rm=args.skip_generic_rm,
            hack_apply=args.hack_apply,
            skip_prepare = args.use_exist)


if __name__ == "__main__":
    main()


