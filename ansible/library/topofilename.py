#!/usr/bin/env python

import re

CLET_SUFFIX = "-clet"

def get_filename(topo):
    return re.sub(CLET_SUFFIX + "$", "", topo) + ".yml"


def main():
    t = "t1-64-lag"
    print("get_filename({}) = {}".format(t, get_filename(t)))

    tc = "t1-64-lag-clet"
    print("get_filename({}) = {}".format(tc, get_filename(tc)))

    if (get_filename(t) != get_filename(tc)):
        raise Exception("Expect same filename")

if __name__== "__main__":
        main()
