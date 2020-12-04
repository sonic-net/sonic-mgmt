import os
from pprint import pprint
from ansible.module_utils.basic import datetime

def create_debug_file(debug_fname):
    curtime = datetime.datetime.now().isoformat()
    timed_debug_fname = debug_fname % curtime
    if os.path.exists(timed_debug_fname) and os.path.isfile(timed_debug_fname):
        os.remove(timed_debug_fname)
    return timed_debug_fname


def print_debug_msg(debug_fname, msg):
    with open(debug_fname, 'a') as fp:
        pprint(msg, fp)