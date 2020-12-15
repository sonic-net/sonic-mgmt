import os
from pprint import pprint
from ansible.module_utils.basic import datetime


def create_debug_file(debug_fname, add_timestamp=True):
    curtime = datetime.datetime.now().isoformat()
    if add_timestamp:
        # Check if there is an extension
        fname_split = os.path.splitext(debug_fname)
        if fname_split[1] != '':
            # We have an extension
            timed_debug_fname = (fname_split[0] + ".%s" + fname_split[1]) % curtime
        else:
            timed_debug_fname = (fname_split[0] + ".%s") % curtime
    else:
        timed_debug_fname = debug_fname
    if os.path.exists(timed_debug_fname) and os.path.isfile(timed_debug_fname):
        os.remove(timed_debug_fname)
    return timed_debug_fname


def print_debug_msg(debug_fname, msg):
    with open(debug_fname, 'a') as fp:
        pprint(msg, fp)
