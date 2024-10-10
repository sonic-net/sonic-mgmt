import sys
import os
import p4runtime_sh.shell as p4sh


# The verbose toggle in P4Runtime shell is not published to pip, so we need to disable it manually.
def disable_print():
    sys.stdout = open(os.devnull, 'w')


def enable_print():
    sys.stdout = sys.__stdout__


def init_p4runtime_shell():
    p4sh.setup(
        device_id=0,
        grpc_addr='127.0.0.1:9559',
        election_id=(0, 1),
    )
