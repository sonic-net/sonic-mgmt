import sys
import os


# The verbose toggle in P4Runtime shell is not published to pip, so we need to disable it manually.
def disable_print():
    sys.stdout = open(os.devnull, 'w')


def enable_print():
    sys.stdout = sys.__stdout__
