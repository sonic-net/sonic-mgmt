#!/usr/bin/python3

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[1;34m'
    OKGREEN = '\033[0;32m'
    WARNING = '\x1b[0;33m'
    FAIL = '\033[0;31m'
    ENDC = '\033[0m'

    def disable(self):
        self.HEADER = ''
        self.OKBLUE = ''
        self.OKGREEN = ''
        self.WARNING = ''
        self.FAIL = ''
        self.ENDC = ''
