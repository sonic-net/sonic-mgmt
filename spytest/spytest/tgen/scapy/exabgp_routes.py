#!/usr/bin/env python

import sys
import time

cmdfile=sys.argv[1]

def read_lines(filepath):
    fh = open(filepath, 'r')
    data = fh.readlines()
    fh.close()
    data = map(str.strip, data)
    return data

messages = read_lines(cmdfile)
time.sleep(2)

for index, message in enumerate(messages):
    sys.stdout.write( message + '\n')
    sys.stdout.flush()
    if index % 10 == 0:
        time.sleep(.1)

while True:
    time.sleep(1)
