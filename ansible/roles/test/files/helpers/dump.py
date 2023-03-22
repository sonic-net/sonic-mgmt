#!/usr/bin/env python

from sys import stdin
import json
import os
import sys

while True:
    try:
        line = stdin.readline()
        obj = json.loads(line)
        f = open("/root/exabgp/" + obj["neighbor"]["ip"], "a")
        f.write(line + "\n")
        f.close()
    except:
        continue
