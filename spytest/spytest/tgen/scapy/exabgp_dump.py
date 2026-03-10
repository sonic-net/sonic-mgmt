#!/usr/bin/env python

from sys import stdin
import json

while True:
    try:
        line = stdin.readline()
        obj = json.loads(line)
        f = open("/root/exabgp/" + obj["neighbor"]["ip"], "a")
        f.write(line)
        f.close()
    except Exception:
        continue
