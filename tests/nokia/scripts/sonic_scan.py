#!/usr/bin/env python

from subprocess import Popen, PIPE
from datetime import datetime
import argparse
import os
import re

hdr = "framework:sonic\n"
hdr += "branch:SONiC_999999\n"
hdr += "branchPrefix: SONiC_999999\n"
hdr += "type,name,level,constraint,phystopos,subtopos,priority,regress_include,exclude_subtopos,tags,guessed_author,owner,fid\n"
suite_suffix = ",regular,,any,,0,true,,,,,"
test_suffix = ",always,true(),any,,0,true,none,,,shubav,"

args = ["find", "/var/www/html/results", "-mtime", "-15", "-iname", "test_console.txt", "-print"]
f = Popen(args, stdout=PIPE, stderr=PIPE)

text_file_name = os.environ['HOME'] + "/scangash/SONiC_999999.scangash"
text_file = open(text_file_name, "w")
n = text_file.write(hdr)

entries_list = []
current_suite = "Unknown"

for file in f.stdout:
    args1 = ["grep", "-ri", "BEGIN ::TestDB::", file.rstrip("\n")]
    a = Popen(args1, stdout=PIPE)
    entries = a.communicate()[0].rstrip("\n")
    for line in entries.split('\n'):
        try:
            item = line.split(' ')[2]
        except:
            pass
        if re.search('TestCase', item):
            if item in entries_list:
                # test exists
                pass
            else:
                # insert test as first test under this suite
                try:
                    suite_idx = entries_list.index(current_suite) + 1
                    entries_list.insert(suite_idx, item)
                except ValueError:
                    pass ;# TBD
            print(line)
        elif re.search('TestSuite', item):
            current_suite = item
            if item in entries_list:
                # suite exists
                pass
            else:
                # new suite
                entries_list.append(item)
            print(line)

for entries in entries_list:
    if re.search("TestCase", entries):
        entries = entries.replace("::TestDB::TestCase::", "test,")
        entries = entries + test_suffix
    else:
        entries = entries.replace("::TestDB::TestSuite::", "suite,")
        entries = entries + suite_suffix
    text_file.write(entries + "\n")

text_file.close()
