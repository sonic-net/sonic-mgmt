import os
import re
import random
import spytest.env as env
from spytest.ordyaml import OrderedYaml
import utilities.common as utils

config = None
levels = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug', 'none']

def get_config():
    global config
    if config: return config
    data = {}
    if env.get("SPYTEST_SYSLOG_ANALISYS", "0") != "0":
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        filename = os.path.join(root, "reporting", "syslogs.yaml")
        oyaml = OrderedYaml(filename,[])
        data = oyaml.get_data() or dict()
    for color in ["yellow", "green", "red"]:
        if color not in data:
            data[color] = []
    return data

def match(lvl, line):
    index = levels.index(lvl)
    needed = "|".join(levels[:index + 1])
    regex = r"^\S+\s+\d+\s+\d+:\d+:\d+(\.\d+){{0,1}}\s+\S+\s+({})\s+"
    cre = re.compile(regex.format(needed.upper()))
    return cre.search(line)

def parse(lvl, msgtype, dut_name, output, filemode=False):
    entries = []
    if lvl in levels:
        index = levels.index(lvl)
        needed = "|".join(levels[:index+1])
        regex = r"^(\S+\s+\d+\s+\d+:\d+:\d+(\.\d+){{0,1}}(\s+\d+){{0,1}})\s+(\S+)\s+({})\s+(.*)"
        cre = re.compile(regex.format(needed.upper()))
        cre_list = []
        chars = r"[a-zA-Z0-9-_/\.]+"
        cre_list.append(re.compile(r"^\s*({0}#{0}):*\s(.*)".format(chars)))
        cre_list.append(re.compile(r"^\s*({0}#{0}\[\d+\]):*\s(.*)".format(chars)))
        cre_list.append(re.compile(r"^\s*({0}\[\d+\]):\s*(.*)".format(chars)))
        cre_list.append(re.compile(r"^\s*({0}):\s*(.*)".format(chars)))
        for line in output.split("\n"):
            rv = cre.search(line)
            if not rv: continue
            entry = [dut_name, msgtype]
            entry.append(rv.group(1)) #date
            entry.append(rv.group(4)) #host
            entry.append(rv.group(5)) #level
            msg = rv.group(6)
            entry.append(msg) #message
            rv = None
            for cre2 in cre_list:
                rv = cre2.search(msg)
                if rv:
                    entry.append(rv.group(1)) #module
                    entry.append(rv.group(2)) #message
                    break
            if not rv:
                entry.append("") #module
                entry.append(msg) #message
            entries.append(entry)

    if filemode and lvl != "none":
        val = random.randint(1, 1000)
        entry = [dut_name, msgtype]
        entry.append(utils.get_current_datetime("%b %d %H:%M:%S.%f %Y"))
        entry.append("sonic") #host
        entry.append(lvl) #level
        entry.append("test syslog {}".format(val)) #message
        entry.append("") #module
        entry.append("test syslog {}".format(val)) #message
        entries.append(entry)

    return entries

def store(prev, current):
    cfg = get_config()
    rmatch, offset = None, 7
    for entry in current:
        gmatch, ymatch, pmatch = None, None, None

        # find green syslogs to discard
        for regex in cfg["green"]:
            if re.compile(regex).match(entry[offset]):
                gmatch = regex
                break
        if gmatch is not None:
            continue # ignore the syslog

        # find yellow syslogs to report only once
        for regex in cfg["yellow"]:
            if re.compile(regex).match(entry[offset]):
                ymatch = regex
                break

        # check if yellow syslog already noted
        for pentry in prev:
            if pentry[offset] == entry[offset]:
                pmatch = ymatch
                break
        if pmatch is not None:
            continue # syslog already reported once

        # add the entry to current syslogs
        prev.append(entry)

        if rmatch is not None:
            continue # first red syslog already noted

        # check if red syslog to report SW Issue
        for regex in cfg["red"]:
            if re.compile(regex).match(entry[offset]):
                rmatch = " ".join(entry)
                break

    return rmatch

