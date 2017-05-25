#!/usr/bin/python

DOCUMENTATION = '''
---
module: switch_counters
version_added: "1.10"
author: Guohan Lu (gulv@microsoft.com)
short_description: Retrieve Switch counters for a device
description:
    - Retrieve switch counters for a device, inserted to the switch_counters key.
    - If check_drops parameter is set to True this module also checks for inbound
      outbound drops. Results returned in 'switch_drops' (boolean) and
      'switch_drops_delta' (dictionary). Variable with name 'switch_counters_2'
      contains a set of counters retrieved in 10 seconds after 'switch_counters'
options:
    - check_drops, not required, default to False
'''

EXAMPLES = '''
# Gather switch counters
- name: Gathering switch counters about the device
  switch_counters:
# Check for drops
- name: Check for drops on the device
  switch_counters: check_drops: yes
- name: Fail if there're drops on the switch
  fail: msg="Drops"
  when: vars['switch_drops']
'''

from ansible.module_utils.basic import *
from collections import defaultdict
import socket
import struct
import re
import json
import time

uc_queue_re = re.compile("UC_PERQ_PKT\((\d+)\)\.(\S+)\s*:\s+([0-9,]+)")
uc_queue_drop_re = re.compile("UCQ_DROP_PKT\((\d+)\)\.(\S+)\s*:\s+([0-9,]+)")
tx_pfc_re = re.compile("TPFC(\d+)\.(\S+)\s*:\s+([0-9,]+)")
drop_pkt_ing_re = re.compile("DROP_PKT_ING\.(\S+)\s*:\s+([0-9,]+)")

def parse_counters(output):

    Tree = lambda: defaultdict(Tree)
    counters = Tree()

    for line in output.split('\n'):
        m = uc_queue_re.match(line)
        if m:
            queuenum = int(m.group(1))
            portname = m.group(2)
            portnum  = int(re.compile("xe(\d+)").match(portname).group(1))
            cportname = "Ethernet" + str(portnum * 4)
            pktcnt = int("".join(m.group(3).split(',')))
            counters[cportname][queuenum]['ucq']['pkt'] = pktcnt
            continue
        
        m = uc_queue_drop_re.match(line)
        if m:
            queuenum = int(m.group(1))
            portname = m.group(2)
            portnum  = int(re.compile("xe(\d+)").match(portname).group(1))
            cportname = "Ethernet" + str(portnum * 4)
            pktcnt = int("".join(m.group(3).split(',')))
            counters[cportname][queuenum]['ucqdrop']['pkt'] = pktcnt
            continue

        m = tx_pfc_re.match(line)
        if m:
            queuenum = int(m.group(1))
            portname = m.group(2)
            portnum  = int(re.compile("xe(\d+)").match(portname).group(1))
            cportname = "Ethernet" + str(portnum * 4)
            pktcnt = int("".join(m.group(3).split(',')))
            counters[cportname][queuenum]['tpfc']['pkt'] = pktcnt
            continue

        m = drop_pkt_ing_re.match(line)
        if m:
            portname = m.group(1)
            m1 = re.compile("xe(\d+)").match(portname)
            if m1:
                portnum = int(m1.group(1))
                cportname = "Ethernet" + str(portnum * 4)
                pktcnt = int("".join(m.group(2).split(',')))
                counters[cportname]['ing_drop']['pkt'] = pktcnt
            continue

    return counters

def get_counters(module):
    # assume it's broadcom switch
    rc, out, err = module.run_command("bcmcmd \"show c all\"")
    if rc != 0:
        module.fail_json(msg="Command failed rc=%d, out=%s, err=%s" %
                (rc, out, err))

    return parse_counters(out)

def calc_drops(module, counters_1, counters_2):
    Tree = lambda: defaultdict(Tree)
    drops = False
    drops_delta = Tree()
    for port in counters_1.keys():
        ing_delta = counters_2[port]['ing_drop']['pkt'] \
                  - counters_1[port]['ing_drop']['pkt']
        ing_delta = ing_delta if ing_delta >= 0 else 2**64 + ing_delta
        if ing_delta > 0:
            drops = True
            drops_delta[port]['ing_drop']['pkt'] = ing_delta

        for queue in counters_1[port].keys():
            c2=counters_2[port][queue]['ucqdrop']['pkt']
            c1=counters_1[port][queue]['ucqdrop']['pkt']
            if isinstance(c2, int):
                ucqdrop_delta = c2 - c1
                ucqdrop_delta = ucqdrop_delta if ucqdrop_delta >= 0 else 2**64 + ucqdrop_delta
                if ucqdrop_delta > 0:
                    drops = True
                    drops_delta[port][queue]['ucqdrop']['pkt'] = ucqdrop_delta

    return drops, drops_delta

def main():
    module = AnsibleModule(
        argument_spec=dict(
            check_drops=dict(required=False, default=False, type='bool'),
        ),
        supports_check_mode=False)

    check_drops = module.params['check_drops']

    # wait for the switch counter to be up-to-date
    time.sleep(2)

    results = {}
    results['switch_counters'] = get_counters(module)
    if check_drops:
        time.sleep(10)  # Possibly, it's better to have 60 seconds here
        results['switch_counters_2'] = get_counters(module)
        results['switch_drops'], results['switch_drops_delta'] = \
            calc_drops(module, results['switch_counters'], results['switch_counters_2'])

    module.exit_json(ansible_facts=results)

if __name__ == "__main__":
    main()

