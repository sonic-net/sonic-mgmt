#!/usr/bin/env python3
import argparse
import grpc
import os
import sys
import json
from time import sleep
from logger.cafylog import CafyLog

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
# sys.path.append(
#    os.path.join(os.path.dirname(os.path.abspath(__file__)),
#                 '../../utils/'))

# Add 3rd party python packages' paths (instead of setting PYTHONPATH)
TP_DIR = "./../../godiva-test/lib"
tp_dirs = os.listdir(TP_DIR)
for tp_dir in tp_dirs:
    sys.path.append(os.path.join(TP_DIR,tp_dir))

import p4_switch
from p4_error_utils import printGrpcError
import p4_info_helper
log = CafyLog(name='P4 Switch Lib')

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2



def tableEntryActions(sw, flow, p4info_helper, action, **kwargs):
    try:
        election_id_low = kwargs["election_id_low"]
    except KeyError:
        election_id_low = 1
    try:
        election_id_high = kwargs["election_id_high"]
    except KeyError:
        election_id_high = 0
    
    table_name = flow['table']
    match_fields = flow.get('match') # None if not found
    action_name = flow['action_name']
    default_action = flow.get('default_action') # None if not found
    action_params = flow['action_params']
    priority = flow.get('priority')  # None if not found
    oper = flow.get('operation') # None if not found
    #priority = 1
    if oper is None:
        oper = action

    table_entry = p4info_helper.buildTableEntry(
        table_name=table_name,
        match_fields=match_fields,
        default_action=default_action,
        action_name=action_name,
        action_params=action_params,
        priority=priority)

    if oper.upper() == 'INSERT':
        sw.WriteTableEntry(table_entry,election_id_low=election_id_low,election_id_high=election_id_high)
    elif oper.upper() == 'DELETE':
        sw.DeleteTableEntry(table_entry,election_id_low=election_id_low,election_id_high=election_id_high)

    return


def printCounter(p4info_helper, sw, counter_name, index):
    """
    Reads the specified counter at the specified index from the switch. In our
    program, the index is the tunnel ID. If the index is 0, it will return all
    values from the counter.

    :param p4info_helper: the P4Info helper
    :param sw:  the switch connection
    :param counter_name: the name of the counter from the P4 program
    :param index: the counter index (in our case, the tunnel ID)
    """
    for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
        for entity in response.entities:
            counter = entity.counter_entry
            print(("{} {} {}: {} packets ({} bytes)".format(
                sw.name, counter_name, index,
                counter.data.packet_count, counter.data.byte_count)))


def json_load_byteified(file_handle):
    return _byteify(json.load(file_handle, object_hook=_byteify),
                    ignore_dicts=True)


def _byteify(data, ignore_dicts=False):
    # if this is a unicode string, return its string representation
    #if isinstance(data, unicode):
    if isinstance(data, str):
        return data
        # For Python2 - return data.encode('utf-8')
    # if this is a list of values, return list of byteified values
    if isinstance(data, list):
        return [_byteify(item, ignore_dicts=True) for item in data]
    # if this is a dictionary, return dictionary of byteified keys and values
    # but only if we haven't already byteified it
    if isinstance(data, dict) and not ignore_dicts:
        return {
            _byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
            for key, value in data.items()
        }
    # if it's anything else, return it in its original form
    return data


def tableEntryToString(flow):
    if 'match' in flow:
        match_str = ['%s=%s' % (match_name, str(flow['match'][match_name])) for match_name in
                     flow['match']]
        match_str = ', '.join(match_str)
    elif 'default_action' in flow and flow['default_action']:
        match_str = '(default action)'
    else:
        match_str = '(any)'
    params = ['%s=%s' % (param_name, str(flow['action_params'][param_name])) for param_name in
              flow['action_params']]
    params = ', '.join(params)
    return "%s: %s => %s(%s)" % (
        flow['table'], match_str, flow['action_name'], params)


