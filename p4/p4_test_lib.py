#!/usr/bin/env python3
import argparse
import grpc
import os
import sys
import json
import re
import time
from time import sleep
from logger.cafylog import CafyLog
import google.protobuf.text_format
import google.protobuf.json_format
from google.protobuf import descriptor
from p4_base_ap import ApData, P4ApBase
from collections import abc


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

from context import P4RuntimeEntity, P4Type, Context
from p4.v1 import p4runtime_pb2
from p4.config.v1 import p4info_pb2
import p4_switch
from p4_error_utils import printGrpcError
import p4_info_helper
log = CafyLog(name='P4 Switch Lib')

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2


p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
p4info=p4info_helper.p4info
context = Context()
context.set_p4info(p4info)


class _PrintContext:
    def __init__(self):
        self.skip_one = False
        self.stack = []

    def find_table(self):
        for msg in reversed(self.stack):
            if msg.DESCRIPTOR.name == "TableEntry":
                try:
                    return context.get_name_from_id(msg.table_id)
                except KeyError:
                    return None
        return None

    def find_action(self):
        for msg in reversed(self.stack):
            if msg.DESCRIPTOR.name == "Action":
                try:
                    return context.get_name_from_id(msg.action_id)
                except KeyError:
                    return None
        return None

def _sub_object(field, value, pcontext):
    id_ = value
    try:
        return context.get_name_from_id(id_)
    except KeyError:
        log.error("Unknown object id {}".format(id_))


def _sub_mf(field, value, pcontext):
    id_ = value
    table_name = pcontext.find_table()
    if table_name is None:
        log.error("Cannot find any table in context")
        return
    return context.get_mf_name(table_name, id_)


def _sub_ap(field, value, pcontext):
    id_ = value
    action_name = pcontext.find_action()
    if action_name is None:
        log.error("Cannot find any action in context")
        return
    return context.get_param_name(action_name, id_)


def _gen_pretty_print_proto_field(substitutions, pcontext):
    def myPrintField(self, field, value):
        self._PrintFieldName(field)
        self.out.write(' ')
        if field.type == descriptor.FieldDescriptor.TYPE_BYTES:
            # TODO(antonin): any kind of checks required?
            self.out.write('\"')
            self.out.write(''.join('\\\\x{:02x}'.format(b) for b in value))
            self.out.write('\"')
        else:
            self.PrintFieldValue(field, value)
        subs = None
        if field.containing_type is not None:
            subs = substitutions.get(field.containing_type.name, None)
        if subs and field.name in subs and value != 0:
            name = subs[field.name](field, value, pcontext)
            self.out.write(' ("{}")'.format(name))
        self.out.write(' ' if self.as_one_line else '\n')

    return myPrintField


def repr_pretty_proto(msg, substitutions):
    """A custom version of google.protobuf.text_format.MessageToString which represents Protobuf
    messages with a more user-friendly string. In particular, P4Runtime ids are supplemented with
    the P4 name and binary strings are displayed in hexadecimal format."""

    pcontext = _PrintContext()

    def message_formatter(message, indent, as_one_line):
        # For each messages we do 2 passes: the first one updates the _PrintContext instance and
        # calls MessageToString again. The second pass returns None immediately (default handling by
        # text_format).
        if pcontext.skip_one:
            pcontext.skip_one = False
            return
        pcontext.stack.append(message)
        pcontext.skip_one = True
        s = google.protobuf.text_format.MessageToString(
            message, indent=indent, as_one_line=as_one_line, message_formatter=message_formatter)
        s = s[indent:-1]
        pcontext.stack.pop()
        return s

    # We modify the "internals" of the text_format module which is not great as it may break in the
    # future, but this enables us to keep the code fairly small.
    saved_printer = google.protobuf.text_format._Printer.PrintField
    google.protobuf.text_format._Printer.PrintField = _gen_pretty_print_proto_field(
        substitutions, pcontext)

    s = google.protobuf.text_format.MessageToString(msg, message_formatter=message_formatter)
   
    google.protobuf.text_format._Printer.PrintField = saved_printer

    return s


def repr_pretty_p4runtime(msg):
    substitutions = {
        "TableEntry": {"table_id": _sub_object},
        "FieldMatch": {"field_id": _sub_mf},
        "Action": {"action_id": _sub_object},
        "Param": {"param_id": _sub_ap},
        "ActionProfileMember": {"action_profile_id": _sub_object},
        "ActionProfileGroup": {"action_profile_id": _sub_object},
        "MeterEntry": {"meter_id": _sub_object},
        "CounterEntry": {"counter_id": _sub_object},
        "ValueSetEntry": {"value_set_id": _sub_object},
        "RegisterEntry": {"register_id": _sub_object},
        "DigestEntry": {"digest_id": _sub_object},
        "DigestListAck": {"digest_id": _sub_object},
        "DigestList": {"digest_id": _sub_object},
    }
    return repr_pretty_proto(msg, substitutions)

def table_entry_to_dict(resp):
    lines = resp.splitlines()
    entries = list()
    entity_list = list()
    entry_list = list()
    first = True

    for line in lines:
        if 'entities' in line:
            if not first:
                entity_list.append(entry_list)
            entry_list = list()
            first = False
            continue
        entry_list.append(line)

    entity_list.append(entry_list)
    
    for entry_list in entity_list:
        if 'table_entry' in entry_list[0]:
            table_dict = _get_table_entry_dict(entry_list)
            entries.append(table_dict)
    
    return entries

def _get_table_entry_dict(table_entry_list):
    table_dict = dict()
    match_section = False
    action_section = False
    first = True
    match_list = list()
    action_list = list()

    for entry in table_entry_list:
        if ':' in entry and first:
            entry = entry.strip()
            x = entry.split(':')
            match = re.search(r'\w*', x[0])
            table_id = match.group()
            y = x[1].lstrip(' ')
            y = y.split(' ')
            table_id = y[0]
            y = y[1].strip("(\"")
            table_name = y.strip("\")")
            first = False
        elif 'match' in entry and ':' not in entry:
            match_section = True
            continue
        elif 'action' in entry and ':' not in entry:
            action_section = True
            match_section = False
            continue
        
        if match_section:
            match_list.append(entry)

        if action_section:
            action_list.append(entry)

    match_dict = _get_match_dict(match_list)
    action_dict = _get_action_dict(action_list)
    table_dict['table_id'] = table_id
    table_dict['table_name'] = table_name
    table_dict['match_dict'] = match_dict
    table_dict['action_dict'] = action_dict
    return table_dict

def _get_match_dict(match_list):
    field_list = list()
    entry_list = list()
    first = True
    match_dict = dict()

    for line in match_list:
        if 'field' in line:
            if not first:
                field_list.append(entry_list)
            entry_list = list()
            entry_list.append(line)
            first = False
            continue
        else:
            entry_list.append(line)

    field_list.append(entry_list)
    for entry_list in field_list:
        match_dict = _parse_field_list(entry_list)

    return match_dict
        
def _parse_field_list(field_list):
    match_dict = dict()
    
    entry = field_list[0]
    entry = entry.strip()
    x = entry.split(':')
    y = x[1].lstrip(' ')
    y = y.split(' ')
    field_id = y[0]
    y = y[1].strip("(\"")
    field_name = y.strip("\")")
    field_list.pop(0)
    match_dict['field_id'] = field_id
    match_dict['field_name'] = field_name

    entry = field_list[0]
    if 'exact' in entry:
        match_dict['match_type'] = 'exact'
        for entry in field_list:
            if 'value' in entry:
                p_list = list()
                entry = entry.strip()
                x = entry.split(':')
                y = x[1].lstrip(' ')
                value = y.strip("\"")
                value = value.split('\\\\x')
                for z in value:
                    if z == "":
                        continue
                    else:
                        z1 = int(z, 16)
                        z1 = str(z1)
                        p_list.append(z1)
        
                if len(p_list) == 4:
                    value = '.'.join(p_list[0:4])
                else:
                    value = ''.join(p_list[0:len(p_list)])
                    value = value.lstrip('0')
                match_dict['value'] = value
    else:
        entry = entry.strip()
        match = re.search(r'\w*', entry)
        sub_field = match.group()
        sub_field_list = list()
        match_dict['match_type'] = match.group()
        for entry in field_list:
            if ':' in entry:
                p_list = list()
                sub_field_dict = dict()
                entry = entry.strip()
                x = entry.split(':')
                match = re.search(r'\w*', x[0])
                sub_field_dict['id'] = match.group()
                y = x[1].lstrip(' ')
                value = y.strip("\"")
                if '\\\\x' in value:
                    value = value.split('\\\\x')
                    for z in value:
                        if z == "":
                            continue
                        else:
                            z1 = int(z, 16)
                            z1 = str(z1)
                            p_list.append(z1)
            
                    if len(p_list) == 4:
                        value = '.'.join(p_list[0:4])
                    else:
                        value = ''.join(p_list[0:len(p_list)])
                        value = value.lstrip('0')

                sub_field_dict['value'] = value
                sub_field_list.append(sub_field_dict)
        
        match_dict[sub_field] = sub_field_list 

    return match_dict

def _get_action_dict(actions_list):
    param_list = list()
    entry_list = list()
    first = True
    indirect_table = True
    action_name = None
    action_id = None
    action_dict = dict()

    for line in actions_list:
        if 'params' in line:
            if not first:
                param_list.append(entry_list)
            entry_list = list()
            first = False
            indirect_table = False
            continue
        elif ':' in line and indirect_table:
            entry = line.strip()
            x = entry.split(':')
            match = re.search(r'\w*', x[0])
            action_name = match.group()
            x = x[1].strip()
            match = re.search(r'\d*', x)
            action_id = match.group()
            
        if not indirect_table:
            entry_list.append(line)
    
    if not indirect_table:
        param_list.append(entry_list)
        params_list = list()
        for entry_list in param_list:
            params_list.append(_parse_param_list(entry_list))
        
        action_dict['params_list'] = params_list

    if indirect_table:
        action_dict['action_name'] = action_name
        action_dict['action_id'] = action_id

    return action_dict

def _parse_param_list(param_list):
    action_dict = dict()
    param_id = None

    for entry in param_list:
        if 'param_id:' in entry:            
            entry = entry.strip()
            x = entry.split(':')
            y = x[1].lstrip(' ')
            y = y.split(' ')
            param_id = y[0]
            y = y[1].strip("(\"")
            param_name = y.strip("\")")
        elif 'value' in entry:
            p_list = list()
            entry = entry.strip()
            x = entry.split(':')
            y = x[1].lstrip(' ')
            value = y.strip("\"")
            if '\\\\x' in value:
                value = value.split('\\\\x')
                for z in value:
                    if z == "":
                        continue
                    else:
                        z1 = int(z, 16)
                        z1 = str(z1)
                        p_list.append(z1)
        
                if len(p_list) == 4:
                    value = '.'.join(p_list[0:4])
                else:
                    value = ''.join(p_list[0:len(p_list)])
                    value = value.lstrip('0')

    if param_id is not None:
        action_dict['param_id'] = param_id
        action_dict['param_name'] = param_name
        action_dict['value'] = value

    return action_dict


def tableEntryActions(sw, flow, p4info_helper, action, **kwargs):
    try:
        election_id_low = kwargs["election_id_low"]
    except KeyError:
        election_id_low = 1
    try:
        election_id_high = kwargs["election_id_high"]
    except KeyError:
        election_id_high = 0
    try:
        role_id = kwargs["role_id"]
    except KeyError:
        role_id = 1
    try:
        priority = kwargs["priority"]
    except KeyError:
        priority = flow.get('priority')  # None if not found
    try:
        device_id = kwargs["device_id"]
    except KeyError:
        device_id = 0

    
    table_name = flow['table']
    match_fields = flow.get('match') # None if not found
    action_name = flow.get('action_name') # None if not found
    default_action = flow.get('default_action') # None if not found
    action_params = flow.get('action_params') # None if not found
    action_member = flow.get('action_member') # None if not found
    action_group = flow.get('action_group') # None if not found
    oper = flow.get('operation') # None if not found
    if oper is None:
        oper = action

    table_entry = p4info_helper.buildTableEntry(
        table_name=table_name,
        match_fields=match_fields,
        default_action=default_action,
        action_name=action_name,
        action_params=action_params,
        action_member=action_member,
        action_group=action_group,
        priority=priority)

    if oper.upper() == 'INSERT':
        sw.WriteTableEntry(table_entry,election_id_low=election_id_low,election_id_high=election_id_high,device_id=device_id,role_id=role_id)
    elif oper.upper() == 'MODIFY':
        sw.WriteTableEntry(table_entry,election_id_low=election_id_low,election_id_high=election_id_high,oper="MODIFY",device_id=device_id,role_id=role_id)
    elif oper.upper() == 'DELETE':
        sw.DeleteTableEntry(table_entry,election_id_low=election_id_low,election_id_high=election_id_high,device_id=device_id,role_id=role_id)

    return

def tableEntryActionsBatched(sw, entryarr, p4info_helper, **kwargs):
    try:
        election_id_low = kwargs["election_id_low"]
    except KeyError:
        election_id_low = 1
    try:
        election_id_high = kwargs["election_id_high"]
    except KeyError:
        election_id_high = 0
    
    table_entries = []
    for flow in entryarr:
        table_name = flow['table']
        match_fields = flow.get('match') # None if not found
        action_name = flow.get('action_name') # None if not found
        default_action = flow.get('default_action') # None if not found
        action_params = flow.get('action_params') # None if not found
        action_member = flow.get('action_member') # None if not found
        action_group = flow.get('action_group') # None if not found
        priority = flow.get('priority')  # None if not found
        oper = flow.get('operation') # None if not found
        #priority = 1
        if oper is None:
            oper = 'INSERT'

        table_entry = p4info_helper.buildTableEntry(
            table_name=table_name,
            match_fields=match_fields,
            default_action=default_action,
            action_name=action_name,
            action_params=action_params,
            action_member=action_member,
            action_group=action_group,
            priority=priority)
        table_entries.append({'te':table_entry, 'op':oper})

    t1 = time.time()
    sw.ProcessBatchedTableEntries(table_entries)
    t2 = time.time()
    log.info("[Time taken] Time for entries %s is %f" % (oper, t2-t1))
    return

def tableWCRead(sw, flow, p4info_helper):
    table_name = flow['table']
    match_fields = flow.get('match') # None if not found
    action_name = flow.get('action_name') # None if not found
    default_action = flow.get('default_action') # None if not found
    action_params = flow.get('action_params') # None if not found
    action_member = flow.get('action_member') # None if not found
    action_group = flow.get('action_group') # None if not found
    priority = flow.get('priority')  # None if not found

    tbl_entry = p4info_helper.buildTableEntry(
        table_name=table_name,
        match_fields=match_fields,
        default_action=default_action,
        action_name=action_name,
        action_params=action_params,
        action_member=action_member,
        action_group=action_group,
        priority=priority)

    table_id = p4info_helper.get_id("tables", name=table_name)
    return sw.ReadTableEntriesWc(table_id, tbl_entry)

def memberActions(sw, flow, p4info_helper, mode, **kwargs):
    try:
        election_id_low = kwargs["election_id_low"]
    except KeyError:
        election_id_low = 1
    try:
        election_id_high = kwargs["election_id_high"]
    except KeyError:
        election_id_high = 0
    
    member_id = flow['member_id']
    action_profile_id = flow.get('action_profile_id')
    action_name = flow.get('action_name')
    action_params = flow.get('action_params')
    
    apmember = p4info_helper.buildActionProfileMember(
        member_id=member_id,
        action_profile_id=action_profile_id,
        action_name=action_name,
        action_params=action_params)

    mode = mode.upper()
    if mode == 'INSERT':
        sw.WriteActionProfileMember(apmember,election_id_low=election_id_low,election_id_high=election_id_high,update_type=mode)
    elif mode == 'MODIFY':
        sw.WriteActionProfileMember(apmember,election_id_low=election_id_low,election_id_high=election_id_high,update_type=mode)
    elif mode == 'DELETE':
        sw.DeleteActionProfileMember(apmember,election_id_low=election_id_low,election_id_high=election_id_high,update_type=mode)

    return

def groupActions(sw, flow, p4info_helper, mode, **kwargs):
    try:
        election_id_low = kwargs["election_id_low"]
    except KeyError:
        election_id_low = 1
    try:
        election_id_high = kwargs["election_id_high"]
    except KeyError:
        election_id_high = 0
    
    group_id = flow['group_id']
    action_profile_id = flow['action_profile_id']
    members = flow.get('members')
    max_size = flow.get('max_size')

    apgroup = p4info_helper.buildActionProfileGroup(
        group_id=group_id,
        action_profile_id=action_profile_id,
        members=members,
        max_size=max_size)

    mode = mode.upper()
    sw.WriteActionProfileGroup(apgroup,election_id_low=election_id_low,election_id_high=election_id_high,update_type=mode)

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
    params = ""
    if 'action_params' in flow:
        params = ['%s=%s' % (param_name, str(flow['action_params'][param_name])) for param_name in
                  flow['action_params']]
        params = ', '.join(params)
    act_name = ""
    if 'action_name' in flow:
        act_name = flow['action_name']
    return "%s: %s => %s(%s)" % (
        flow['table'], match_str, act_name, params)



