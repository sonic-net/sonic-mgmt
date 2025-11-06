import os
import json
import time
import sys
import pytest
import tortuga_common_utils as common_util
# Import Spytest APIs and helpers
from spytest import st, tgapi, SpyTestDict

scheduler_opts = ['type', 'weight', 'priority', 'meter-type', 'cir', 'pir',\
                  'cbs', 'pbs']


@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    """
    Pytest fixture to setup topology before running tests.
    Ensures minimum topology and sets global DUT handle.
    """
    global dut1
    global test_dict

    st.log("setup topology Started")
    testbed_dict = st.ensure_min_topology("D1")
    dut1 = testbed_dict.D1
    test_dict = common_util.get_qos_test_dict('../qos/qos_test_input1.json2',
                                              'CLI_TESTS', True)
    if test_dict == None:
        st.report_fail('msg', 'Failed to read test input file or missing key')
        return
    yield

def user_dict_to_cli_str(user_dict):
    cli_str = '"'
    for k, v in user_dict.items():
        cli_str += "{}:{},".format(k, v)
    if cli_str[-1] == ',':
        cli_str = cli_str[:-1]
    cli_str += '"'
    return cli_str
    

def st_config_wrapper(dut, cmd_str):
    try:
        st.config(dut, cmd_str)
    except:
        return '{} failed'.format(cmd_str)
    else:
        return 'OK'

def check_post_add_dict(cli_dict, cmd_name, key_name, tag_name, user_data):
    new_dict = common_util.show_cmd_to_dict(dut1, cmd_name)
    new_dict = new_dict[key_name]
    if tag_name in new_dict and new_dict[tag_name] == user_data:
        temp_dict = dict(new_dict)
        del temp_dict[tag_name]
        if cli_dict == temp_dict:
            st.log("add op successful")
            # Return new dictionary value
            return 'OK', new_dict

    return 'add: Bad new dictionary {}'.format(new_dict), {}

def check_post_update_dict(cli_dict, cmd_name, key_name, tag_name, user_data):
    new_dict = common_util.show_cmd_to_dict(dut1, cmd_name)
    new_dict = new_dict[key_name]
    diff_keys = list(set(new_dict) - set(cli_dict))
    if len(diff_keys) != 0: 
        return 'Bad updated dict {}'.format(new_dict), {}

    for key in cli_dict:
        if key != tag_name:
            # This is the unmodified key value so should be same
            if cli_dict[key] != new_dict[key]:
                return 'Bad updated dict {}'.format(new_dict), {}
            continue

        val1 = cli_dict[key]
        val2 = new_dict[key]
        diff_keys = list(set(val1) - set(val2))
        if len(diff_keys) != 0:
            return 'Bad updated dict {}'.format(new_dict), {}

        for subk1 in val1:
            if subk1 in user_data:
                if val2[subk1] != user_data[subk1]:
                    return 'Bad updated dict {}'.format(new_dict), {}
            elif val1[subk1] != val2[subk1]:
                    return 'Bad updated dict {}'.format(new_dict), {}

    st.log("Map update successful")
    # Return new dictionary value
    return 'OK', new_dict

def check_post_delete_dict(cli_dict, cmd_name, key_name, tag_name):
    new_dict = common_util.show_cmd_to_dict(dut1, cmd_name)
    new_dict = new_dict[key_name]
    diff_keys = list(set(cli_dict) - set(new_dict))
    if len(diff_keys) == 1 and tag_name in diff_keys:
        for key in new_dict:
            if cli_dict[key] != new_dict[key]:
                return 'Bad post-delete dict'.format(new_dict), {}

        st.log("Map delete successful")
        # Return new dictionary value
        return 'OK', new_dict

    return 'Bad post-delete dict'.format(new_dict), {}

def qos_cfg_add_map(cli_dict, cmd_name, key_name, tag_name, user_data):
    # Convert user dictionary back to string form for cli
    user_str = user_dict_to_cli_str(user_data)
    # Add a new map and capture the new output
    rv = st_config_wrapper(dut1, 'config {} add {} --maps {}'.format(cmd_name, tag_name, user_str))
    if rv is 'OK':
        return check_post_add_dict(cli_dict, cmd_name, key_name, tag_name, user_data)
    return rv, {}

def qos_cfg_update_map(cli_dict, cmd_name, key_name, tag_name, user_data):
    # Convert user dictionary back to string form for cli
    user_str = user_dict_to_cli_str(user_data)
    if tag_name not in cli_dict:
        return 'Non-existent profile {}'.format(tag_name), {}
    # Update the specified map
    rv = st_config_wrapper(dut1, 'config {} update {} --maps {}'.format(cmd_name, tag_name, user_str))
    if rv is 'OK':
        return check_post_update_dict(cli_dict, cmd_name, key_name, tag_name, user_data)
    return rv, {}

def qos_cfg_delete_map(cli_dict, cmd_name, key_name, tag_name):
    if tag_name not in cli_dict:
        return 'Non-existent profile {}'.format(tag_name), {}
    rv = st_config_wrapper(dut1, 'config {} del {}'.format(cmd_name, tag_name))
    if rv is 'OK':
        return check_post_delete_dict(cli_dict, cmd_name, key_name, tag_name)
    return rv, {}

def qos_cfg_scheduler_handler(cli_dict, op, tag_name, user_data):
    if op == 'add' or op == 'update':
        cmd_opts = ' ' + op + ' {}'.format(tag_name)
        for key in user_data:
            if key not in scheduler_opts:
                return 'Bad scheduler option {}'.format(key), {}
            cmd_opts += ' --{} {}'.format(key, user_data[key])
        rv = st_config_wrapper(dut1, 'config scheduler' + cmd_opts)
        if rv is not 'OK':
            return rv, {}

        if op == 'add':
            return check_post_add_dict(cli_dict, 'scheduler', 'SCHEDULER',\
                                       tag_name, user_data)
        return check_post_update_dict(cli_dict, 'scheduler', 'SCHEDULER',\
                                      tag_name, user_data)

    if op == 'delete':
        rv = st_config_wrapper(dut1, 'config scheduler delete {}'.format(tag_name))
        if rv is not 'OK':
            return rv, {}

        return check_post_delete_dict(cli_dict, 'scheduler', 'SCHEDULER',\
                                      tag_name)
    return 'Unknown op {}'.format(op), {}

def test_single_map_add_update_del():
    for cmd_name, val in test_dict.items():
        if 'key_name' not in val:
            st.error("'key_name' missing in test block {}".format(cmd_name))
            continue;

        key_name = val['key_name']
        st.config(dut1, "config qos reload")
        # Capture original cli dictionary
        curr_dict = common_util.show_cmd_to_dict(dut1, cmd_name)
        curr_dict = curr_dict[key_name]
        cmd_list = val['commands']
        for cmd_dict in cmd_list:
            op = cmd_dict['op']
            tag_name = cmd_dict['name']
            if 'value' in cmd_dict:
                # For comparison purposes, we need to copy this OrderedDict to
                # regular dictionary
                tmp = cmd_dict['value']
                user_data = {}
                for k, v in tmp.items():
                    user_data[k] = v
            else:
                user_data = ''
            st.log('cmd {} key {} tag {} data {}'.format(cmd_name, \
                     key_name, tag_name, user_data))
            if cmd_name == 'scheduler':
                rv, new_dict = qos_cfg_scheduler_handler(curr_dict, op, \
                                    tag_name, user_data)
            elif op == 'add':
                rv, new_dict = qos_cfg_add_map(curr_dict, cmd_name, key_name,\
                                     tag_name, user_data)
            elif op == 'update':
                rv, new_dict = qos_cfg_update_map(curr_dict, cmd_name, \
                                    key_name, tag_name, user_data)
            elif op == 'delete':
                rv, new_dict = qos_cfg_delete_map(curr_dict, cmd_name,\
                                    key_name, tag_name)
            else:
                rv, new_dict = 'Unknown op {}'.format(op), {}
            if rv is not 'OK': 
                new_dict = common_util.show_cmd_to_dict(dut1, cmd_name)
                new_dict = new_dict[key_name]
                if curr_dict != new_dict:
                    st.report_fail('Test failed and cli corrupt {}'.format(rv))
                    return
                if 'bad_input' in cmd_dict and cmd_dict['bad_input']:
                    st.banner('PASS: Dict {} rejected as EXPECTED {}'.format(cmd_dict, rv))
                else:
                    st.report_fail('Test dict {} FAILED {}'.format(cmd_dict, rv))
                    return
            else:
                st.banner('PASS: Dict {}'.format(cmd_dict))
            curr_dict = new_dict
    st.config(dut1, "config qos clear")
    st.report_pass('test_case_passed')
