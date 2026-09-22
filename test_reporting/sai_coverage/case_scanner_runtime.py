import argparse
import json
import os
import re
import uuid

"""
This script parses the published artifacts, and outputs a json format result.

Examples:
  - Input
    1) log example:
        02/24/2023 03:34:54 AM - /tmp/sai_qualify/SAI/ptf/sairif.py:SviLagHostTest - \
        sai_adapter.py - INFO - sai_adapter_invoke func:[sai_thrift_create_switch] \
        args: [{'client': '<sai_thrift.sai_rpc.Client object at 0x7f7adac58a58>', \
                'init_switch': 'True', 'src_mac_address': '00:77:66:55:44:00'}]

    2) info_file example:
        Platform: x86_64-dell_s6000_s1220-r0
        HwSKU: Force10-S6000

  - Output:
    parsed_log.json:
    {
        "id": "c3be2806-6c1b-495a-b33e-a531ca477e67",
        "is_azure_used": false,
        "file_name": "sairif.py",
        "case_name": "SviLagHostTest",
        "class_name": "SviLagHostTest",
        "case_invoc": "sai_thrift_create_switch",
        "sai_alias": "create_switch",
        "sai_api": "create_switch",
        "sai_feature": "switch",
        "test_set": "ptf",
        "test_platform": "x86_64-cel_seastone-r0",
        "sai_obj_attr_key": "init_switch",
        "sai_obj_attr_val": "True",
        "runnable": true,
        "sai_folder": "/tmp/sai_qualify/SAI/ptf",
        "upload_time": "2023-02-24"
    }
"""


def get_parser(description="Runtime Scanner"):
    """
    Parse command line
    """
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--log_path", "-l", type=str,
                        default="log", help="log path to scan.")
    parser.add_argument("--info_file", "-i", type=str,
                        default="log", help="test platform info file path to scan.")
    parser.add_argument("--result_path", "-r", type=str, default="result",
                        help="path of the parsed result.")
    args = parser.parse_args()
    return args


def get_test_platform(path):
    """
    Parse the info_file, and extract test_platform info

    Arg:
      path: path of info_file
    """
    with open(path, 'r') as f:
        for line in f:
            if 'Platform:' in line:
                return line.split()[1]


def parse_log(log_path, result_path, test_platform):
    """
    Parse the log and info_file, and output result json

    Arg:
      log_path: path of log
      result_path: path to save the json result
      test_platform: platform of running cases
    """
    results = []
    with open(log_path, 'r') as f:
        file_cnt = len(open(log_path, 'r').readlines())
        cur_cnt = 0

        for line in f:
            cur_cnt += 1
            print('Scanning:', str(cur_cnt)+'/'+str(file_cnt))
            if '** END TEST CASE' in line or 'retval' in line:
                continue

            pattern = r' - '  # split each line by ` - `
            obj = re.split(pattern, line)
            _, fine_data = obj[4].split(' ', 1)  # fine_data stores func and args

            pattern2 = r'\[(.*?)\]'  # extract items in `[]`
            obj_args = re.split(pattern2, fine_data)

            key_val_pairs = obj_args[3][1:-1] if obj_args[3][-1] == '}' else obj_args[3][1:]  # get args
            k_v = key_val_pairs.split(', \'')

            for kv in k_v:
                k, v = kv.split('\':')
                if 'client' in k:
                    continue
                if '\'[' in v:  # if `v` is a list
                    v_list = v.split(', ')
                    v = []
                    print(v_list)
                    for v_i in v_list:
                        v_i = re.findall(r'\.(.*?)\:', v_i)
                        data = construct_data(obj, obj_args, k, v_i[0], test_platform)
                        results.append(data)
                else:
                    data = construct_data(obj, obj_args, k, v, test_platform)
                    results.append(data)

    """
    `data` stores each item of the parsed log, and `result` stores all `data` items.
    After traversing the input log file, all parsed items are stored in `result`.
    The `result` will be saved in `result_path/parsed_log.json`
    """
    print('Scan complete, parsed log generating...')
    os.makedirs(result_path, exist_ok=True)
    with open(os.path.join(result_path, 'parsed_log.json'), 'w+') as f:
        json.dump(results, f, indent=4)


def construct_data(obj, obj_args, k, v, test_platform):
    """
    Contruct data item

    Arg:
      obj: main body of each log
      obj_args: args of each log
      k: key
      v: value
      test_platform: platform of running cases
    """
    data = {}

    k = re.sub('[\' ]', '', k)
    v = re.sub('[\' ]', '', v)

    data['id'] = str(uuid.uuid4())
    data['is_azure_used'] = False

    sai_path, case_name = obj[1].split(':')
    data['file_name'] = sai_path.split('/')[-1]
    data['case_name'] = case_name
    data['class_name'] = case_name
    data['case_invoc'] = obj_args[1]

    data['sai_alias'] = data['case_invoc'][11:]
    if 'attribute' in data['sai_alias']:
        data['sai_api'] = data['sai_alias'][:len(data['sai_alias'])-10]
    else:
        data['sai_api'] = data['sai_alias']
    idx = data['sai_api'].find('_') + 1
    sai_feature = data['sai_api'][idx:].split('entry')[0].replace('_', '')
    data['sai_feature'] = sai_feature.replace('table', '').replace('trap', '')

    data['test_set'] = 't0' if 'sai_test' in sai_path else 'ptf'
    data['test_platform'] = test_platform

    data['sai_obj_attr_key'] = k
    data['sai_obj_attr_val'] = v

    data['runnable'] = True
    data['sai_folder'] = '/'.join(sai_path.split('/')[:-1])
    formatted_time = obj[0].split()[0].split('/')
    data['upload_time'] = formatted_time[2]+'-'+formatted_time[0]+'-'+formatted_time[1]

    return data


if __name__ == "__main__":
    parser = get_parser()
    test_platform = get_test_platform(parser.info_file)
    parse_log(parser.log_path, parser.result_path, test_platform)
