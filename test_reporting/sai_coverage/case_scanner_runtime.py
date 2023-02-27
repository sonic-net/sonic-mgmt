import argparse
import json
import os
import re
import uuid


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
    with open(path, 'r') as f:
        for line in f:
            if 'Platform:' in line:
                return line.split()[1]


def parse_log(log_path, result_path, test_platform):
    results = []
    with open(log_path, 'r') as f:
        file_cnt = len(open(log_path, 'r').readlines())
        cur_cnt = 0

        for line in f:
            cur_cnt += 1
            print('Scanning:', str(cur_cnt)+'/'+str(file_cnt))
            if '** END TEST CASE' in line or 'retval' in line:
                continue

            pattern = r' - '
            obj = re.split(pattern, line)
            _, fine_data = obj[4].split(' ', 1)

            pattern2 = r'\[(.*?)\]'
            obj2 = re.split(pattern2, fine_data)

            key_val_pairs = obj2[3][1:-1]
            k_v = key_val_pairs.split(', \'')
            print(k_v)

            for kv in k_v:
                k, v = kv.split('\':')
                k = re.sub('[\' ]', '', k)
                v = re.sub('[\' ]', '', v)

                data = {}
                data['id'] = str(uuid.uuid4())
                data['is_azure_used'] = False

                sai_path, case_name = obj[1].split(':')
                data['file_name'] = sai_path.split('/')[-1]
                data['case_name'] = case_name
                data['class_name'] = case_name
                data['case_invoc'] = obj2[1]

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

                results.append(data)

    os.makedirs(result_path, exist_ok=True)
    with open(os.path.join(result_path, 'parsed_log.json'), 'w+') as f:
        json.dump(results, f, indent=4)


if __name__ == "__main__":
    parser = get_parser()
    test_platform = get_test_platform(parser.info_file)
    parse_log(parser.log_path, parser.result_path, test_platform)
