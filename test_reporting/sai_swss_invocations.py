import argparse
from curses.ascii import isupper
import json

from os import listdir
from os.path import isfile, join, basename
from typing import Dict, List, Tuple
from report_data_storage import KustoConnector
import yaml


def _run_script() -> Dict:
    '''
    Return:
        config: swss file
    '''
    parser = argparse.ArgumentParser(
        description="Upload sairedis log to Kusto.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog='''
                Examples:
                python3 sai_swss_invocations.py --config_path swss.yml
                Doc:
                sairedis log scanner.md
                '''
    )
    parser.add_argument('--config_path', type=str,
                        help="your yaml file path\n")
    args = parser.parse_args()
    with open(args.config_path, 'r', encoding='utf-8') as f:
        yaml_config = yaml.safe_load(f)
    return yaml_config


def get_files_from_path(path: str) -> List:
    '''
    Args:
        path: where we search the file
    Return:
        onlyfiles
    '''
    onlyfiles = [f for f in listdir(path) if isfile(join(path, f))]
    return onlyfiles


def get_files_from_path_and_name_pattern(path: str,
                                         name_pattern: str,
                                         exclusive_pattern: str) -> List:
    '''
    Args:
        path: where we search the file
    Return:
        onlyfiles: files meeting the pattern
    '''
    onlyfiles = []
    for f in listdir(path):
        if (isfile(join(path, f)) and name_pattern in f
                and exclusive_pattern not in f):
            onlyfiles.append(join(path, f))
    return onlyfiles


def generate_sai_feature_file_map_from_header_files(files: List) -> Dict:
    '''
    Args:
        files: header
    Return:
        map: feature header mapping
    Purpose
        we need to now each sai object comes from which header file
        and ususally each header represents a kind of feature, sai object
        has single feature.so with feautre,we can know sai objects belong to
        which header
    Example
        obj:    SAI_BOJECT_FDB_ENTRY    feature: fdb
        header: saifdb.h                feature: fdb
        SAI_BOJECT_FDB_ENTRY --> fdb --> saifdb.h
    '''
    feaure_file_map = {}
    for i in files:
        feature = i.replace('sai', '')
        feature = feature.replace('.h', '')
        if feature:
            feaure_file_map[feature] = i
    return feaure_file_map


def generate_sai_feature_from_header_files(files: List) -> List:
    '''
    Args:
        files: header
    Return:
        features: feature list
    '''
    features = []
    for i in files:
        feature = i.replace('sai', '')
        feature = feature.replace('.h', '')
        if feature:
            features.append(feature)
    return features


def get_object_type_from_log(line: str) -> Tuple:
    '''
    Args:
        line: log entry
    Return:
        sai_obj, sai_object_key
    '''
    # object always start with SAI_OBJECT_TYPE
    items = line.split('|')
    for i in items:
        if i.startswith('SAI_OBJECT_TYPE'):
            obj = i.split(':', 1)
            if (len(obj) == 1):
                return obj[0], [None]
            return obj[0], [obj[1]]
    return None


def get_log_time(line: str) -> str:
    '''
    Args:
        line: log entry
    Return:
        items[0]: time
    '''
    # only get the time when contains SAI_OBJECT_TYPE
    items = line.split('|')
    return items[0]


def get_sai_op(line: str, operation_map: Dict) -> Tuple:
    '''
    Args:
        line: log entry
        operation_map: single character to operation name   eg: c -> create
    Return:
        bool: is bulk op?
        string: op name
    '''
    items = line.split('|')
    return isupper(items[1]), operation_map.get(items[1])


def get_sai_api(op: str, obj: str) -> str:
    '''concate op and obj
    Args:
        op: operation
        obj: sai obj
    Return:
        sai_api
    '''
    obj = obj.replace('SAI_OBJECT_TYPE_', '').lower()
    return '_'.join([op, obj])


def get_sai_obj_type(line: str) -> List:
    '''each line may have many objects, each objects may have many features
    Args:
        line: log entry
    Return:
        attributes: 2D array [obj_index][featue list]
    '''
    attributes = []
    items = line.split('|')
    for item in items:
        if '=' in item:
            attributes.append(item.replace('\n', '').split('='))
    return [attributes]


def get_sai_header_file_from_sai_obj(feature: str,
                                     sai_feature_file_map: Dict) -> str:
    '''
    Args:
        feature
        sai_feature_file_map
    Return:
        header file
    '''
    if feature in sai_feature_file_map:
        header_file = sai_feature_file_map[feature]
    else:
        print("feature: {} not in sai_feature_file_map.".format(feature))
        return None
    return header_file


def get_sai_feature_from_sai_obj(sai_obj: str,
                                 features: List,
                                 sai_obj_feature_map: Dict) -> str:
    '''
    The purpose for getting feature of a object is
    matching object with it's c header file
    '''
    if sai_obj in sai_obj_feature_map:
        feature = sai_obj_feature_map[sai_obj]
    else:
        obj_type = sai_obj.replace('SAI_OBJECT_TYPE_', '')
        obj_secs = obj_type.split('_')
        got_value = False
        for i in range(0, len(obj_secs)):
            feature = ''.join(obj_secs[0:len(obj_secs)-i]).lower()
            if feature in features:
                sai_obj_feature_map[sai_obj] = feature
                got_value = True
                break
        # add to default type.h
        if not got_value:
            feature = 'types'
            sai_obj_feature_map[sai_obj] = 'types'

    return feature


def process_bulk(line: str) -> Tuple:
    '''process entry with bulk eperations
    Args:
        line: log entry
    Return:
        obj: sai object
        obj_keys: sai object keys
        obj_key_attrs: attributes of key
    '''
    # timestamp|action|objecttype||objectid|attrid=value|...||objectid||objectid|attrid=value|...||...
    fields = line.split('||')  # timestamp|action|objecttype
    obj = fields[0].split('|')[2]
    obj_keys, obj_key_attrs = [], []
    for idx in range(1, len(fields)):
        # object_id|attr=value|...
        joined = fields[idx]
        splits = joined.split('|')
        obj_keys.append(splits[0])
        attr = []
        for id in range(1, len(splits)):
            attr.append(splits[id].split('='))
        obj_key_attrs.append(attr)
    return obj, obj_keys, obj_key_attrs


def convert_log_item(config: Dict,
                     log_file: str,
                     features: List,
                     sai_feature_file_map: Dict,
                     sai_obj_feature_map: Dict,
                     info: Dict) -> None:
    '''convert log to swss item
    Args:
        config: swss config
        log_file: log file path
        features: sai features list
        sai_feature_file_map: sai feature maps to header file
        sai_obj_feature_map: sai obgject maps to feature
        info: info of the one device log config
    '''
    f = open(log_file, 'r', encoding='utf-8')
    log_name = basename(log_file)
    Lines = f.readlines()
    items = []
    for line in Lines:
        line = line.rstrip()
        if 'SAI_OBJECT_TYPE' in line:
            is_bulk, op = get_sai_op(line, config['operation_map'])
            if op:
                if is_bulk:  # bulk op
                    sai_obj, sai_object_key, obj_key_attrs = process_bulk(line)
                else:
                    sai_obj, sai_object_key = get_object_type_from_log(
                        line)
                    obj_key_attrs = get_sai_obj_type(line)
                for obj_key, attributes in zip(sai_object_key, obj_key_attrs):
                    if len(attributes) == 0:
                        log_item = Swss_log_item(config,
                                                 info,
                                                 sai_obj,
                                                 obj_key,
                                                 log_file,
                                                 line,
                                                 features,
                                                 sai_feature_file_map,
                                                 sai_obj_feature_map)
                        if log_item.sai_feature and log_item.header_file:
                            items.append(log_item)
                    else:
                        for attribute in attributes:
                            log_item = Swss_log_item(config,
                                                     info,
                                                     sai_obj,
                                                     obj_key,
                                                     log_file,
                                                     line,
                                                     features,
                                                     sai_feature_file_map,
                                                     sai_obj_feature_map,
                                                     attribute)
                            if log_item.sai_feature and log_item.header_file:
                                items.append(log_item)
    json_file = config['json_log_path'] + "/" + \
        log_name + "." + info['device'] + ".json"
    print("write to file {}".format(json_file))
    with open(json_file, 'w') as f:
        json.dump([ob.__dict__ for ob in items], f, sort_keys=True, indent=4)


def generate_json_logs(config: Dict,
                       info: Dict,
                       sai_obj_feature_map: Dict) -> None:
    '''get all the files and convert log to item
    Args:
        config: swss config
        info: info of the one device log config
        sai_obj_feature_map: sai obgject maps to feature
    '''
    file_list = get_files_from_path(config['sai_path'])
    sai_feature_file_map = generate_sai_feature_file_map_from_header_files(
        file_list)
    features = generate_sai_feature_from_header_files(file_list)
    files = get_files_from_path_and_name_pattern(
        info['log_path'], "sairedis.rec", ".gz")
    file_sum = len(files)
    count = 0
    for f in files:
        count += 1
        print("Generate json from file {}, {}/{}".format(f, count, file_sum))
        convert_log_item(config, f,
                         features, sai_feature_file_map,
                         sai_obj_feature_map, info)


def ingest_json_logs(json_log_path: str) -> None:
    '''ingest json to the kusto table
    Args:
        path:json path
    '''
    kusto_db = KustoConnector("SaiTestData")
    files = get_files_from_path_and_name_pattern(
        json_log_path, "sairedis.rec", ".gz")
    file_sum = len(files)
    count = 0
    try:
        for f in files:
            kusto_db.upload_swss_report_file(f)
            count += 1
            print("Ingested file {}, {}/{}".format(f, count, file_sum))
    except Exception as e:
        print("upload to kusto", e)


class Swss_log_item:

    def __init__(self, config: Dict, info: Dict,
                 sai_obj: str, sai_object_key: str,
                 log_file: str, line: str, features: List,
                 sai_feature_file_map: Dict,
                 sai_obj_feature_map: Dict,
                 attribute=None):
        self.log_file = log_file
        self.log = line
        self.sai_obj = sai_obj
        self.sai_object_key = sai_object_key
        self.log_time = get_log_time(line)
        self.sai_feature = get_sai_feature_from_sai_obj(
            self.sai_obj, features, sai_obj_feature_map)
        self.header_file = get_sai_header_file_from_sai_obj(
            self.sai_feature, sai_feature_file_map)
        _, self.sai_op = get_sai_op(line, config['operation_map'])
        self.sai_api = get_sai_api(self.sai_op, self.sai_obj)
        self.sai_obj_attr_key = attribute[0] if attribute else None
        self.sai_obj_attr_value = attribute[1] if attribute else None
        self.device = info['device']
        self.os_version = info['os_version']
        self.deployment_type = info['deployment_type']
        self.deployment_subtype = info['deployment_subtype']
        self.ngsdevice_type = config['ngsdevice_type']

    def dump_to_json(self):
        '''
        class item dumps to json
        '''
        return json.dumps(self, default=lambda o: o.__dict__,
                          sort_keys=True, indent=4)


if __name__ == "__main__":
    '''Before run this command, need to
    1. clone the sai repo to local disk and change sai_path
    2. set the json log generating folder
       and os_version in swss_device_log_items
    3. set the swss log input folders swss_log_paths
    '''
    config = _run_script()
    sai_obj_feature_map = {}
    for info in config['swss_device_log_items']:
        generate_json_logs(config, info, sai_obj_feature_map)
    ingest_json_logs(config['json_log_path'])
