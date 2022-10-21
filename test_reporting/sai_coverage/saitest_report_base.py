'''
    This file is for defining SAI qualification report variables and classes:
'''
import json

######### For SAI interface coverage report AST #########
SAI_API_PREFIX = "sai_thrift"
RUNTEST_PREFIX = "runTest"
IGNORE_FILE_LIST = ["sai_adapter.py", "sai_base_test.py", "sai_utils.py", "__init__.py"]
SKIP_METHODS = ["runTest", "setUp", "tearDown"]
# COMPRESSED_JSON_FILE = "compressed.json"
# FLATTEN_JSON_FILE = "flatten.json"

SAI_HEADER_FILE = "saiintf_target.json"
SAI_ADAPTER_DIRPATH = "sai_adapter.json"
IGNORE_HEADER_FILE_LIST = ["sai.h", "saiobject.h", "saistatus.h", "saitypes.h"]
SAI_INTF_TARGET_FILENAME = "saiintf_target.json"


class SAIInterfaceHeader(object):
    def __init__(self, intf_groupname, intf_groupalias, intf_name, intf_alias, file_name):
        self.intf_groupname = intf_groupname
        self.intf_groupalias = intf_groupalias
        self.intf_name = intf_name
        self.intf_alias = intf_alias
        self.file_name = file_name


class TestInvocation(object):
    def __init__(self, file_name, class_name, case_name, case_invoc, sai_header, saiintf_id, saiintf_method_table, saiintf_name, saiintf_alias, test_set, test_platform, platform_purpose_attr, attr_name, attr_value):
        self.file_name = file_name
        self.case_name = case_name
        self.class_name = class_name
        self.case_invoc = case_invoc
        self.sai_header = sai_header
        self.saiintf_id = saiintf_id
        self.saiintf_method_table = saiintf_method_table
        self.sai_api = saiintf_name
        self.saiintf_alias = saiintf_alias
        self.test_set = test_set
        self.test_platform = test_platform
        self.platform_purpose_attr = platform_purpose_attr
        self.sai_obj_attr_key = attr_name
        self.sai_obj_attr_value = attr_value


def store_result(data, file_name):
    with open(file_name, 'w+') as f:
        json.dump(data, f, indent=4)


# This is used for serialize the sai coverage data
class SAIJsonEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, set):
            return list(o)
        return json.JSONEncoder.default(self, o)
