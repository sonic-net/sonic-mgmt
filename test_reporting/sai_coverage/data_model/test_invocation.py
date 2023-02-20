class TestInvocation(object):
    """
    Structure of invocation

    Args:
        id: unique identifier for each record
        file_name: file name
        class_name: class name
        case_name: method name
        case_invoc: SAI interface
        sai_header: file name
        saiintf_id: SAI interface groupname
        saiintf_method_table: SAI interface groupalias
        saiintf_name: SAI interface name
        saiintf_alias: SAI interface alias
        test_set: distinguish test set ("t0" or "ptf")
        test_platform: the platform used for running cases
        platform_purpose_attr: platform
        attr_name: Attribute name
        attr_value: Attribute value
        runnable: distinguish whether case runnable
        sai_folder: folder name of the scanning file
        upload_time: upload time
    """

    def __init__(self, id, file_name, class_name, case_name, case_invoc, sai_header, saiintf_id,
                 saiintf_method_table, saiintf_name, saiintf_alias, test_set, test_platform,
                 platform_purpose_attr, attr_name, attr_value, runnable, sai_folder, upload_time):
        sai_api = saiintf_name[4:4 + len(saiintf_name) - 7]
        sai_feature = saiintf_method_table[4:4 + len(saiintf_method_table) - 10]

        self.id = id
        self.is_azure_used = False
        self.file_name = file_name
        self.case_name = case_name
        self.class_name = class_name
        self.case_invoc = case_invoc
        self.sai_header = sai_header
        self.saiintf_id = saiintf_id
        self.saiintf_method_table = saiintf_method_table
        self.sai_feature = sai_feature.replace('_', '')
        self.sai_api = sai_api[0:len(sai_api) - 10] if 'attribute' in sai_api else sai_api
        self.saiintf_alias = saiintf_alias
        self.test_set = test_set
        self.test_platform = test_platform
        self.platform_purpose_attr = platform_purpose_attr
        self.sai_obj_attr_key = attr_name
        self.sai_obj_attr_value = attr_value
        self.runnable = runnable
        self.sai_folder = sai_folder
        self.upload_time = upload_time
