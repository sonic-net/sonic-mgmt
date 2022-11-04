class TestInvocation(object):
    """
    Structure of invocation
    """

    def __init__(self, file_name, class_name, case_name, case_invoc, sai_header, saiintf_id,
                 saiintf_method_table, saiintf_name, saiintf_alias, test_set, test_platform,
                 platform_purpose_attr, attr_name, attr_value, runnable, sai_folder):
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
        self.runnable = runnable
        self.sai_folder = sai_folder
