class TestInvocation(object):
    """
    Structure of invocation

    Args:
        id: unique identifier for each record
        file_name: file name
        class_name: class name
        case_name: method name
        case_invoc: SAI interface
        saiintf_method_table: SAI interface groupalias
        test_set: distinguish test set ("t0" or "ptf")
        test_platform: the platform used for running cases
        attr_name: Attribute name
        attr_value: Attribute value
        runnable: distinguish whether case runnable
        sai_folder: folder name of the scanning file
        upload_time: upload time
    """

    def __init__(self, id, file_name, class_name, case_name, case_invoc, saiintf_method_table,
                 test_set, test_platform, attr_name, attr_value, runnable, sai_folder, upload_time):

        self.id = id
        self.is_azure_used = False
        self.file_name = file_name
        self.case_name = case_name
        self.class_name = class_name
        self.case_invoc = case_invoc
        self.sai_alias = self.case_invoc[11:]
        self.sai_api = self.sai_alias[:len(self.sai_alias)-10] if 'attribute' in self.sai_alias else self.sai_alias
        self.sai_feature = saiintf_method_table[4:4 + len(saiintf_method_table) - 10].replace('_', '')
        self.test_set = test_set
        self.test_platform = test_platform
        self.sai_obj_attr_key = attr_name
        self.sai_obj_attr_value = attr_value
        self.runnable = runnable
        self.sai_folder = sai_folder
        self.upload_time = upload_time
