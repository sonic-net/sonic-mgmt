class SAIInterfaceHeader(object):
    """
    Structure of SAI interface header
    """
    def __init__(self, intf_groupname, intf_groupalias, intf_name, intf_alias, file_name):
        sai_method_table_split = intf_groupalias.split('_')
        sai_feature = sai_method_table_split[1: len(sai_method_table_split)-2]

        self.sai_header = file_name
        self.sai_id = intf_groupname
        self.sai_method_table = intf_groupalias
        self.sai_feature = ''.join(sai_feature)
        self.sai_api = intf_alias[:-10] if 'attribute' in intf_alias else intf_alias
        self.sai_alias = intf_alias
