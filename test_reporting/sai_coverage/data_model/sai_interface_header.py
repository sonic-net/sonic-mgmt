class SAIInterfaceHeader(object):
    """
    Structure of SAI interface header

    Args:
        intf_groupname: SAI interface groupname
        intf_groupalias: SAI interface groupalias
        intf_name: SAI interface name
        intf_alias: SAI interface alias
        file_name: file name
    """
    def __init__(self, intf_groupname, intf_groupalias, intf_name, intf_alias, file_name):
        self.intf_groupname = intf_groupname
        self.intf_groupalias = intf_groupalias
        self.intf_name = intf_name
        self.intf_alias = intf_alias
        self.file_name = file_name
