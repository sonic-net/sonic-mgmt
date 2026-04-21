from enum import Enum


class LicenseMsgCatalog(Enum):
    ERR_WRONG_STATE = "Unsupported state value: {}. \
        Only support: present/absent."
    OK_ADD_LICENSE = "Successfully added license: {}."
    ERR_LICENSE_ADD_SPEC = "You must provide a non-empty 'license_file_path' "
    ERR_ADD = "Failed to add license. Error: {}."
