from enum import Enum


class StorageFaultDomainMsgCatalog(Enum):
    ERR_WRONG_STATE = "Unsupported state value: {}. \
        Only support: present/absent."
    OK_CREATE_NEW_STORAGE_COMPONENT = "Successfully created storage fault domain: {}."
    OK_DEL_NEW_STORAGE_COMPONENT = "Successfully created storage fault domain: {}."
    OK_CREATE_NEW_STORAGE_FAULT_DOMAIN = "Successfully created storage fault domain: {}."
    OK_DEL_NEW_STORAGE_FAULT_DOMAIN = "Successfully deleted storage fault domain: {}."
    ERR_INVALID_SPEC_FIELDS = (
        "Invalid spec detected. "
        "Please provide either a valid \'id\' or \'page_size\' field, "
        "but not both simultaneously."
    )
    ERR_INVALID_DEFAULT_SPEC = "Cannot provide the parameter \'default\' in the spec with other parameters."
    ERR_INVALID_SIZE = "Invalid Page Size: {}. Provide a positive integer."

    ERR_INVALID_ID_VALUE = "Storage fault domain id \'{}\' is invalid."
    ERR_ID_NOT_FOUND = "Storage fault domain with id \'{}\' does not exist."
    ERR_INVALID_ID = "\'id\' field is required."
    ERR_INVALID_NAME_EMPTY = "\'name\' field is required"
    ERR_INVALID_TYPE_PAGE_SIZE = "\'page_size\' must be an integer."
    ERR_ID_NOT_EXIST = "\'id\' does not exist."
    ERR_NAME_EXISTS = "Storage fault domain name \'{}\' already exists."
