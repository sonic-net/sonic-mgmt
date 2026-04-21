from enum import Enum


class StorageClassMsgCatalog(Enum):
    ERR_CREATE_UPDATE = "Failed to create/update storage class. Error: {}."
    ERR_UPDATE = "Failed to update default storage class. Error: {}."
    ERR_INVALID_SPEC_FIELDS = (
        "Invalid spec detected. "
        "Please provide either a valid \'id\' or \'page_size\' field, "
        "but not both simultaneously."
    )
    ERR_INVALID_DEFAULT_SPEC = "Cannot provide the parameter \'default\' in the spec with other parameters."
    ERR_INVALID_SIZE = "Invalid Page Size: {}. Provide a positive integer."
    ERR_INVALID_ID = "\'id\' field is required."
    ERR_INVALID_ID_VALUE = "Storage class id \'{}\' is invalid."
    ERR_INVALID_TYPE_PAGE_SIZE = "\'page_size\' must be an integer."
    ERR_ID_NOT_FOUND = "Storage class with id \'{}\' does not exist."
    ERR_INVALID_NAME = "\'name\' field is required."
    ERR_INVALID_DATA_COUNT = "\'data_count\' field is required."
    ERR_INVALID_PARITY_COUNT = "\'parity_count\' field is required."
