from enum import Enum


class StorageComponentMsgCatalog(Enum):
    ERR_WRONG_STATE = "Unsupported state value: {}. \
        Only support: present/absent."
    OK_CREATE_NEW_STORAGE_COMPONENT = "Successfully created storage component: {}."
    OK_DEL_NEW_STORAGE_COMPONENT = "Successfully created storage component: {}."
    ERR_ACTIVATE_STORAGE_COMPONENT = "Failed to activate storage component. Error: {}."
    ERR_TEST_STORAGE_COMPONENT = "Failed to test storage component connectivity. Error: {}."
    ERR_CREATE_STORAGE_COMPONENT = "Failed to create storage component. Error: {}."
    ERR_UPDATE_STATE_STORAGE_COMPONENT = "Failed to update storage component state. Error: {}."
    ERR_INVALID_UUID = "'id' field is required."
    ERR_INVALID_SPEC_ID_LABEL = "Invalid spec. Provide value for either \'id\' or \'label\' in the spec."

    ERR_INVALID_COMPONENT_STATE = "Invalid storage component state: {}. Provide correct desired state."
    ERR_INVALID_SPEC_FIELDS = (
        "Invalid spec detected. "
        "Please provide both valid \'id\' or \'storage_component_state\' field."
    )
    ERR_INVALID_ID = "\'id\' field is required."
    ERR_COMPONENT_STATE_EMPTY = "\'storage_component_state\' must be specified."
    ERR_INVALID_COMPONENT_STATE_TYPE = "\'storage_component_state\' must be an string."
    ERR_EMPTY_SPEC = "\'spec\' cannot be empty"
    ERR_EMPTY_COMP_CONF = "\'storage_component_config\' cannot be empty"
    ERR_INVALID_STATE = "Cannot set both \'operation\' and \'storage_component_config\' at the same time"
    INFO_ACTIVE_STATE = "Storage component with id {} is already activated."
    FIELDS_MISSING_CREATE = ("\'{}\' is missing in the spec.")
    ERR_ID_NOT_FOUND = "Storage component with \'id\' {} is not present."
    ERR_INVALID_ID_VALUE = "Storage component id {} is invalid."
    ERR_INVALID_STATE_CONVERSION = "Invalid State Conversion. Cannot convert from {} to {}."
    ERR_INVALID_COMPONENT_QUERY_PARAM = "Invalid storage component facts query param : {}."
    ERR_OPERATION_UNSUPPORTED = "Operation not supported. Provide \'query\' param"
    ERR_INVALID_PAGE_SIZE = "Invalid page_size value : {}. It must be a positive integer."
    ERR_INVALID_TYPE_PAGE_SIZE = "Invalid type for page_size. It must be an integer."
