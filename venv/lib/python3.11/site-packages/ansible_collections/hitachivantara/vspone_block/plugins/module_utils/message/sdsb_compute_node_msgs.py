from enum import Enum


class SDSBComputeNodeMessage(Enum):
    pass


class SDSBComputeNodeValidationMsg(Enum):

    VOLUMES_EXIST = "Ensure that all volume names provided in the spec are present in the system. Compute node is not created."
    ADD_ISCSI_ERR = "spec.state is add_iscsi_initiator, but iscsi_initiators are not provided. Compute node is not created."
    ADD_NQNS_ERR = "spec.state is add_host_nqns, but host nqns are not provided. Compute node is not created."
    ADD_BOTH_IQN_NQN_ERR = (
        "Both iscsi_initiators and host_nqns are provided, you can specify only one type, "
        "based on your compute port protocol. Compute node is not created."
    )
    ATTACH_VOLUME_ERR = "spec.state is attach_volume, but volumes are not provided. Compute node is not created."
    INVALID_SPEC_STATE = "Invalid state provided in the spec. Valid states in the spec are : {0}, {1}, {2}, {3}, {4} and {5}."
    NO_SPEC = "Specifications for the compute node are not provided."
    COMPUTE_NODE_ID_ABSENT = "Could not find compute node with ID {0}."
    NO_NAME_ID = "Either compute node ID or compute node name must be provided"
    INVALID_OS_TYPE = (
        "Invalid os_type {0} specified, valid values are Linux, VMware, and Windows."
    )
    OS_TYPE_REQUIRED = "os_type is required for compute node creation. Provide os_type in the spec with valid values Linux, VMware, or Windows."
    CN_NAME_NOT_FOUND = "Could not find compute node with name {0}."
    STRING_VALUE_HBA = "Provide a string for hba_name."
