from enum import Enum


class SDSBClusterValidationMsg(Enum):
    NO_NAME_OR_ID_FOR_STORAGE_NODE = "Either node_name or node_id of the storage node must be specified to do this operation."
    STORAGE_NODE_NOT_FOUND = "Did not find storage node named {}."
    STORAGE_NODE_SETUP_PASSWD_REQD = (
        "Storage node setup_user_password is a required field, which is missing."
    )
    CONFIG_FILE_DOES_NOT_EXIST = (
        "File path ({}) provided for the configuration_file does not exist."
    )
    COFIG_FILE_OR_SROARGE_NODES_REQD = (
        "Either configuration_file or storage_nodes must be specified."
    )
    INVALID_SUBNET_MASK = "Subnet mask 255.255.255.255 or 0.0.0.0 cannot be specified."
    FD_NOT_IN_CLUSTER = "The fault_domain_name {} specified in the spec not present in the cluster, cluster's fault domains = {}."
    CONTROL_IP_ALREADY_IN_CLUSTER = (
        "The control_network_ip {} specified in the spec is already present in the cluster, "
        "cluster's control network IPs = {}."
    )
    INTER_NODE_IP_ALREADY_IN_CLUSTER = (
        "The internode_network_ip {} specified in the spec is already present in the cluster, "
        "cluster's inter node network IPs = {}."
    )
    COMPUTE_IP_ALREADY_IN_CLUSTER = "The compute_network_ip {} specified in the spec is already present in the cluster, cluster's compute network IPs = {}."
    SPEC_NONE = "Spec can't be null for add_storage_node operation."
    MACHINE_IMAGE_ID_REQD = (
        "For Azure, machine_image_id is a required field for adding a node."
    )
    SPEC_REQD_CONFIG_CLOUD = (
        "On cloud platform spec is required to create a configuration file."
    )
    EXPORT_FILE_TYPE_REQD_CONFIG_CLOUD = "On the {} Cloud Platform, export_file_type is required to create a configuration file."
    INVALID_EXPORT_FILE_TYPE = (
        "Invalid value provided for export_file_type attribute in the spec for {} cloud platform."
        "Valid values for export_file_type for this cloud platform are {}."
    )
    MACHINE_IMAGE_ID_REQD_CONFIG_CLOUD = "On the {} Cloud Platform, machine_image_id is required for the specified operation to create a configuration file."
    NODE_ID_IS_REQD = "On the GCP, node_id is required for replacing a storage node."
    NO_OF_DRIVES_REQD_CONFIG_CLOUD = "On the {} Cloud Platform, no_of_drives is required for the specified operation to create a configuration file."
    OPERATION_NOT_SUPPORTED_YET = "On the {} Cloud Platform, the specified operation to create a configuration file is not supported yet."
    MUST_SPECIFY_S3_URL = "For AWS, you must specify template_s3_url attribute."
    CONFIG_FILE_REQD = "Configuration file is required for this operation."
    S3_URL_MUST_BE_HTTPS = "template_s3_url must be a https url."
    ADD_STORAGE_NODE_SUCCESS_MSG = (
        "Successfully started add storage node to the cluster job. This is a long running operation, and might take an hour or so."
        "You can check the status of the job started periodically using hv_sds_block_job_facts module."
        "Job ID = {}"
    )
    REPLACE_STORAGE_NODE_SUCCESS_MSG = (
        "Successfully started replace storage node to the cluster job. This is a long running operation, and might take an hour or so."
        "You can check the status of the job started periodically using hv_sds_block_job_facts module."
        "Job ID = {}"
    )
    REMOVE_STORAGE_NODE_SUCCESS_MSG = (
        "Successfully started remove storage node from the cluster job. This is a long running operation, and might take few hours."
        "You can check the status of the job started periodically using hv_sds_block_job_facts module."
        "Job ID = {}"
    )
    STOP_REMOVING_STORAGE_NODE_SUCCESS_MSG = (
        "Successfully stopped removing storage nodes. Job ID = {}"
    )
    STOP_REMOVING_STORAGE_NODE_FAILURE_MSG = (
        "The job could not be stopped. There is no Job to be stopped."
    )
    INVALID_PD_ID = (
        "Invalid protection domain ID. Please provide the ID in UUID format."
    )

    FAILED_REPLACE_STORAGE_NODE = "Failed to replace storage node. Error: {}"
    NODE_ID_REQUIRED = (
        "node_id or node_name must be provided to replace a storage node."
    )
    STORAGE_NODE_INVALID_STATE = (
        "Storage node with id {} is in {} state, cannot be replaced it should "
        "be in one of the following states: {}."
    )
    NOT_FOUND_WITH_STORAGE_NODE_ID = "Not found storage node with id/name {}."
    SYSTEM_REQUIREMENT_FILE_REQD = (
        "The path to the system requirements file is mandatory."
    )
    BAD_SYSTEM_REQUIREMENT_FILE_NAME = (
        "The system requirements file must be named SystemRequirementsFile.yml."
    )
    SYSTEM_REQUIREMENT_FILE_DOES_NOT_EXIST = (
        "File path ({}) provided for the syssystem_requirement_file does not exist."
    )
    IMPORT_SYSTEM_REQUIREMET_FILE_SUCCESS_MSG = (
        "Successfully imported SystemRequirementsFile.yml. Job ID = {}"
    )
    IMPORT_SYSTEM_REQUIREMET_FILE_FAILURE_MSG = (
        "Failed to import SystemRequirementsFile.yml. Cause = {}"
    )
    BAD_PARAMETERS_FOR_STOP_CLUSTER = "When true is specified for reboot or config_parameter_setting_mode, true cannot be specified for force."
    STOP_CLUSTER_SUCCESS_MSG = (
        "Successfully initiated the task to stop the storage cluster. Job ID = {}"
    )
    STOP_CLUSTER_FAILURE_MSG = "Failed to stop storage cluster. Cause = {}"
