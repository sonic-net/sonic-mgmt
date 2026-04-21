from enum import Enum


class SDSBSoftwareUpdateValidationMsg(Enum):

    SOFTWARE_UPDATE_FILE_NOT_FOUND = "The software update file was not found. Either the cluster has not been updated or update file has been deleted."
    STOP_SOFTWARE_UPDATE_SUCCESS_MSG = "Successfully stopped software update."
    STOP_SOFTWARE_UPDATE_FAILURE_MSG = (
        "The job could not be stopped. There is no Job to be stopped."
    )
    DOWNGRADE_SOFTWARE_SUCCESS_MSG = (
        "Successfully started downgrading storage software job. This is a long running operation, and might take some time."
        "You can check the status of the job started periodically using hv_sds_block_job_facts module."
        "ID for this job = {}"
    )
    DOWNGRADE_SOFTWARE_FAILURE_MSG = (
        "Failed to downgrade the software. Verify that the storage software update file has been uploaded. "
        "Also, confirm that the address specified in connection_info is either the IP or the FQDN of the cluster master node (primary)."
    )
    UPDATE_SOFTWARE_SUCCESS_MSG = (
        "Successfully started updating storage software job. This is a long running operation, and might take some time."
        "You can check the status of the job started periodically using hv_sds_block_job_facts module."
        "ID for this job = {}"
    )
    UPDATE_SOFTWARE_FAILURE_MSG = "Failed to update software. Check if the storage software update file was uploaded."
    SOFTWARE_UPDATE_FILE_REQD = "software_update_file is a mandatory field for this operation, but it is missing."
    SOFTWARE_UPDATE_FILE_DOES_NOT_EXIST = (
        "File path ({}) provided for the software_update_file does not exist."
    )
    UPLOAD_SOFTWARE_UPDATE_FILE_SUCCESS_MSG = (
        "Successfully uploaded software update file to the cluster."
    )
    UPLOAD_SOFTWARE_UPDATE_FILE_FAILURE_MSG = (
        "Failed to upload software update file to the cluster."
    )
