try:

    from .gateway_manager import VSPConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..model.vsp_server_priority_manager_models import (
        ServerPriorityManagerInfoList,
        ServerPriorityManagerInfo,
    )
except ImportError:
    from .gateway_manager import VSPConnectionManager
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from model.vsp_server_priority_manager_models import (
        ServerPriorityManagerInfoList,
        ServerPriorityManagerInfo,
    )


SPM_URL = "v1/objects/io-control-ldev-wwns-iscsis"
SPM_URL_FOR_QUERY = "v1/objects/io-control-ldev-wwns-iscsis{}"
ONE_SPM_URL = "v1/objects/io-control-ldev-wwns-iscsis/{}"

logger = Log()


class VSPSpmGateway:
    def __init__(self, connection_info):

        self.connection_manager = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )
        self.connection_info = connection_info
        self.serial = None
        self.pegasus_model = None

    @log_entry_exit
    def set_storage_serial_number(self, serial=None):
        if serial:
            self.serial = serial
            logger.writeDebug(f"GW:set_serial={self.serial}")

    @log_entry_exit
    def get_all_spms(self):
        end_point = SPM_URL
        spms = self.connection_manager.get(end_point)
        logger.writeDebug(
            "GW:get_all_spms:spms={}",
            spms,
        )
        spms = ServerPriorityManagerInfoList().dump_to_object(spms)
        return spms

    @log_entry_exit
    def get_spms_with_query(self, ldev_id=None, host_wwn=None, iscsi_name=None):
        q_string = ""
        if ldev_id:
            q_string = f"?ldevId={ldev_id}"
        elif host_wwn:
            q_string = f"?hostWwn={host_wwn}"
        elif host_wwn:
            q_string = f"?iscsiName={iscsi_name}"
        end_point = SPM_URL_FOR_QUERY.format(q_string)
        spms = self.connection_manager.get(end_point)
        logger.writeDebug(
            "GW:get_spms_with_query:spms={}",
            spms,
        )
        spms = ServerPriorityManagerInfoList().dump_to_object(spms)
        return spms

    @log_entry_exit
    def get_one_spm(self, ldev_id, hba_name):
        object_id = f"{ldev_id},{hba_name}"
        end_point = ONE_SPM_URL.format(object_id)
        spm = self.connection_manager.get(end_point)
        logger.writeDebug(
            "GW:get_one_spm:spm={}",
            spm,
        )
        spm = ServerPriorityManagerInfo(**spm)
        return spm

    @log_entry_exit
    def set_spm(self, spm_set_object):
        end_point = SPM_URL
        payload = {}
        payload["ldevId"] = spm_set_object.ldev_id
        if spm_set_object.host_wwn:
            payload["hostWwn"] = spm_set_object.host_wwn
        if spm_set_object.iscsi_name:
            payload["iscsiName"] = spm_set_object.iscsi_name
        if spm_set_object.upper_limit_for_iops:
            payload["upperLimitForIops"] = spm_set_object.upper_limit_for_iops
        if spm_set_object.upper_limit_for_transfer_rate_in_MBps:
            payload["upperLimitForTransferRate"] = (
                spm_set_object.upper_limit_for_transfer_rate_in_MBps
            )

        spm = self.connection_manager.post(end_point, payload)
        logger.writeDebug(
            "GW:set_spm:spm={}",
            spm,
        )

        return spm

    @log_entry_exit
    def change_spm(self, ldev_id, hba_name, spm_change_object):
        object_id = f"{ldev_id},{hba_name}"
        end_point = ONE_SPM_URL.format(object_id)

        payload = {}
        if spm_change_object.upper_limit_for_iops:
            payload["upperLimitForIops"] = spm_change_object.upper_limit_for_iops
        elif spm_change_object.upper_limit_for_transfer_rate_in_MBps:
            payload["upperLimitForTransferRate"] = (
                spm_change_object.upper_limit_for_transfer_rate_in_MBps
            )
        spm = self.connection_manager.patch(end_point, payload)
        logger.writeDebug(
            "GW:change_spm:spm={}",
            spm,
        )
        return spm

    @log_entry_exit
    def delete_spm(self, ldev_id, hba_name):
        object_id = f"{ldev_id},{hba_name}"
        end_point = ONE_SPM_URL.format(object_id)
        spm = self.connection_manager.delete(end_point)
        logger.writeDebug(
            "GW:delete_spm:spm={}",
            spm,
        )
        return spm
