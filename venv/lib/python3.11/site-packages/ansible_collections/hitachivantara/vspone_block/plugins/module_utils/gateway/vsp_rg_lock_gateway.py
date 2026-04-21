try:
    from .gateway_manager import VSPConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
except ImportError:
    from .gateway_manager import VSPConnectionManager
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit

LOCK_RESOURCE_GROUP_DIRECT = "v1/services/resource-group-service/actions/lock/invoke"
UNLOCK_RESOURCE_GROUP_DIRECT = (
    "v1/services/resource-group-service/actions/unlock/invoke"
)
POST_UPDATE_CACHE = "v1/services/storage-cache-service/actions/refresh/invoke"

logger = Log()
gCopyGroupList = None


class VSPResourceGroupLockDirectGateway:

    def __init__(self, connection_info):
        self.connection_manager = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )
        self.connection_info = connection_info
        self.remote_connection_manager = None
        self.serial = None

    @log_entry_exit
    def set_serial(self, serial):
        self.serial = serial

    @log_entry_exit
    def lock_resource_group(self, spec):
        parameters = {
            "waitTime": 0,
        }
        if spec.lock_timeout_sec:
            parameters["waitTime"] = spec.lock_timeout_sec
        payload = {"parameters": parameters}

        lock_session_id, lock_token = self.connection_manager.get_lock_session_token()
        end_point = LOCK_RESOURCE_GROUP_DIRECT
        response = self.connection_manager.post(
            end_point, data=payload, token=lock_token
        )
        logger.writeDebug(
            f"lock_resource_group:response={response} lock_token={lock_token} lock_session_id={lock_session_id}"
        )
        remote_lock_session_id = None
        remote_lock_token = None
        if spec.secondary_connection_info is not None:
            self.remote_connection_manager = VSPConnectionManager(
                spec.secondary_connection_info.address,
                spec.secondary_connection_info.username,
                spec.secondary_connection_info.password,
                spec.secondary_connection_info.api_token,
            )
            remote_lock_session_id, remote_lock_token = (
                self.remote_connection_manager.get_lock_session_token()
            )
            response2 = self.remote_connection_manager.post(
                end_point, data=payload, token=remote_lock_token
            )
            logger.writeDebug(
                f"lock_resource_group:response2={response2} lock_token={remote_lock_token} lock_session_id={remote_lock_session_id}"
            )

        self.connection_info.changed = True
        return lock_session_id, lock_token, remote_lock_session_id, remote_lock_token

    @log_entry_exit
    def unlock_resource_group(self, spec):
        end_point = UNLOCK_RESOURCE_GROUP_DIRECT
        response = self.connection_manager.post(end_point, data=None)
        logger.writeDebug(f"unlock_resource_group:response={response}")
        if spec.secondary_connection_info is not None:
            self.remote_connection_manager = VSPConnectionManager(
                spec.secondary_connection_info.address,
                spec.secondary_connection_info.username,
                spec.secondary_connection_info.password,
                spec.secondary_connection_info.api_token,
            )
            response2 = self.remote_connection_manager.post(end_point, data=None)
            logger.writeDebug(f"unlock_resource_group:response2={response2}")
        self.connection_info.changed = True
        return response
