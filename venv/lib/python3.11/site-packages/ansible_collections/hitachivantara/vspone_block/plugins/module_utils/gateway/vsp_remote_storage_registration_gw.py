try:
    from .gateway_manager import VSPConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from ..model.common_base_models import VSPStorageDevice
    from ..model.vsp_remote_storage_registration_models import (
        VSPRemoteStorageSystemsInfoPfrestList,
        VSPRemoteStorageSystemsInfoPfrest,
    )
except ImportError:
    from .gateway_manager import VSPConnectionManager
    from common.hv_log import Log
    from common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from model.common_base_models import VSPStorageDevice
    from model.vsp_remote_storage_registration_models import (
        VSPRemoteStorageSystemsInfoPfrestList,
        VSPRemoteStorageSystemsInfoPfrest,
    )

SET_CMD_DEVICE_DIRECT = "v1/objects/ldevs/{}/actions/set-as-command-device/invoke"
POST_UPDATE_CACHE = "v1/services/storage-cache-service/actions/refresh/invoke"
GET_STORAGE_INFO_DIRECT = "v1/objects/storages"
REGISTER_REMOTE_STORAGE_DIRECT = "v1/objects/remote-storages"
GET_REMOTE_STORAGES_DIRECT = "v1/objects/remote-storages"
DELETE_REMOTE_STORAGE_DIRECT = "v1/objects/remote-storages/{}"


logger = Log()
gCopyGroupList = None


class VSPRemoteStorageRegistrationDirectGateway:

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
    def init_remote_connection_manager(self, remote_connection_info):
        self.remote_connection_manager = VSPConnectionManager(
            remote_connection_info.address,
            remote_connection_info.username,
            remote_connection_info.password,
            remote_connection_info.api_token,
        )
        return

    def init_connections(self, remote_connection_info):
        self.connection_manager = VSPConnectionManager(
            self.connection_info.address,
            self.connection_info.username,
            self.connection_info.password,
            remote_connection_info.api_token,
        )
        self.remote_connection_manager = VSPConnectionManager(
            remote_connection_info.address,
            remote_connection_info.username,
            remote_connection_info.password,
            remote_connection_info.api_token,
        )
        return

    @log_entry_exit
    def get_storage_model(self):
        end_point = GET_STORAGE_INFO_DIRECT
        storage_info = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_storage_model:storage details={}", storage_info)
        storage_info = VSPStorageDevice(**storage_info)
        return storage_info.model

    @log_entry_exit
    def get_remote_storage_device_id(self, remote_connection_info):
        if self.remote_connection_manager is None:
            self.init_remote_connection_manager(remote_connection_info)
        end_point = GET_STORAGE_INFO_DIRECT
        storage_info = self.remote_connection_manager.get(end_point)
        logger.writeDebug("GW:get_storage_model:storage details={}", storage_info)
        storage_info = VSPStorageDevice(**storage_info["data"][0])
        return storage_info.storageDeviceId

    @log_entry_exit
    def get_remote_storages_from_local(self):
        end_point = GET_REMOTE_STORAGES_DIRECT
        storage_devices = self.connection_manager.get(end_point)
        logger.writeDebug(
            "GW:get_remote_storages_from_local:storage_devices={}", storage_devices
        )
        return VSPRemoteStorageSystemsInfoPfrestList(
            dicts_to_dataclass_list(
                storage_devices["data"], VSPRemoteStorageSystemsInfoPfrest
            )
        )

    @log_entry_exit
    def get_remote_storages_from_remote(self, remote_connection_info):
        if self.remote_connection_manager is None:
            self.init_remote_connection_manager(remote_connection_info)

        end_point = GET_REMOTE_STORAGES_DIRECT
        storage_devices = self.remote_connection_manager.get(end_point)
        logger.writeDebug(
            "GW:get_remote_storages_from_remote:storage_devices={}", storage_devices
        )
        return VSPRemoteStorageSystemsInfoPfrestList(
            dicts_to_dataclass_list(
                storage_devices["data"], VSPRemoteStorageSystemsInfoPfrest
            )
        )

    @log_entry_exit
    def get_remote_token(self, remote_connection_info):
        if self.remote_connection_manager is None:
            self.init_remote_connection_manager(remote_connection_info)
        # logger.writeDebug(f"GW-Direct:create_true_copy:get_remote_token:remote_connection_info={remote_connection_info}")
        try:
            token = self.remote_connection_manager.getAuthToken()
            return token
        except Exception as e:
            if "User authentication failed" in str(e):
                self.init_remote_connection_manager(remote_connection_info)
                return self.remote_connection_manager.getAuthToken()
            else:
                logger.writeDebug("GW:get_remote_token:exception={}", e)
                raise e

    @log_entry_exit
    def get_rest_server_token(self, address, username, password):
        rest_connection_manager = VSPConnectionManager(address, username, password)
        return rest_connection_manager.getAuthToken()

    @log_entry_exit
    def get_remote_rest_server_ip(self, remote_storage_id):
        storages = self.get_remote_storages_from_local()
        for storage in storages.data:
            if storage.storageDeviceId == remote_storage_id:
                return storage.restServerIp
        raise ValueError("Remote storage not found.")

    @log_entry_exit
    def delete_remote_storage(self, spec):

        if spec.is_mutual_deletion is not None and spec.is_mutual_deletion is False:
            payload = {"isMutualDeletion": False}
        else:
            payload = {"isMutualDeletion": True}

        remote_storage_id = self.get_remote_storage_device_id(
            spec.secondary_connection_info
        )
        logger.writeDebug(
            "GW:delete_remote_storage: payload={} remote_storage_id={}",
            payload,
            remote_storage_id,
        )
        rest_server_ip = self.get_remote_rest_server_ip(remote_storage_id)
        headers = self.get_rest_server_token(
            rest_server_ip,
            spec.secondary_connection_info.username,
            spec.secondary_connection_info.password,
        )
        headers["Remote-Authorization"] = headers.pop("Authorization")
        end_point = DELETE_REMOTE_STORAGE_DIRECT.format(remote_storage_id)
        response = self.connection_manager.delete(
            end_point, payload, headers_input=headers
        )
        self.connection_info.changed = True
        return response

    @log_entry_exit
    def register_remote_storage(self, spec):

        remote_storage_device_id = self.get_remote_storage_device_id(
            spec.secondary_connection_info
        )
        rest_server_ip = spec.secondary_connection_info.address
        rest_server_port = 443
        is_mutual_discovery = True
        if spec.rest_server_ip:
            rest_server_ip = spec.rest_server_ip
        if spec.rest_server_port:
            rest_server_port = spec.rest_server_port
        if spec.is_mutual_discovery is not None and spec.is_mutual_discovery is False:
            is_mutual_discovery = False
        payload = {
            "storageDeviceId": remote_storage_device_id,
            "restServerIp": rest_server_ip,
            "restServerPort": rest_server_port,
            "isMutualDiscovery": is_mutual_discovery,
        }
        logger.writeDebug(
            "GW:is_valid_config_for_remote_replication: payload={}", payload
        )
        # self.init_connections(spec.secondary_connection_info)
        # headers = self.get_remote_token(self.connection_info)
        headers = self.get_rest_server_token(
            rest_server_ip,
            spec.secondary_connection_info.username,
            spec.secondary_connection_info.password,
        )
        headers["Remote-Authorization"] = headers.pop("Authorization")
        end_point = REGISTER_REMOTE_STORAGE_DIRECT
        response = self.connection_manager.post(
            end_point, payload, headers_input=headers
        )
        self.connection_info.changed = True
        return response
