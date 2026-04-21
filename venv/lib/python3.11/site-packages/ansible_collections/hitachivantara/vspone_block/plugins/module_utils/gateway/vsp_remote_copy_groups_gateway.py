import time

try:
    from .gateway_manager import VSPConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
except ImportError:
    from .gateway_manager import VSPConnectionManager
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit

GET_REMOTE_STORAGE_SYSTEMS = "v1/objects/remote-storages"
GET_REMOTE_COPY_GROUPS = "v1/objects/remote-mirror-copygroups?remoteStorageDeviceId={}"
GET_ONE_REMOTE_COPY_GROUP = "v1/objects/remote-mirror-copygroups/{}"


logger = Log()


class VSPRemoteCopyGroupsDirectGateway:

    def __init__(self, connection_info):
        self.connection_manager = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )
        self.connection_info = connection_info
        self.remote_connection_manager = None

    @log_entry_exit
    def get_remote_storage_device_id(self, secondary_storage_serial):
        response = self.connection_manager.get(GET_REMOTE_STORAGE_SYSTEMS)
        logger.writeDebug(f"GW:get_remote_storage_device_id:response={response}")
        for x in response.get("data"):
            if str(x.get("serialNumber")) == str(secondary_storage_serial):

                remote_storage_device_id = x.get("storageDeviceId")
                return remote_storage_device_id

        return None

    @log_entry_exit
    def get_remote_copy_groups(self, spec):
        start_time = time.time()
        remote_storage_device_id = self.get_remote_storage_device_id(
            spec.secondary_storage_serial_number
        )
        logger.writeDebug(f"GW:remote_storage_device_id={remote_storage_device_id}")
        remote_connection_info = spec.remote_connection_info
        remote_connection_manager = VSPConnectionManager(
            remote_connection_info.address,
            remote_connection_info.username,
            remote_connection_info.password,
            remote_connection_info.api_token,
        )
        headers = remote_connection_manager.getAuthToken()
        headers["Remote-Authorization"] = headers.pop("Authorization")
        response = self.connection_manager.get_with_headers(
            GET_REMOTE_COPY_GROUPS.format(remote_storage_device_id),
            headers_input=headers,
        )
        logger.writeDebug(f"GW:get_remote_copy_groups:response={response}")
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:get_remote_copy_groups:time={:.2f} no_of_copy_groups = {}",
            end_time - start_time,
            len(response.get("data")),
        )
        return response

    @log_entry_exit
    def get_all_copy_pairs(self, spec):

        if spec.copy_group_name:
            response = self.get_all_copy_pairs_by_copygroup_name(spec)
            return response

        start_time = time.time()
        copy_groups = self.get_remote_copy_groups(spec)
        remote_storage_device_id = self.get_remote_storage_device_id(
            spec.secondary_storage_serial_number
        )
        logger.writeDebug(f"GW:remote_storage_device_id={remote_storage_device_id}")
        remote_connection_info = spec.remote_connection_info
        remote_connection_manager = VSPConnectionManager(
            remote_connection_info.address,
            remote_connection_info.username,
            remote_connection_info.password,
            remote_connection_info.api_token,
        )
        copy_pairs = []
        headers = remote_connection_manager.getAuthToken()
        headers["Remote-Authorization"] = headers.pop("Authorization")
        for x in copy_groups.get("data"):
            try:
                response = self.connection_manager.get_with_headers(
                    GET_ONE_REMOTE_COPY_GROUP.format(x["remoteMirrorCopyGroupId"]),
                    headers_input=headers,
                )
                logger.writeDebug(f"GW:get_remote_copy_pairs:response={response}")
                copy_pairs.append(response)
            except Exception as e:
                logger.writeDebug("GW:get_all_copy_pairs:exception={}", e)
                if "User authentication failed" in str(e):
                    # Refresh the connections
                    self.connection_manager = VSPConnectionManager(
                        self.connection_info.address,
                        self.connection_info.username,
                        self.connection_info.password,
                        self.connection_info.api_token,
                    )
                    remote_connection_manager = VSPConnectionManager(
                        remote_connection_info.address,
                        remote_connection_info.username,
                        remote_connection_info.password,
                        remote_connection_info.api_token,
                    )
                    headers = remote_connection_manager.getAuthToken()
                    headers["Remote-Authorization"] = headers.pop("Authorization")
                    response = self.connection_manager.get_with_headers(
                        GET_ONE_REMOTE_COPY_GROUP.format(x["remoteMirrorCopyGroupId"]),
                        headers_input=headers,
                    )
                    logger.writeDebug(f"GW:get_remote_copy_pairs:response={response}")
                    copy_pairs.append(response)
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:get_all_copy_pairs:time={:.2f} no_of_copy_grps = {} no_of_copy_pairs = {}",
            end_time - start_time,
            len(copy_groups.get("data")),
            len(copy_pairs),
        )
        return copy_pairs

    @log_entry_exit
    def get_all_copy_pairs_by_copygroup_name(self, spec):
        response = self.get_remote_copy_groups(spec)
        remote_storage_device_id = self.get_remote_storage_device_id(
            spec.secondary_storage_serial_number
        )
        logger.writeDebug(f"GW:remote_storage_device_id={remote_storage_device_id}")
        remote_connection_info = spec.remote_connection_info
        remote_connection_manager = VSPConnectionManager(
            remote_connection_info.address,
            remote_connection_info.username,
            remote_connection_info.password,
            remote_connection_info.api_token,
        )
        copy_pairs = []
        for x in response.get("data"):
            if x["copyGroupName"] != spec.copy_group_name:
                continue
            headers = remote_connection_manager.getAuthToken()
            headers["Remote-Authorization"] = headers.pop("Authorization")
            response = self.connection_manager.get_with_headers(
                GET_ONE_REMOTE_COPY_GROUP.format(x["remoteMirrorCopyGroupId"]),
                headers_input=headers,
            )
            logger.writeDebug(f"GW:get_remote_copy_groups:response={response}")
            copy_pairs.append(response)
        return copy_pairs
