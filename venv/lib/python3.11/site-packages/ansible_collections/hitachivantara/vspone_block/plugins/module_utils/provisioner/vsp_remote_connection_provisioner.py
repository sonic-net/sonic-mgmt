try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from .vsp_remote_storage_registration_provisioner import (
        VSPRemoteStorageRegistrationProvisioner,
    )
    from ..message.vsp_remote_connection_msgs import VSPRemoteConnectionMSG
except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from .vsp_remote_storage_registration_provisioner import (
        VSPRemoteStorageRegistrationProvisioner,
    )
    from message.vsp_remote_connection_msgs import VSPRemoteConnectionMSG


R9_MODEL_NAME = "VSP 5"
B85 = "B85"
R9 = "R9"
M8 = "M8"
RH20ETP = "RH20ETP"

logger = Log()


class VSPRemoteConnectionProvisioner:

    def __init__(self, connection_info, serial=None):
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_REMOTE_CONNECTION
        )
        self.connection_info = connection_info

        self.remote_storage_system_gw = VSPRemoteStorageRegistrationProvisioner(
            connection_info
        )
        self.remote_storage_type_id = None
        self.remote_storage_device_id = None
        self.remote_serial = None

        # fetch the remote storage device id and type id
        # self.get_remote_connection_info()

    @log_entry_exit
    def get_all_remote_connections(self, basic=True):
        remote_connections = self.gateway.get_all_remote_connections(basic=basic)
        return remote_connections

    @log_entry_exit
    def get_detail_remote_connection_by_id(self, object_id):
        remote_connections = self.get_all_remote_connections(basic=False)
        for remote_connection in remote_connections.data:
            if remote_connection.remotepathGroupId == object_id:
                return remote_connection
        return None

    @log_entry_exit
    def get_remote_connection_by_id(self, object_id):
        remote_connection = self.gateway.get_remote_connection_by_id(object_id)
        return remote_connection

    @log_entry_exit
    def create_update_remote_connection(self, spec):
        spec.remote_serial_number = self.remote_serial
        spec.remote_storage_type_id = self.remote_storage_type_id
        spec.remote_storage_device_id = self.remote_storage_device_id
        spec.object_id = (
            f"{self.remote_serial},{self.remote_storage_type_id},{spec.path_group_id}"
        )

        existing_remote = self.get_remote_connection_by_id(spec.object_id)
        if not existing_remote:

            if spec.remote_paths is None or len(spec.remote_paths) < 1:
                raise ValueError(VSPRemoteConnectionMSG.REMOTE_PATHS_NOT_PROVIDED.value)
            try:
                self.gateway.create_remote_connection(spec)
            except Exception as e:
                if self.get_remote_connection_by_id(spec.object_id):
                    self.gateway.delete_remote_connection(spec.object_id)
                raise e
            spec.remote_paths = (
                spec.remote_paths[1:] if len(spec.remote_paths) > 1 else []
            )

        self.update_remote_connection(spec, existing_remote)
        response = self.get_detail_remote_connection_by_id(
            spec.object_id
        ).camel_to_snake_dict()

        return response

    @log_entry_exit
    def change_remote_connection_settings(self, spec):
        if (
            spec.min_remote_paths
            or spec.remote_io_timeout_in_sec
            or spec.round_trip_in_msec
        ):
            response = self.gateway.change_remote_connection_settings(spec)
        return

    @log_entry_exit
    def add_remote_path(self, spec):
        response = self.gateway.add_remote_path(spec)
        self.connection_info.changed = True
        return response

    @log_entry_exit
    def update_remote_connection(self, spec, existing_remote=None):

        spec_paths_normalized = set()
        existing_remote_paths_normalized = set()
        changed = False
        if spec.remote_paths is not None:
            # Normalize the remote paths to spec type and compare
            if existing_remote is not None:
                logger.writeDebug(
                    f"Existing remote paths: {existing_remote.remotePaths}"
                )
                existing_remote_paths_normalized = {
                    frozenset(
                        {
                            "local_port": path.localPortId,
                            "remote_port": path.remotePortId,
                        }.items()
                    )
                    for path in existing_remote.remotePaths
                }

            spec_paths_normalized = {
                frozenset(path.to_dict().items()) for path in spec.remote_paths
            }

            paths_to_add = [
                dict(path)
                for path in spec_paths_normalized.difference(
                    existing_remote_paths_normalized
                )
            ]
            paths_to_remove = [
                dict(path)
                for path in existing_remote_paths_normalized.difference(
                    spec_paths_normalized
                )
            ]

            for path in paths_to_add:
                self.gateway.add_remote_path_to_remote_connection_single(
                    spec.object_id, path["local_port"], path["remote_port"]
                )

                changed = True
            for path in paths_to_remove:
                self.gateway.remove_remote_path_from_remote_connection_single(
                    spec.object_id, path["local_port"], path["remote_port"]
                )
                changed = True

        if self.gateway.change_remote_connection_settings(spec):
            changed = True
        self.connection_info.changed = changed
        return

    @log_entry_exit
    def delete_remote_connection(self, spec):
        spec.object_id = (
            f"{self.remote_serial},{self.remote_storage_type_id},{spec.path_group_id}"
        )
        rc = self.get_remote_connection_by_id(spec.object_id)
        if not rc:
            return VSPRemoteConnectionMSG.REMOTE_CONNECTION_NOT_EXITS.value.format(
                spec.path_group_id
            )
        response = self.gateway.delete_remote_connection(spec.object_id)
        self.connection_info.changed = True
        return

    def get_remote_connection_facts(self, spec):
        connections = self.get_all_remote_connections(basic=False)
        if spec.path_group_id is not None:
            connections.data = [
                conn
                for conn in connections.data
                if conn.pathGroupId == spec.path_group_id
            ]
        return connections.data_to_snake_case_list()

    @log_entry_exit
    def get_remote_connection_info(self):
        basic_info = self.remote_storage_system_gw.get_remote_storages_from_local()
        for storage in basic_info.data:
            if storage.serialNumber == int(self.remote_serial):
                self.remote_storage_device_id = storage.storageDeviceId
                if B85 in storage.model.strip().upper():
                    self.remote_storage_type_id = RH20ETP
                else:
                    self.remote_storage_type_id = (
                        R9 if R9_MODEL_NAME in storage.model else M8
                    )
                return basic_info
        raise ValueError(
            VSPRemoteConnectionMSG.REMOTE_STORAGE_IS_NOT_REGISTERED.value.format(
                self.remote_serial
            )
        )
