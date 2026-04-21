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
R9 = "R9"
M8 = "M8"

logger = Log()


class VSPIscsiRemoteConnectionProvisioner:

    def __init__(self, connection_info, serial=None):
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_ISCSI_REMOTE_CONNECTION
        )
        self.connection_info = connection_info

        self.remote_storage_system_gw = VSPRemoteStorageRegistrationProvisioner(
            connection_info
        )
        self.remote_storage_type_id = None
        self.remote_storage_device_id = None
        self.remote_serial = None

    @log_entry_exit
    def get_all_iscsi_remote_connections(
        self,
    ):
        remote_connections = self.gateway.get_all_iscsi_remote_connections()
        return remote_connections

    @log_entry_exit
    def get_iscsi_remote_connection_by_id(self, object_id):
        remote_connection = self.gateway.get_iscsi_remote_connection_by_id(object_id)
        return remote_connection

    @log_entry_exit
    def create_update_iscsi_remote_connection(self, spec):
        spec.remote_serial_number = self.remote_serial
        spec.remote_storage_type_id = self.remote_storage_type_id
        spec.remote_storage_device_id = self.remote_storage_device_id
        spec.object_id = f"{spec.local_port},{self.remote_serial},{self.remote_storage_type_id},{spec.remote_port}"

        existing_remote = self.get_iscsi_remote_connection_by_id(spec.object_id)
        if not existing_remote:
            response = self.gateway.create_iscsi_remote_connection(spec)
            self.connection_info.changed = True
            existing_remote = self.get_iscsi_remote_connection_by_id(spec.object_id)
        return existing_remote.camel_to_snake_dict()

    @log_entry_exit
    def delete_iscsi_remote_connection(self, spec):
        spec.object_id = f"{spec.local_port},{self.remote_serial},{self.remote_storage_type_id},{spec.remote_port}"
        rc = self.get_iscsi_remote_connection_by_id(spec.object_id)
        if not rc:
            return VSPRemoteConnectionMSG.REMOTE_CONNECTIONS_NOT_FOUND.value
        response = self.gateway.delete_iscsi_remote_connection(spec.object_id)
        self.connection_info.changed = True
        return

    def get_remote_connection_facts(self, spec):
        connections = self.get_all_iscsi_remote_connections()
        return connections.data_to_snake_case_list()

    @log_entry_exit
    def get_remote_connection_info(self):
        basic_info = self.remote_storage_system_gw.get_remote_storages_from_local()
        for storage in basic_info.data:
            if storage.serialNumber == int(self.remote_serial):
                self.remote_storage_device_id = storage.storageDeviceId
                self.remote_storage_type_id = (
                    R9 if R9_MODEL_NAME in storage.model else M8
                )
                return basic_info
        raise ValueError(
            VSPRemoteConnectionMSG.REMOTE_STORAGE_IS_NOT_REGISTERED.value.format(
                self.remote_serial
            )
        )
