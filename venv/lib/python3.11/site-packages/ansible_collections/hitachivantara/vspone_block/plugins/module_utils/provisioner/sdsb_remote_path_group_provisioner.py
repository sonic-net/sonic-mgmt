try:
    from ..gateway.sdsb_remote_path_group_gateway import SDSBRemotePathGroupGateway
    from ..common.ansible_common import log_entry_exit
    from ..common.hv_log import Log
except ImportError:
    from gateway.sdsb_remote_path_group_gateway import SDSBRemotePathGroupGateway
    from common.ansible_common import log_entry_exit
    from common.hv_log import Log

logger = Log()


class SDSBRemotePathGroupProvisioner:

    def __init__(self, connection_info):
        self.gateway = SDSBRemotePathGroupGateway(connection_info)

    @log_entry_exit
    def get_remote_path_groups(self, spec=None):

        local_storage_controller_id = None
        remote_serial = None
        remote_storage_system_type = None
        path_group_id = None

        if spec:
            if spec.local_storage_controller_id:
                local_storage_controller_id = spec.local_storage_controller_id
            if spec.remote_serial:
                remote_serial = spec.remote_serial
            if spec.remote_storage_system_type:
                remote_storage_system_type = spec.remote_storage_system_type
            if spec.path_group_id:
                path_group_id = spec.path_group_id

        response = self.gateway.get_remote_path_groups(
            local_storage_controller_id,
            remote_serial,
            remote_storage_system_type,
            path_group_id,
        )
        return response.data_to_snake_case_list()

    @log_entry_exit
    def get_remote_path_group_by_id(self, id):
        try:
            response = self.gateway.get_remote_path_group_by_id(id)
            if response is None:
                return None
            else:
                return response.camel_to_snake_dict()
        except Exception as e:
            logger.writeException(e)
            return None

    @log_entry_exit
    def create_remote_path_group(self, spec=None):
        response = self.gateway.create_remote_path_group(
            spec.remote_serial,
            spec.remote_storage_system_type,
            spec.local_port,
            spec.remote_port,
            spec.path_group_id,
            spec.remote_io_timeout_in_sec,
        )
        return response.camel_to_snake_dict()

    @log_entry_exit
    def delete_remote_path_group(self, id):
        response = self.gateway.delete_remote_path_group(id)
        return response

    @log_entry_exit
    def update_remote_path_group(self, spec=None):
        response = self.gateway.update_remote_path_group(
            spec.id,
            spec.remote_io_timeout_in_sec,
        )
        return response.camel_to_snake_dict()

    @log_entry_exit
    def add_remote_path_to_remote_path_group(self, spec=None):
        response = self.gateway.add_remote_path_to_remote_path_group(
            spec.id,
            spec.local_port,
            spec.remote_port,
        )
        return response.camel_to_snake_dict()

    @log_entry_exit
    def remove_remote_path_from_remote_path_group(self, spec=None):
        response = self.gateway.remove_remote_path_from_remote_path_group(
            spec.id,
            spec.local_port,
            spec.remote_port,
        )
        return response.camel_to_snake_dict()
