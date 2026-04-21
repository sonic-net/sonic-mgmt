try:
    from ..gateway.sdsb_platform_info_gateway import SDSBPlatformInfoGateway
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..gateway.sdsb_cluster_gateway import SDSBClusterGateway
except ImportError:
    from gateway.sdsb_platform_info_gateway import SDSBPlatformInfoGateway
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit

logger = Log()


class SDSBClusterProvisioner:

    def __init__(self, connection_info):

        self.gateway = SDSBClusterGateway(connection_info)
        self.connection_info = connection_info

    @log_entry_exit
    def create_config_file(self, export_file_type):
        return self.gateway.create_config_file(export_file_type)

    @log_entry_exit
    def download_config_file(self, file_name):
        return self.gateway.download_config_file(file_name)

    @log_entry_exit
    def add_storage_node(
        self,
        setup_user_password,
        config_file=None,
        exported_config_file=None,
        vm_configuration_file_s3_uri=None,
    ):
        return self.gateway.add_storage_node(
            setup_user_password,
            config_file,
            exported_config_file,
            vm_configuration_file_s3_uri,
        )

    @log_entry_exit
    def remove_storage_node(self, id):
        return self.gateway.remove_storage_node(id)

    @log_entry_exit
    def stop_removing_storage_nodes(self):
        return self.gateway.stop_removing_storage_nodes()

    @log_entry_exit
    def get_storage_time_settings(self):
        return self.gateway.get_storage_time_settings()

    @log_entry_exit
    def get_platform(self):
        platform_gw = SDSBPlatformInfoGateway(self.connection_info)
        return platform_gw.get_platform().strip()

    @log_entry_exit
    def create_config_file_for_add_storage_node(
        self, machine_image_id, template_s3_url=None
    ):
        return self.gateway.create_config_file_for_add_storage_node(
            machine_image_id, template_s3_url
        )

    @log_entry_exit
    def create_config_file_to_replace_storage_node(self, spec):
        return self.gateway.create_config_file_to_replace_storage_node(
            spec.machine_image_id,
            spec.template_s3_url,
            spec.node_id,
            spec.should_recover_single_node,
        )

    @log_entry_exit
    def edit_capacity_management_settings(
        self, is_capacity_balancing_enabled, controller_id=None
    ):
        return self.gateway.edit_capacity_management_settings(
            is_capacity_balancing_enabled, controller_id
        )

    @log_entry_exit
    def create_config_file_for_add_drives(self, no_of_drives):
        return self.gateway.create_config_file_for_add_drives(no_of_drives)

    @log_entry_exit
    def import_system_requirement_file(self, spec):
        return self.gateway.import_system_requirement_file(spec.system_requirement_file)

    @log_entry_exit
    def stop_storage_cluster(self, spec):
        return self.gateway.stop_storage_cluster(
            spec.force, spec.reboot, spec.config_parameter_setting_mode
        )
