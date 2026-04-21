try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..provisioner.vsp_storage_system_provisioner import VSPStorageSystemProvisioner
    from ..gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from ..common.hv_log import Log
    from ..model.vsp_external_path_group_models import ExternalPathGroupSpec
    from ..common.ansible_common import (
        log_entry_exit,
    )
    from ..message.vsp_external_path_group_msgs import VSPSExternalPathGroupValidateMsg

except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from provisioner.vsp_storage_system_provisioner import VSPStorageSystemProvisioner
    from gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from common.hv_log import Log
    from model.vsp_external_path_group_models import ExternalPathGroupSpec
    from common.ansible_common import (
        log_entry_exit,
    )
    from message.vsp_external_path_group_msgs import VSPSExternalPathGroupValidateMsg

logger = Log()


class VSPExternalPathGroupProvisioner:

    def __init__(self, connection_info, serial):
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_UVM
        )

        self.storage_prov = VSPStorageSystemProvisioner(connection_info)
        self.connection_info = connection_info
        self.connection_type = connection_info.connection_type
        self.serial = serial
        if self.serial is None:
            self.serial = self.get_storage_serial_number()
        self.gateway.set_storage_serial_number(serial)

    @log_entry_exit
    def get_storage_serial_number(self):
        storage_gw = VSPStorageSystemDirectGateway(self.connection_info)
        storage_system = storage_gw.get_current_storage_system_info()
        return storage_system.serialNumber

    @log_entry_exit
    def rm_external_path_from_group(self, spec: ExternalPathGroupSpec):
        if spec.external_fc_paths:
            for path in spec.external_fc_paths:
                if not path.port or not path.external_wwn:
                    raise ValueError(
                        VSPSExternalPathGroupValidateMsg.FC_PATH_FIELDS.value
                    )

                data = self.remove_external_path_from_path_group_fc(
                    spec.external_path_group_id, path
                )

                if data is None:
                    raise ValueError(
                        VSPSExternalPathGroupValidateMsg.DEL_FC_PATH_FAILED.value.format(
                            path.port, path.external_wwn
                        )
                    )
                else:
                    logger.writeDebug(
                        f"External FC path {path} removed from path group successfully."
                    )

        if spec.external_iscsi_target_paths:
            for path in spec.external_iscsi_target_paths:
                if not path.external_iscsi_ip_address or not path.external_iscsi_name:
                    raise ValueError(
                        VSPSExternalPathGroupValidateMsg.ISCSI_PATH_FIELDS.value
                    )

                data = self.remove_external_path_from_path_group_iscsi(
                    spec.external_path_group_id, path
                )

                if data is None:
                    raise ValueError(
                        VSPSExternalPathGroupValidateMsg.DEL_ISCSI_PATH_FAILED.value.format(
                            path.port,
                            path.external_iscsi_ip_address,
                            path.external_iscsi_name,
                        )
                    )
                else:
                    logger.writeDebug(
                        f"External iSCSI target path {path} removed from path group successfully."
                    )

    @log_entry_exit
    def add_external_path_to_group(self, spec: ExternalPathGroupSpec):
        PATH_ALREADY_DEFINED_MSG = "The same external path is already defined for the specified external path group."
        if spec.external_fc_paths:
            for path in spec.external_fc_paths:
                if not path.port or not path.external_wwn:
                    raise ValueError(
                        VSPSExternalPathGroupValidateMsg.FC_PATH_FIELDS.value
                    )
                try:
                    data = self.add_external_path_to_path_group_fc(
                        spec.external_path_group_id, path
                    )
                except Exception as e:
                    if PATH_ALREADY_DEFINED_MSG in str(e):
                        logger.writeException(e)
                        continue
                    else:
                        raise ValueError(str(e))
                if data is None:
                    raise ValueError(
                        VSPSExternalPathGroupValidateMsg.ADD_FC_PATH_FAILED.value.format(
                            path.port, path.external_wwn
                        )
                    )
                else:
                    logger.writeDebug(
                        f"External FC path {path} added to path group successfully."
                    )

        if spec.external_iscsi_target_paths:
            for path in spec.external_iscsi_target_paths:
                if not path.external_iscsi_ip_address or not path.external_iscsi_name:
                    raise ValueError(
                        VSPSExternalPathGroupValidateMsg.ISCSI_PATH_FIELDS.value
                    )
                try:
                    data = self.add_external_path_to_path_group_iscsi(
                        spec.external_path_group_id, path
                    )
                except Exception as e:
                    if PATH_ALREADY_DEFINED_MSG in str(e):
                        logger.writeException(e)
                        continue
                    else:
                        raise ValueError(str(e))
                if data is None:
                    raise ValueError(
                        VSPSExternalPathGroupValidateMsg.ADD_ISCSI_PATH_FAILED.value.format(
                            path.port,
                            path.external_iscsi_ip_address,
                            path.external_iscsi_name,
                        )
                    )
                else:
                    logger.writeDebug(
                        f"External iSCSI target path {path} added to path group successfully."
                    )

    @log_entry_exit
    def remove_external_path_from_path_group_fc(self, ext_path_gr_id, path):
        return self.gateway.remove_external_path_from_path_group_fc(
            ext_path_gr_id, path
        )

    @log_entry_exit
    def remove_external_path_from_path_group_iscsi(self, ext_path_gr_id, path):
        return self.gateway.remove_external_path_from_path_group_iscsi(
            ext_path_gr_id, path
        )

    @log_entry_exit
    def add_external_path_to_path_group_fc(self, ext_path_gr_id, path):
        return self.gateway.add_external_path_to_path_group_fc(ext_path_gr_id, path)

    @log_entry_exit
    def add_external_path_to_path_group_iscsi(self, ext_path_gr_id, path):
        return self.gateway.add_external_path_to_path_group_iscsi(ext_path_gr_id, path)
