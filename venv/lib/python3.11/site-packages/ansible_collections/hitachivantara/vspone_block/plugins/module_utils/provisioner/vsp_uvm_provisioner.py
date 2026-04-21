try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit

    # from ..model.vsp_user_models import (
    #     VspUserInfoList,
    # )
except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit

    # from model.vsp_user_models import (
    #     VspUserInfoList,
    # )


logger = Log()


class VSPUvmProvisioner:

    def __init__(self, connection_info, serial=None):
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_UVM
        )
        self.connection_info = connection_info
        self.serial = serial

    @log_entry_exit
    def get_external_port_info(self, spec=None):
        if "external_iscsi_targets" in spec.query:
            return self.get_info_iscsi_target_port_ext_storage(spec)
        elif "registered_external_iscsi_targets" in spec.query:
            return self.get_iscsi_name_ext_storage_register_to_port(spec.ports[0])
        elif "external_storage_ports" in spec.query:
            return self.get_external_storage_ports(spec)
        elif "external_luns" in spec.query:
            return self.get_external_luns(spec)

    @log_entry_exit
    def get_info_iscsi_target_port_ext_storage(self, spec=None):
        return self.gateway.get_info_iscsi_target_port_ext_storage(spec)

    @log_entry_exit
    def get_iscsi_name_ext_storage_register_to_port(self, port):
        return self.gateway.get_iscsi_name_ext_storage_register_to_port(port)

    @log_entry_exit
    def get_external_storage_ports(self, spec=None):
        return self.gateway.get_external_storage_ports(spec)

    @log_entry_exit
    def get_external_luns(self, spec=None):
        if spec.external_wwn:
            return self.gateway.get_external_storage_luns_fc_port(spec)

        if spec.external_iscsi_ip_address and spec.external_iscsi_name:
            return self.gateway.get_external_storage_luns_iscsi_port(spec)

    @log_entry_exit
    def login_test(self, spec=None):
        logger.writeDebug(f"login_test_result:spec = {spec}")
        port = spec.port
        iscsi_targets = spec.external_iscsi_targets

        consolidated_result = {
            "portId": port,
        }
        all_external_iscsi_targets = []
        for iscsi_target in iscsi_targets:
            iscsi_ip_address = iscsi_target.get("ip_address")
            iscsi_name = iscsi_target.get("name")
            result = self.gateway.perform_login_test(port, iscsi_ip_address, iscsi_name)
            logger.writeDebug(f"login_test_result = {result}")
            all_external_iscsi_targets.extend(result.get("externalIscsiTargets"))
        consolidated_result["externalIscsiTargets"] = all_external_iscsi_targets
        return consolidated_result

    @log_entry_exit
    def register_external_iscsi_target(self, spec=None):
        port = spec.port
        iscsi_targets = spec.external_iscsi_targets
        logger.writeDebug(f"login_test_result = {iscsi_targets}")
        # all_result = []
        for iscsi_target in iscsi_targets:
            iscsi_ip_address = iscsi_target.get("ip_address")
            iscsi_name = iscsi_target.get("name")
            tcp_port = iscsi_target.get("tcp_port", None)
            result = self.gateway.register_iscsi_name_ext_storage_port(
                port, iscsi_ip_address, iscsi_name, tcp_port
            )
            logger.writeDebug(f"register_external_iscsi_target = {result}")
            # all_result.append(result)
        # return all_result
        return self.get_iscsi_name_ext_storage_register_to_port(port)

    @log_entry_exit
    def unregister_external_iscsi_target(self, spec=None):
        port = spec.port
        iscsi_targets = spec.external_iscsi_targets
        logger.writeDebug(f"login_test_result = {iscsi_targets}")
        # all_result = []
        for iscsi_target in iscsi_targets:
            iscsi_ip_address = iscsi_target.get("ip_address")
            iscsi_name = iscsi_target.get("name")
            tcp_port = iscsi_target.get("tcp_port", None)
            result = self.gateway.delete_iscsi_name_of_external_storage_from_port(
                port, iscsi_ip_address, iscsi_name
            )
            logger.writeDebug(f"unregister_external_iscsi_target = {result}")
            # all_result.append(result)
        # return all_result
        return self.get_iscsi_name_ext_storage_register_to_port(port)

    @log_entry_exit
    def disconnect_from_a_volume_on_external_storage(self, spec=None):
        result = self.gateway.disconnect_from_a_volume_on_external_storage(
            spec.external_parity_group
        )
        return result
