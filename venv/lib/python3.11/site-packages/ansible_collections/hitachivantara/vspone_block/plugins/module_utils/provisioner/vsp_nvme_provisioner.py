try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.hv_log import Log
    from ..common.ansible_common import (
        log_entry_exit,
        generate_random_name_prefix_string,
    )
    from ..message.vsp_nvm_msgs import VspNvmValidationMsg
    from ..model.vsp_nvme_models import (
        VspNvmeSubsystemDetailInfo,
        VspNvmeSubsystemDetailInfoList,
        VspNvmeSubsystemDisplay,
        VspNvmePortDisplay,
        VspHostNqnDisplay,
        VspNamespacePathDisplay,
        VspNamespaceDisplay,
    )
    from .vsp_storage_port_provisioner import VSPStoragePortProvisioner


except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit, generate_random_name_prefix_string
    from message.vsp_nvm_msgs import VspNvmValidationMsg
    from model.vsp_nvme_models import (
        VspNvmeSubsystemDetailInfo,
        VspNvmeSubsystemDetailInfoList,
        VspNvmeSubsystemDisplay,
        VspNvmePortDisplay,
        VspHostNqnDisplay,
        VspNamespacePathDisplay,
        VspNamespaceDisplay,
    )
    from .vsp_storage_port_provisioner import VSPStoragePortProvisioner


logger = Log()


class VSPNvmeProvisioner:

    API_MSG = "The API is not supported for the specified storage system"

    def __init__(self, connection_info, serial=None):
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_NVME_SUBSYSTEM
        )
        self.port_prov = VSPStoragePortProvisioner(connection_info)
        self.connection_info = connection_info

        if serial:
            self.serial = serial

    @log_entry_exit
    def get_nvme_subsystem_by_name(self, name):

        nvme_subsystems = self.gateway.get_nvme_subsystems()
        for nvme in nvme_subsystems.data:
            if nvme.nvmSubsystemName == name:
                return nvme
        return None

    @log_entry_exit
    def get_nvme_subsystem_by_id(self, id):

        try:
            nvme_subsystem = self.gateway.get_nvme_subsystem_by_id(id)
            logger.writeDebug(
                f"PV:get_nvme_subsystem_by_id: nvme_subsystem_data=  {nvme_subsystem}"
            )
            return nvme_subsystem
        except Exception as err:
            logger.writeError(err)
            if isinstance(err.args[0], str) and self.API_MSG in err.args[0]:
                err_msg = VspNvmValidationMsg.FEATURE_NOT_SUPPORTED.value
                logger.writeError(err_msg)
                raise ValueError(err_msg)
            else:
                return None

    @log_entry_exit
    def get_nvme_subsystem_details_by_id(self, id):

        try:
            nvme_subsystem = self.gateway.get_nvme_subsystem_by_id(id)
            logger.writeDebug(
                f"PV:get_nvme_subsystem_by_id: nvme_subsystem_data=  {nvme_subsystem}"
            )
            return self.get_details_for_one_nvme(nvme_subsystem)
        except Exception as err:
            logger.writeError(err)
            if isinstance(err.args[0], str) and self.API_MSG in err.args[0]:
                err_msg = VspNvmValidationMsg.FEATURE_NOT_SUPPORTED.value
                logger.writeError(err_msg)
                raise ValueError(err_msg)
            else:
                return None

    @log_entry_exit
    def get_nvme_subsystems_basic(self):
        try:
            nvme_subsystems = self.gateway.get_nvme_subsystems()
            return nvme_subsystems
        except Exception as err:
            # Older storage models do not support nvm subsystem.
            # So catch the exception and send user friendly msg.
            logger.writeError(err)
            if isinstance(err.args[0], str) and self.API_MSG in err.args[0]:
                err_msg = VspNvmValidationMsg.FEATURE_NOT_SUPPORTED.value
                logger.writeError(err_msg)
                raise ValueError(err_msg)

    @log_entry_exit
    def get_nvme_subsystems(self, spec=None):

        nvme_subsystems = None
        try:
            nvme_subsystems = self.gateway.get_nvme_subsystems()
        except Exception as err:
            # Older storage models do not support nvm subsystem.
            # So catch the exception and send user friendly msg.
            logger.writeError(err)
            if isinstance(err.args[0], str) and self.API_MSG in err.args[0]:
                err_msg = VspNvmValidationMsg.FEATURE_NOT_SUPPORTED.value
                logger.writeError(err_msg)
                raise ValueError(err_msg)

        if nvme_subsystems is None:
            err_msg = VspNvmValidationMsg.NO_NVM_SUBSYSTEM_FOUND.value
            logger.writeError(err_msg)
            raise ValueError(err_msg)
        logger.writeDebug(
            f"PV:get_nvme_subsystem: nvme_subsystems_data=  {nvme_subsystems}"
        )
        if not spec:
            consolidated_data = self.get_nvme_details(nvme_subsystems.data)
            logger.writeDebug(
                f"PV:get_nvme_subsystem: consolidated_data=  {consolidated_data}"
            )
            return VspNvmeSubsystemDetailInfoList(data=consolidated_data)
        else:
            ret_nvme = self.apply_filters(nvme_subsystems.data, spec)
            consolidated_data = self.get_nvme_details(ret_nvme)
            return VspNvmeSubsystemDetailInfoList(data=consolidated_data)

    @log_entry_exit
    def get_nvme_subsystems_by_namespace(self):
        nvme_subsystems = self.gateway.get_nvme_subsystems_by_namespace()
        return nvme_subsystems

    @log_entry_exit
    def get_nvme_subsystems_by_nqn(self):
        nvme_subsystems = self.gateway.get_nvme_subsystems_by_nqn()
        return nvme_subsystems

    @log_entry_exit
    def get_nvme_subsystems_by_port(self):
        nvme_subsystems = self.gateway.get_nvme_subsystems_by_port()
        return nvme_subsystems

    @log_entry_exit
    def get_host_nqns(self, nvm_system_id):
        host_nqns = self.gateway.get_host_nqns(nvm_system_id)
        return host_nqns

    @log_entry_exit
    def get_host_nqn(self, host_nqn_id):
        host_nqn = self.gateway.get_host_nqn(host_nqn_id)
        return host_nqn

    @log_entry_exit
    def get_namespaces(self, nvm_system_id):
        namespaces = self.gateway.get_namespaces(nvm_system_id)
        return namespaces

    @log_entry_exit
    def get_namespace_paths(self, nvm_system_id):
        namespace_paths = self.gateway.get_namespace_paths(nvm_system_id)
        return namespace_paths

    @log_entry_exit
    def get_nvme_ports(self, nvm_system_id):
        nvme_ports = self.gateway.get_nvme_ports(nvm_system_id)
        return nvme_ports

    @log_entry_exit
    def register_host_nqn(self, nvm_subsystem_id, host_nqn):
        host_nqn = self.gateway.register_host_nqn(nvm_subsystem_id, host_nqn)
        self.connection_info.changed = True
        return host_nqn

    @log_entry_exit
    def create_namespace(self, nvm_subsystem_id, ldev_id):
        ns_id = self.gateway.create_namespace(nvm_subsystem_id, ldev_id)
        self.connection_info.changed = True
        return ns_id

    @log_entry_exit
    def set_host_namespace_path(self, nvm_subsystem_id, host_nqn, namespace_id):
        host_ns_path_id = self.gateway.set_host_namespace_path(
            nvm_subsystem_id, host_nqn, namespace_id
        )
        self.connection_info.changed = True
        return host_ns_path_id

    @log_entry_exit
    def delete_namespace(self, nvm_subsystem_id, namespace_id):
        ns_data = self.gateway.delete_namespace(nvm_subsystem_id, namespace_id)
        self.connection_info.changed = True
        return ns_data

    @log_entry_exit
    def delete_host_namespace_path(self, nvm_subsystem_id, h_nqn, namespace_id):
        h_ns_path_data = self.gateway.delete_host_namespace_path(
            nvm_subsystem_id, h_nqn, namespace_id
        )
        self.connection_info.changed = True
        return h_ns_path_data

    @log_entry_exit
    def delete_host_namespace_path_by_id(self, id):
        h_ns_path_data = self.gateway.delete_host_namespace_path_by_id(id)
        self.connection_info.changed = True
        return h_ns_path_data

    @log_entry_exit
    def delete_host_nqn(self, nvm_subsystem_id, host_nqn):
        id = f"{nvm_subsystem_id},{host_nqn}"
        h_nqn_data = self.gateway.delete_host_nqn_by_id(id)
        self.connection_info.changed = True
        return h_nqn_data

    @log_entry_exit
    def delete_host_nqn_by_id(self, id):
        h_nqn_data = self.gateway.delete_host_nqn_by_id(id)
        self.connection_info.changed = True
        return h_nqn_data

    @log_entry_exit
    def apply_filters(self, ret_nvme, spec):
        result = ret_nvme
        if spec.name:
            result = self.apply_filter_nvm_subsystem_name(result, spec.name)
        if spec.id:
            result = self.apply_filter_nvme_subsystem_id(result, spec.id)

        return result

    @log_entry_exit
    def apply_filter_nvm_subsystem_name(self, nvme_subsystems, nvm_subsystem_name):
        ret_val = []

        for nvme in nvme_subsystems:
            if nvme.nvmSubsystemName == nvm_subsystem_name:
                ret_val.append(nvme)
        return ret_val

    @log_entry_exit
    def apply_filter_nvme_subsystem_id(self, nvme_subsystems, id):
        ret_val = []

        for nvme in nvme_subsystems:
            if nvme.nvmSubsystemId == id:
                ret_val.append(nvme)
        return ret_val

    @log_entry_exit
    def get_nvme_details(self, nvme_list):

        ret_val = []
        for nvme in nvme_list:
            nvme_detail = self.get_details_for_one_nvme(nvme)
            ret_val.append(nvme_detail)

        return ret_val

    @log_entry_exit
    def get_details_for_one_nvme(self, nvme):
        basic_data = self.get_display_basic(nvme)
        port_data = self.get_display_port_data(nvme.nvmSubsystemId)
        namespaces_data = self.get_display_ns_data(nvme.nvmSubsystemId)
        namespace_paths_data = self.get_display_namespace_paths_data(
            nvme.nvmSubsystemId
        )
        host_nqn_data = self.get_display_host_nqn_data(nvme.nvmSubsystemId)

        nvme_detail = VspNvmeSubsystemDetailInfo(
            basic_data, port_data, namespaces_data, namespace_paths_data, host_nqn_data
        )
        return nvme_detail

    @log_entry_exit
    def get_display_basic(self, nvme):
        nvme_basic = VspNvmeSubsystemDisplay(
            nvme.nvmSubsystemId,
            nvme.nvmSubsystemName,
            nvme.resourceGroupId,
            nvme.namespaceSecuritySetting,
            nvme.t10piMode,
            nvme.hostMode,
        )
        return nvme_basic

    @log_entry_exit
    def get_port_type(self, port_id):
        port_type = self.port_prov.get_port_type(port_id)
        return port_type

    @log_entry_exit
    def get_display_port_data(self, nvm_ss_id):
        display_list = []
        port_data = self.get_nvme_ports(nvm_ss_id)
        for port in port_data.data:
            port_type = self.get_port_type(port.portId)
            display_port = VspNvmePortDisplay(port.portId, port_type)
            display_list.append(display_port)
        return display_list

    @log_entry_exit
    def get_display_host_nqn_data(self, nvm_ss_id):
        display_list = []
        hnqn_data = self.get_host_nqns(nvm_ss_id)
        for hnqn in hnqn_data.data:
            if hnqn.hostNqnNickname == "-":
                host_nick_name = ""
            else:
                host_nick_name = hnqn.hostNqnNickname
            display_hnqn = VspHostNqnDisplay(hnqn.hostNqn, host_nick_name)
            display_list.append(display_hnqn)
        return display_list

    @log_entry_exit
    def get_display_namespace_paths_data(self, nvm_ss_id):
        display_list = []
        nsp_data = self.get_namespace_paths(nvm_ss_id)
        for nsp in nsp_data.data:
            display_hnqn = VspNamespacePathDisplay(
                nsp.hostNqn, nsp.namespaceId, nsp.ldevId
            )
            display_list.append(display_hnqn)
        return display_list

    @log_entry_exit
    def get_display_ns_data(self, nvm_ss_id):
        display_list = []
        ns_data = self.get_namespaces(nvm_ss_id)
        for ns in ns_data.data:
            if ns.namespaceNickname == "-":
                ns_nick_name = ""
            else:
                ns_nick_name = ns.namespaceNickname
            display_ns = VspNamespaceDisplay(
                ns.namespaceId,
                ns_nick_name,
                ns.ldevId,
                ns.byteFormatCapacity,
                ns.blockCapacity,
            )
            display_list.append(display_ns)
        return display_list

    @log_entry_exit
    def create_nvme_subsystem(self, spec):
        if not spec.name:
            spec.name = generate_random_name_prefix_string()
        try:
            ret_value = self.gateway.create_nvme_subsystem(spec)
        except Exception as err:
            logger.writeError(err)
            if VspNvmValidationMsg.NVME_ALREADY_PRESENT.value in str(err):
                spec.name = generate_random_name_prefix_string()
                return self.create_nvme_subsystem(spec)
            else:
                raise err
        return ret_value

    @log_entry_exit
    def delete_nvme_subsystem(self, nvme_subsystem_id):
        ret_value = self.gateway.delete_nvme_subsystem(nvme_subsystem_id)
        return ret_value

    @log_entry_exit
    def update_nvme_subsystem_name(self, nvme_subsystem_id, name):
        ret_value = self.gateway.update_nvme_subsystem_name(nvme_subsystem_id, name)
        return ret_value

    @log_entry_exit
    def update_nvme_subsystem_host_mode(self, nvme_subsystem_id, host_mode):
        ret_value = self.gateway.update_nvme_subsystem_host_mode(
            nvme_subsystem_id, host_mode
        )
        return ret_value

    @log_entry_exit
    def update_nvme_subsystem_host_mode_options(
        self, nvme_subsystem_id, host_mode_options
    ):
        ret_value = self.gateway.update_nvme_subsystem_host_mode_options(
            nvme_subsystem_id, host_mode_options
        )
        return ret_value

    @log_entry_exit
    def update_nvme_subsystem_namespace_security_setting(
        self, nvme_subsystem_id, namespace_security_setting
    ):
        ret_value = self.gateway.update_nvme_subsystem_namespace_security_setting(
            nvme_subsystem_id, namespace_security_setting
        )
        return ret_value

    @log_entry_exit
    def add_nvme_subsystem_port(self, nvme_subsystem_id, port_id):
        ret_value = self.gateway.add_nvme_subsystem_port(nvme_subsystem_id, port_id)
        return ret_value

    @log_entry_exit
    def remove_nvme_subsystem_port(self, nvme_subsystem_id, port_id):
        ret_value = self.gateway.remove_nvme_subsystem_port(nvme_subsystem_id, port_id)
        return ret_value

    @log_entry_exit
    def set_namespace_nickname(self, nvme_subsystem_id, namespace_id, nickname):
        ret_value = self.gateway.set_namespace_nickname(
            nvme_subsystem_id, namespace_id, nickname
        )
        return ret_value

    @log_entry_exit
    def set_host_nqn_nickname(self, nvm_subsystem_id, host_nqn, nickname):
        ret_value = self.gateway.set_host_nqn_nickname(
            nvm_subsystem_id, host_nqn, nickname
        )
        return ret_value
