try:
    from .gateway_manager import VSPConnectionManager
    from ..model.vsp_nvme_models import (
        VspOneServerInfoList,
        VspOneServerInfo,
        VspNvmeSubsystemInfoList,
        VspNvmeSubsystemInfo,
        NvmSubsystemPortList,
        NvmSubsystemPort,
        VspHostNqnInfoList,
        VspHostNqnInfo,
        VspNamespaceInfoList,
        VspNamespaceInfo,
        VspNamespacePathInfoList,
        VspNamespacePathInfo,
        VspNvmePortInfoList,
        VspNvmePortInfo,
        NvmSubsystemById,
    )
    from ..common.ansible_common import dicts_to_dataclass_list
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
except ImportError:
    from .gateway_manager import VSPConnectionManager
    from model.vsp_nvme_models import (
        VspOneServerInfoList,
        VspOneServerInfo,
        VspNvmeSubsystemInfoList,
        VspNvmeSubsystemInfo,
        NvmSubsystemPortList,
        NvmSubsystemPort,
        VspHostNqnInfoList,
        VspHostNqnInfo,
        VspNamespaceInfoList,
        VspNamespaceInfo,
        VspNamespacePathInfoList,
        VspNamespacePathInfo,
        VspNvmePortInfoList,
        VspNvmePortInfo,
        NvmSubsystemById,
    )
    from common.ansible_common import dicts_to_dataclass_list
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit


GET_SERVERS = "simple/v1/objects/servers"
GET_NVME_SUBSYSTEMS = "v1/objects/nvm-subsystems"
GET_NVME_SUBSYSTEM_BY_NQN = "v1/objects/nvm-subsystems?nvmSubsystemInfo=nqn"
GET_NVME_SUBSYSTEM_BY_NAMESPACE = "v1/objects/nvm-subsystems?nvmSubsystemInfo=namespace"
GET_NVME_SUBSYSTEM_BY_PORT = "v1/objects/nvm-subsystems?nvmSubsystemInfo=port"
GET_NVME_SUBSYSTEM_BY_ID = "v1/objects/nvm-subsystems/{}"

GET_HOST_NQNS = "v1/objects/host-nqns?nvmSubsystemId={}"
GET_HOST_NQN = "v1/objects/host-nqns/{}"
POST_HOST_NQN = "v1/objects/host-nqns"
GET_NAMESPACES = "v1/objects/namespaces?nvmSubsystemId={}"
GET_NAMESPACE_PATH = "v1/objects/namespace-paths?nvmSubsystemId={}"
GET_NVME_ALL_PORTS = "v1/objects/nvm-subsystem-ports"
GET_NVME_PORTS = "v1/objects/nvm-subsystem-ports?nvmSubsystemId={}"
POST_NAMESPACE = "v1/objects/namespaces"
POST_HOST_NAMESPACE_PATH = "v1/objects/namespace-paths"

DELETE_NAMESPACE = "v1/objects/namespaces/{},{}"
DELETE_HOST_NAMESPACE_PATH = "v1/objects/namespace-paths/{},{},{}"
DELETE_HOST_NAMESPACE_PATH_BY_ID = "v1/objects/namespace-paths/{}"
DELETE_HOST_NQN = "v1/objects/host-nqns/{},{}"
DELETE_HOST_NQN_BY_ID = "v1/objects/host-nqns/{}"

CREATE_NVM_SUBSYSTEM = "v1/objects/nvm-subsystems"
DELETE_NVM_SUBSYSTEM = "v1/objects/nvm-subsystems/{}"
UPDATE_NVM_SUBSYSTEM = "v1/objects/nvm-subsystems/{}"
ADD_PORT_TO_NVM_SUBSYSTEM = "v1/objects/nvm-subsystem-ports"
REMOVE_PORT_FROM_NVM_SUBSYSTEM = "v1/objects/nvm-subsystem-ports/{},{}"
SET_NAMESPACE_NICKNAME = "v1/objects/namespaces/{},{}"
SET_HOST_NQN_NICKNAME = "v1/objects/host-nqns/{},{}"


logger = Log()

NVM_HOST_MODE_MAP = {
    "linux": "LINUX/IRIX",
    "linux/irix": "LINUX/IRIX",
    "vmware": "VMWARE",
    "vmware_ex": "VMWARE_EX",
    "aix": "AIX",
}


class VSPOneNvmeSubsystemDirectGateway:

    def __init__(self, connection_info):
        self.connection_manager = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )

    @log_entry_exit
    def get_servers(self, spec=None):

        # org_base_url = self.connection_manager.get_base_url()
        # self.connection_manager.set_base_url_for_vsp_one_server()

        end_point = GET_SERVERS
        server_data = self.connection_manager.get(end_point)

        servers = VspOneServerInfoList(
            dicts_to_dataclass_list(server_data["data"], VspOneServerInfo)
        )

        # self.connection_manager.set_base_url(org_base_url)
        count = server_data["count"]

        logger.writeDebug("GW:get_servers:data={} count = {}", servers, count)

        if len(servers.data) != count:
            # if this is for pagination handle it later
            raise ValueError(
                "Something wrong! Number of servers returned and count did not match!"
            )
        else:
            return servers

    @log_entry_exit
    def get_nvme_subsystems(self):

        end_point = GET_NVME_SUBSYSTEMS
        nvme_data = self.connection_manager.get(end_point)

        nvme_subsystems = VspNvmeSubsystemInfoList(
            dicts_to_dataclass_list(nvme_data["data"], VspNvmeSubsystemInfo)
        )

        return nvme_subsystems

    @log_entry_exit
    def get_nvme_subsystems_by_nqn(self):

        end_point = GET_NVME_SUBSYSTEM_BY_NQN
        nvme_data = self.connection_manager.get(end_point)
        nvme_subsystems = VspNvmeSubsystemInfoList(
            dicts_to_dataclass_list(nvme_data["data"], VspNvmeSubsystemInfo)
        )
        return nvme_subsystems

    @log_entry_exit
    def get_nvme_subsystems_by_namespace(self):

        end_point = GET_NVME_SUBSYSTEM_BY_NAMESPACE
        nvme_data = self.connection_manager.get(end_point)
        nvme_subsystems = VspNvmeSubsystemInfoList(
            dicts_to_dataclass_list(nvme_data["data"], VspNvmeSubsystemInfo)
        )
        return nvme_subsystems

    @log_entry_exit
    def get_nvme_subsystems_by_port(self):

        end_point = GET_NVME_SUBSYSTEM_BY_PORT
        nvme_data = self.connection_manager.get(end_point)
        nvme_subsystems = NvmSubsystemPortList(
            dicts_to_dataclass_list(nvme_data["data"], NvmSubsystemPort)
        )
        return nvme_subsystems

    @log_entry_exit
    def get_nvme_subsystem_by_id(self, id):

        end_point = GET_NVME_SUBSYSTEM_BY_ID.format(id)
        nvme_data = self.connection_manager.get(end_point)

        # nvme_subsystems = VspNvmeSubsystemInfoList(
        #     dicts_to_dataclass_list(nvme_data["data"], VspNvmeSubsystemInfo)
        # )

        return NvmSubsystemById(**nvme_data)

    @log_entry_exit
    def get_host_nqns(self, nvm_system_id):

        end_point = GET_HOST_NQNS.format(nvm_system_id)
        host_nqn_data = self.connection_manager.get(end_point)

        host_nqn = VspHostNqnInfoList(
            dicts_to_dataclass_list(host_nqn_data["data"], VspHostNqnInfo)
        )
        return host_nqn

    @log_entry_exit
    def get_namespaces(self, nvm_system_id):

        end_point = GET_NAMESPACES.format(nvm_system_id)
        namespaces_data = self.connection_manager.get(end_point)

        namespaces = VspNamespaceInfoList(
            dicts_to_dataclass_list(namespaces_data["data"], VspNamespaceInfo)
        )

        return namespaces

    @log_entry_exit
    def get_namespace_paths(self, nvm_system_id):

        end_point = GET_NAMESPACE_PATH.format(nvm_system_id)
        namespace_paths_data = self.connection_manager.get(end_point)

        namespace_paths = VspNamespacePathInfoList(
            dicts_to_dataclass_list(namespace_paths_data["data"], VspNamespacePathInfo)
        )

        return namespace_paths

    @log_entry_exit
    def get_nvme_ports(self, nvm_system_id):

        end_point = GET_NVME_PORTS.format(nvm_system_id)
        nvme_ports_data = self.connection_manager.get(end_point)

        nvme_ports = VspNvmePortInfoList(
            dicts_to_dataclass_list(nvme_ports_data["data"], VspNvmePortInfo)
        )

        return nvme_ports

    @log_entry_exit
    def get_host_nqn(self, host_nqn_id):

        end_point = GET_HOST_NQN.format(host_nqn_id)
        host_nqn_data = self.connection_manager.get(end_point)

        host_nqn = VspHostNqnInfo(**host_nqn_data)
        return host_nqn

    @log_entry_exit
    def register_host_nqn(self, nvm_subsystem_id, host_nqn):

        end_point = POST_HOST_NQN
        payload = {
            "nvmSubsystemId": nvm_subsystem_id,
            "hostNqn": host_nqn,
        }
        host_nqn_data = self.connection_manager.post(end_point, payload)

        return host_nqn_data

    @log_entry_exit
    def create_namespace(self, nvm_subsystem_id, ldev_id, ns_id=None):
        end_point = POST_NAMESPACE
        payload = {}
        if ns_id is not None:
            payload = {
                "nvmSubsystemId": nvm_subsystem_id,
                "ldevId": int(ldev_id),
                "namespaceId": int(ns_id),
            }
        else:
            payload = {
                "nvmSubsystemId": nvm_subsystem_id,
                "ldevId": int(ldev_id),
            }
        ns_data = self.connection_manager.post(end_point, payload)
        return ns_data

    @log_entry_exit
    def set_host_namespace_path(self, nvm_subsystem_id, host_nqn, namespace_id):
        end_point = POST_HOST_NAMESPACE_PATH
        payload = {
            "nvmSubsystemId": nvm_subsystem_id,
            "hostNqn": host_nqn,
            "namespaceId": namespace_id,
        }
        host_ns_path_data = self.connection_manager.post(end_point, payload)
        return host_ns_path_data

    @log_entry_exit
    def delete_namespace(self, nvm_subsystem_id, namespace_id):
        end_point = DELETE_NAMESPACE.format(nvm_subsystem_id, namespace_id)
        ns_data = self.connection_manager.delete(end_point)
        return ns_data

    @log_entry_exit
    def delete_host_namespace_path(self, nvm_subsystem_id, h_nqn, namespace_id):
        end_point = DELETE_HOST_NAMESPACE_PATH.format(
            nvm_subsystem_id, h_nqn, namespace_id
        )
        ns_data = self.connection_manager.delete(end_point)
        return ns_data

    @log_entry_exit
    def delete_host_namespace_path_by_id(self, id):
        end_point = DELETE_HOST_NAMESPACE_PATH_BY_ID.format(id)
        ns_data = self.connection_manager.delete(end_point)
        return ns_data

    @log_entry_exit
    def delete_host_nqn(self, nvm_subsystem_id, host_nqn):
        end_point = DELETE_HOST_NQN.format(nvm_subsystem_id, host_nqn)
        ns_data = self.connection_manager.delete(end_point)
        return ns_data

    @log_entry_exit
    def delete_host_nqn_by_id(self, id):
        end_point = DELETE_HOST_NQN_BY_ID.format(id)
        ns_data = self.connection_manager.delete(end_point)
        return ns_data

    @log_entry_exit
    def create_nvme_subsystem(self, spec):

        end_point = CREATE_NVM_SUBSYSTEM
        nvm_ss_id = spec.id
        payload = {
            "nvmSubsystemId": nvm_ss_id,
        }
        if spec.name:
            payload["nvmSubsystemName"] = spec.name

        if spec.host_mode:
            nvm_host_mode = NVM_HOST_MODE_MAP[spec.host_mode.lower()]
            payload["hostMode"] = nvm_host_mode

        # if spec.host_mode_options:
        #     # validate hostModeOptions somewhere
        #     payload["hostModeOptions"] =  spec.host_mode_options

        if spec.enable_namespace_security is not None:
            # Default is Enable, we send Disable only when this is False
            if spec.enable_namespace_security is False:
                payload["namespaceSecuritySetting"] = "Disable"

        ns_data = self.connection_manager.post(end_point, payload)
        return ns_data

    @log_entry_exit
    def delete_nvme_subsystem(self, id):
        end_point = DELETE_NVM_SUBSYSTEM.format(id)
        ns_data = self.connection_manager.delete(end_point)
        return ns_data

    @log_entry_exit
    def update_nvme_subsystem_name(self, id, value):

        end_point = UPDATE_NVM_SUBSYSTEM.format(id)
        payload = {
            "nvmSubsystemName": value,
        }
        ns_data = self.connection_manager.patch(end_point, payload)
        return ns_data

    @log_entry_exit
    def update_nvme_subsystem_host_mode(self, id, value):

        end_point = UPDATE_NVM_SUBSYSTEM.format(id)
        payload = {"hostMode": NVM_HOST_MODE_MAP[value.lower()]}
        ns_data = self.connection_manager.patch(end_point, payload)
        return ns_data

    @log_entry_exit
    def update_nvme_subsystem_host_mode_options(self, id, value):

        end_point = UPDATE_NVM_SUBSYSTEM.format(id)
        payload = {"hostModeOptions": value}
        ns_data = self.connection_manager.patch(end_point, payload)
        return ns_data

    @log_entry_exit
    def update_nvme_subsystem_namespace_security_setting(self, id, value):

        end_point = UPDATE_NVM_SUBSYSTEM.format(id)
        payload = {"namespaceSecuritySetting": value}
        ns_data = self.connection_manager.patch(end_point, payload)
        return ns_data

    @log_entry_exit
    def add_nvme_subsystem_port(self, id, port_id):

        end_point = ADD_PORT_TO_NVM_SUBSYSTEM
        payload = {
            "nvmSubsystemId": id,
            "portId": port_id,
        }
        ns_data = self.connection_manager.post(end_point, payload)
        return ns_data

    @log_entry_exit
    def remove_nvme_subsystem_port(self, id, port_id):
        end_point = REMOVE_PORT_FROM_NVM_SUBSYSTEM.format(id, port_id)
        ns_data = self.connection_manager.delete(end_point)
        return ns_data

    @log_entry_exit
    def set_namespace_nickname(self, nvme_subsystem_id, namespace_id, nickname):

        end_point = SET_NAMESPACE_NICKNAME.format(nvme_subsystem_id, namespace_id)
        payload = {
            "namespaceNickname": nickname,
        }
        ns_data = self.connection_manager.patch(end_point, payload)
        return ns_data

    @log_entry_exit
    def set_host_nqn_nickname(self, nvme_subsystem_id, host_nqn, nickname):

        end_point = SET_HOST_NQN_NICKNAME.format(nvme_subsystem_id, host_nqn)
        payload = {
            "hostNqnNickname": nickname,
        }
        nqn_data = self.connection_manager.patch(end_point, payload)
        return nqn_data
