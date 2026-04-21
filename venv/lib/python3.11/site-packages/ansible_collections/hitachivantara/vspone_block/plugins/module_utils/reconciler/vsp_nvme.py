try:
    from ..common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        volume_id_to_hex_format,
        get_default_value,
        convert_to_mb,
    )
    from ..common.vsp_constants import AutomationConstants
    from ..common.hv_log import Log
    from ..common.hv_constants import StateValue
    from ..provisioner.vsp_nvme_provisioner import VSPNvmeProvisioner
    from ..provisioner.vsp_storage_port_provisioner import VSPStoragePortProvisioner
    from ..provisioner.vsp_host_group_provisioner import VSPHostGroupProvisioner
    from ..gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from ..message.vsp_nvm_msgs import VspNvmValidationMsg


except ImportError:
    from common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        volume_id_to_hex_format,
        get_default_value,
        convert_to_mb,
    )
    from common.vsp_constants import AutomationConstants
    from common.hv_log import Log
    from common.hv_constants import StateValue
    from provisioner.vsp_nvme_provisioner import VSPNvmeProvisioner
    from provisioner.vsp_storage_port_provisioner import VSPStoragePortProvisioner
    from provisioner.vsp_host_group_provisioner import VSPHostGroupProvisioner
    from gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from message.vsp_nvm_msgs import VspNvmValidationMsg


logger = Log()


class VSPNvmSubsystemSubstates:
    """
    Enum class for VSP NVM Subsystem Substates
    """

    ADD_PORT = "add_port"
    REMOVE_PORT = "remove_port"
    ADD_HOST_NQN = "add_host_nqn"
    REMOVE_HOST_NQN = "remove_host_nqn"
    ADD_NAMESPACE = "add_namespace"
    REMOVE_NAMESPACE = "remove_namespace"
    ADD_NAMESPACE_PATH = "add_namespace_path"
    REMOVE_NAMESPACE_PATH = "remove_namespace_path"


class VSPNvmeReconciler:
    def __init__(self, connection_info, serial=None, state=None):

        self.connection_info = connection_info

        self.provisioner = VSPNvmeProvisioner(connection_info, serial)
        self.port_prov = VSPStoragePortProvisioner(self.connection_info)
        self.hg_provisioner = VSPHostGroupProvisioner(self.connection_info)
        self.storage_serial_number = serial
        if self.storage_serial_number is None:
            self.storage_serial_number = self.get_storage_serial_number()
        if state:
            self.state = state

    @log_entry_exit
    def reconcile_nvm_subsystem(self, spec):
        """Reconciler for nvm subsystem management"""

        if self.state == StateValue.PRESENT:
            nvme_subsystem = None
            if spec.id:
                nvme_subsystem = self.provisioner.get_nvme_subsystem_by_id(spec.id)
            else:
                if spec.name:
                    nvme_subsystem = self.provisioner.get_nvme_subsystem_by_name(
                        spec.name
                    )

            if not nvme_subsystem:
                if (spec.id or spec.name) and spec.state:
                    if (
                        spec.state.lower() == VSPNvmSubsystemSubstates.REMOVE_PORT
                        or spec.state.lower()
                        == VSPNvmSubsystemSubstates.REMOVE_HOST_NQN
                        or spec.state.lower()
                        == VSPNvmSubsystemSubstates.REMOVE_NAMESPACE
                        or spec.state.lower()
                        == VSPNvmSubsystemSubstates.REMOVE_NAMESPACE_PATH
                    ):
                        raise ValueError(
                            VspNvmValidationMsg.NVM_SUBSYSTEM_NOT_FOUND.value
                        )
                spec.id = self.create_nvme_subsystem(spec)
            else:
                spec.id = nvme_subsystem.nvmSubsystemId
                self.update_nvme_subsystem(nvme_subsystem, spec)

            nvme_ss = self.provisioner.get_nvme_subsystem_details_by_id(spec.id)
            logger.writeDebug("RC:reconcile_nvm_subsystem:nvme_ss={}", nvme_ss)
            extracted_data = NvmeSubsystemDetailInfoExtractor(
                self.storage_serial_number
            ).extract([nvme_ss.to_dict()])
            return extracted_data
            # return nvme_ss

        elif self.state == StateValue.ABSENT:
            if spec.id:
                nvme_subsystem = self.provisioner.get_nvme_subsystem_by_id(spec.id)
            else:
                if spec.name:
                    nvme_subsystem = self.provisioner.get_nvme_subsystem_by_name(
                        spec.name
                    )
            if not nvme_subsystem:
                return "NVM Subsystem not found."
            logger.writeDebug(
                "RC:reconcile_nvm_subsystem:state=absent:nvme_subsystem={}",
                nvme_subsystem,
            )

            if spec.force and spec.force is True:
                return self.delete_nvme_subsystem_force(nvme_subsystem)
            else:
                return self.delete_nvme_subsystem(nvme_subsystem)

    @log_entry_exit
    def get_storage_serial_number(self):
        storage_gw = VSPStorageSystemDirectGateway(self.connection_info)
        storage_system = storage_gw.get_current_storage_system_info()
        return storage_system.serialNumber

    @log_entry_exit
    def update_nvme_subsystem(self, nvme_subsystem, spec):

        ret_value = None
        if spec.name and nvme_subsystem.nvmSubsystemName != spec.name:
            ret_value = self.provisioner.update_nvme_subsystem_name(
                nvme_subsystem.nvmSubsystemId, spec.name
            )
            self.connection_info.changed = True
        if spec.host_mode and nvme_subsystem.hostMode != spec.host_mode:
            ret_value = self.provisioner.update_nvme_subsystem_host_mode(
                nvme_subsystem.nvmSubsystemId, spec.host_mode
            )
            self.connection_info.changed = True
        # if spec.host_mode_options and nvme_subsystem.hostModeOptions != spec.host_mode_options:
        #     ret_value = self.provisioner.update_nvme_subsystem_host_mode_options(nvme_subsystem.nvmSubsystemId, spec.host_mode_options)
        #     self.connection_info.changed = True
        if spec.enable_namespace_security:
            if (
                spec.enable_namespace_security is True
                and nvme_subsystem.namespaceSecuritySetting == "Disable"
            ):
                ret_value = (
                    self.provisioner.update_nvme_subsystem_namespace_security_setting(
                        nvme_subsystem.nvmSubsystemId, "Enable"
                    )
                )
                self.connection_info.changed = True
            if (
                spec.enable_namespace_security is False
                and nvme_subsystem.namespaceSecuritySetting == "Enable"
            ):
                ret_value = (
                    self.provisioner.update_nvme_subsystem_namespace_security_setting(
                        nvme_subsystem.nvmSubsystemId, "Disable"
                    )
                )
                self.connection_info.changed = True

        if (
            spec.state is None
            or spec.state.lower() == VSPNvmSubsystemSubstates.ADD_PORT
        ):
            if spec.ports:
                self.add_nvme_ports(nvme_subsystem.nvmSubsystemId, spec.ports)

        if spec.state and spec.state.lower() == VSPNvmSubsystemSubstates.REMOVE_PORT:
            if spec.ports:
                self.remove_nvme_ports(nvme_subsystem.nvmSubsystemId, spec.ports)

        if (
            spec.state is None
            or spec.state.lower() == VSPNvmSubsystemSubstates.ADD_HOST_NQN
        ):
            if spec.host_nqns:
                self.add_host_nqns(nvme_subsystem.nvmSubsystemId, spec.host_nqns)

        if (
            spec.state
            and spec.state.lower() == VSPNvmSubsystemSubstates.REMOVE_HOST_NQN
        ):
            if spec.host_nqns:
                if spec.force and spec.force is True:
                    self.remove_host_nqns_force(
                        nvme_subsystem.nvmSubsystemId, spec.host_nqns
                    )
                else:
                    self.remove_host_nqns(nvme_subsystem.nvmSubsystemId, spec.host_nqns)

        if (
            spec.state is None
            or spec.state.lower() == VSPNvmSubsystemSubstates.ADD_NAMESPACE
        ):
            if spec.namespaces:
                self.add_namespaces(nvme_subsystem.nvmSubsystemId, spec.namespaces)

        if (
            spec.state
            and spec.state.lower() == VSPNvmSubsystemSubstates.REMOVE_NAMESPACE
        ):
            if spec.namespaces:
                if spec.force and spec.force is True:
                    logger.writeDebug(f"RC:remove_namespaces_force_called={spec}")
                    self.remove_namespaces_force(
                        nvme_subsystem.nvmSubsystemId, spec.namespaces
                    )
                else:
                    logger.writeDebug(f"RC:remove_namespaces_called={spec}")
                    self.remove_namespaces(
                        nvme_subsystem.nvmSubsystemId, spec.namespaces
                    )

        if (
            spec.state is None
            or spec.state.lower() == VSPNvmSubsystemSubstates.ADD_NAMESPACE_PATH
        ):
            if spec.namespaces:
                self.add_namespace_paths(nvme_subsystem.nvmSubsystemId, spec.namespaces)

        if (
            spec.state
            and spec.state.lower() == VSPNvmSubsystemSubstates.REMOVE_NAMESPACE_PATH
        ):
            if spec.namespaces:
                self.remove_namespace_paths(
                    nvme_subsystem.nvmSubsystemId, spec.namespaces
                )
        return

    @log_entry_exit
    def add_namespace_paths(self, nvme_subsystem_id, namespaces):
        self.add_namespaces(nvme_subsystem_id, namespaces)
        # for ns in namespaces:
        #     for path in ns.paths:
        #         self.provisioner.set_host_namespace_path(nvme_subsystem_id, path, ns.namespace_id)
        #         self.connection_info.changed = True
        return

    @log_entry_exit
    def remove_namespace_paths(self, nvme_subsystem_id, namespaces):
        for ns in namespaces:
            ldev_paths = self.find_ldevs_in_paths(nvme_subsystem_id, ns.ldev_id)
            if ldev_paths and len(ldev_paths) > 0:
                for x in ldev_paths:
                    logger.writeDebug(
                        f"RC:remove_namespace_paths:x={x} ns.paths={ns.paths}"
                    )
                    if x.hostNqn in ns.paths:
                        logger.writeDebug(
                            f"RC:remove_namespace_paths:IN x={x} ns.paths={ns.paths}"
                        )
                        self.provisioner.delete_host_namespace_path_by_id(
                            x.namespacePathId
                        )
                        self.connection_info.changed = True
        return

    @log_entry_exit
    def remove_namespace_path_force(self, nvme_subsystem_id, ldev_id):

        ldev_paths = self.find_ldevs_in_paths(nvme_subsystem_id, ldev_id)
        if ldev_paths and len(ldev_paths) > 0:
            for x in ldev_paths:
                self.provisioner.delete_host_namespace_path_by_id(x.namespacePathId)
                self.connection_info.changed = True
        return

    @log_entry_exit
    def find_ldevs_in_paths(self, nvm_subsystem_id, ldev_id):
        ldevs = []
        paths = self.provisioner.get_namespace_paths(nvm_subsystem_id)
        for path in paths.data:
            logger.writeDebug(
                f"RC:find_ldevs_in_paths:path.ldevId={path.ldevId} ldev_id={ldev_id}"
            )
            if str(path.ldevId) == str(ldev_id):
                ldevs.append(path)
        return ldevs

    @log_entry_exit
    def find_host_nqn_in_paths(self, nvm_subsystem_id, host_nqn):
        hnqns = []
        paths = self.provisioner.get_namespace_paths(nvm_subsystem_id)
        for path in paths.data:
            logger.writeDebug(
                f"RC:find_host_nqn_in_paths:path.hostNqn={path.hostNqn} ldev_id={host_nqn}"
            )
            if str(path.hostNqn) == str(host_nqn):
                hnqns.append(path)
        return hnqns

    @log_entry_exit
    def remove_host_nqns_force(self, nvme_subsystem_id, host_nqns):
        for x in host_nqns:
            self.remove_host_nqn_force(nvme_subsystem_id, x.nqn)
            self.connection_info.changed = True

    @log_entry_exit
    def remove_host_nqn_force(self, nvme_subsystem_id, host_nqn):
        hnqn_paths = self.find_host_nqn_in_paths(nvme_subsystem_id, host_nqn)
        if hnqn_paths and len(hnqn_paths) > 0:
            for x in hnqn_paths:
                self.provisioner.delete_host_namespace_path_by_id(x.namespacePathId)
                self.connection_info.changed = True
        logger.writeDebug("RC:remove_host_nqnq_force={}", host_nqn)
        self.provisioner.delete_host_nqn(nvme_subsystem_id, host_nqn)
        self.connection_info.changed = True

    @log_entry_exit
    def remove_namespaces_force(self, nvme_subsystem_id, namespaces):
        for x in namespaces:
            self.remove_namespace_force(nvme_subsystem_id, x)
            self.connection_info.changed = True

    @log_entry_exit
    def remove_namespace_force(self, nvme_subsystem_id, namespace):
        logger.writeDebug("RC:remove_namespaces={}", namespace)
        self.remove_namespace_path_force(nvme_subsystem_id, namespace.ldev_id)
        self.remove_namespace(nvme_subsystem_id, namespace)
        self.connection_info.changed = True

    @log_entry_exit
    def remove_namespaces(self, nvme_subsystem_id, namespaces):
        logger.writeDebug("RC:remove_namespaces={}", namespaces)
        for x in namespaces:
            self.remove_namespace(nvme_subsystem_id, x)
            self.connection_info.changed = True

    @log_entry_exit
    def remove_namespace(self, nvme_subsystem_id, namespace):
        logger.writeDebug("RC:remove_namespace:spec={}", namespace)
        ns = self.is_ldev_present(nvme_subsystem_id, namespace.ldev_id)
        logger.writeDebug("RC:remove_namespace:actual={}", ns)
        if ns:
            self.provisioner.delete_namespace(nvme_subsystem_id, ns.namespaceId)
            self.connection_info.changed = True

    @log_entry_exit
    def remove_host_nqns(self, nvme_subsystem_id, host_nqns):
        logger.writeDebug("RC:remove_host_nqns={}", host_nqns)
        for x in host_nqns:
            self.provisioner.delete_host_nqn(nvme_subsystem_id, x.nqn)
            self.connection_info.changed = True

    @log_entry_exit
    def add_host_nqns(self, nvme_subsystem_id, host_nqns):
        logger.writeDebug("RC:add_host_nqns={}", host_nqns)
        for x in host_nqns:
            self.provisioner.register_host_nqn(nvme_subsystem_id, x.nqn)
            if x.nickname:
                self.provisioner.set_host_nqn_nickname(
                    nvme_subsystem_id, x.nqn, x.nickname
                )
            self.connection_info.changed = True

    @log_entry_exit
    def create_nvme_subsystem(self, spec):
        if spec.state:
            if (
                spec.state.lower() == VSPNvmSubsystemSubstates.REMOVE_PORT
                or spec.state.lower() == VSPNvmSubsystemSubstates.REMOVE_HOST_NQN
                or spec.state.lower() == VSPNvmSubsystemSubstates.REMOVE_NAMESPACE
                or spec.state.lower() == VSPNvmSubsystemSubstates.REMOVE_NAMESPACE_PATH
            ):

                raise ValueError(VspNvmValidationMsg.CONTRADICT_INFO.value)

        if spec.id is None:
            next_free_id = self.get_next_free_id()
            spec.id = next_free_id

        nvm_subsystem_id = self.provisioner.create_nvme_subsystem(spec)
        logger.writeDebug("RC:create_nvme_subsystem:ret_value={}", nvm_subsystem_id)
        self.connection_info.changed = True

        if (
            spec.state is None
            or spec.state.lower() == VSPNvmSubsystemSubstates.ADD_PORT
        ):
            if spec.ports:
                self.add_nvme_ports(nvm_subsystem_id, spec.ports)

        if (
            spec.state is None
            or spec.state.lower() == VSPNvmSubsystemSubstates.ADD_HOST_NQN
        ):
            if spec.host_nqns:
                self.add_host_nqns(nvm_subsystem_id, spec.host_nqns)

        if (
            spec.state is None
            or spec.state.lower() == VSPNvmSubsystemSubstates.ADD_NAMESPACE
            or spec.state.lower() == VSPNvmSubsystemSubstates.ADD_NAMESPACE_PATH
        ):
            if spec.namespaces:
                self.add_namespaces(nvm_subsystem_id, spec.namespaces)

        return nvm_subsystem_id

    @log_entry_exit
    def get_next_free_id(self):
        nvme_subsystems = self.provisioner.get_nvme_subsystems_basic()
        logger.writeDebug("RC:get_next_free_id:nvme_subsystems={}", nvme_subsystems)
        if nvme_subsystems:
            index = 0
            for x in nvme_subsystems.data:
                logger.writeDebug(
                    f"RC:get_next_free_id:index={index} id= {x.nvmSubsystemId}"
                )
                if x.nvmSubsystemId == index:
                    index = index + 1
                else:
                    if index <= AutomationConstants.NVM_SUBSYSTEM_MAX_ID:
                        return index
                    else:
                        raise ValueError(VspNvmValidationMsg.NO_NVM_ID_LEFT.value)
        return AutomationConstants.NVM_SUBSYSTEM_MIN_ID

    @log_entry_exit
    def add_namespaces(self, nvme_subsystem_id, namespaces):
        for ns in namespaces:
            ldev_id = ns.ldev_id
            ldev_found = self.is_ldev_present(nvme_subsystem_id, ldev_id)
            if not ldev_found:
                try:
                    object_id = self.provisioner.create_namespace(
                        nvme_subsystem_id, ldev_id
                    )
                    self.connection_info.changed = True
                    ns_id = object_id.split(",")[-1]
                except Exception as e:
                    logger.writeError("RC:add_namespaces:Exception={}", str(e))
                    if VspNvmValidationMsg.NAMESPACE_CREATION_FAILED.value in str(e):
                        raise ValueError(
                            VspNvmValidationMsg.NAMESPACE_CREATION_FAILED.value
                        )
                    else:
                        raise e
            else:
                ns_id = ldev_found.namespaceId

            if ns.nickname:
                if ldev_found:
                    if ldev_found.namespaceNickname != ns.nickname:
                        self.provisioner.set_namespace_nickname(
                            nvme_subsystem_id, ns_id, ns.nickname
                        )
                        self.connection_info.changed = True
                else:
                    self.provisioner.set_namespace_nickname(
                        nvme_subsystem_id, ns_id, ns.nickname
                    )
                    self.connection_info.changed = True
            if ns.paths:
                for path in ns.paths:
                    self.provisioner.set_host_namespace_path(
                        nvme_subsystem_id, path, ns_id
                    )
                    self.connection_info.changed = True

        return

    @log_entry_exit
    def is_ldev_present(self, nvme_subsystem_id, ldev_id):
        ret_list = self.provisioner.get_namespaces(nvme_subsystem_id)
        logger.writeDebug("RC:is_ldev_present={}", ret_list)
        for x in ret_list.data:
            if str(x.ldevId) == str(ldev_id):
                return x
        return False

    @log_entry_exit
    def add_nvme_ports(self, nvme_subsystem_id, ports):
        for port in ports:
            port_info = self.port_prov.get_single_storage_port(port)
            if port_info:
                ret_value = self.can_this_port_be_added_to_nvme_subsystem(port_info)
                logger.writeDebug("RC:add_nvme_ports:port_info={}", port_info)
                if ret_value:
                    self.provisioner.add_nvme_subsystem_port(nvme_subsystem_id, port)
                    self.connection_info.changed = True
                else:
                    logger.writeDebug(
                        "Port {} can't be added to NVM subsystem.", port_info.portId
                    )
        return

    @log_entry_exit
    def can_this_port_be_added_to_nvme_subsystem(self, port_info):
        if port_info.portType == "NVME_TCP":
            return True
        if port_info.portType == "FIBRE" and port_info.portMode == "FC-NVMe":
            return True
        if port_info.portType == "FIBRE" and port_info.portMode == "FCP-SCSI":
            hgs = self.hg_provisioner.get_host_groups(ports_input=[port_info.portId])
            logger.writeDebug(
                "RC:can_this_port_be_added_to_nvme_subsystem:Port = {} hgs = {}.",
                port_info.portId,
                hgs,
            )
            change_port_settings = False
            if hgs.data:
                if len(hgs.data) > 1:
                    raise ValueError(
                        VspNvmValidationMsg.FC_PORT_HAS_HOST_GROUPS.value.format(
                            port_info.portId
                        )
                    )
                elif len(hgs.data) == 1:
                    if hgs.data[0].hostGroupId != 0:
                        raise ValueError(
                            VspNvmValidationMsg.FC_PORT_HAS_HOST_GROUPS.value.format(
                                port_info.portId
                            )
                        )
                    else:
                        change_port_settings = True
                else:
                    change_port_settings = True
            else:
                change_port_settings = True

            if change_port_settings:
                try:
                    self.port_prov.change_port_settings(
                        port_info.portId, "FC-NVMe", None
                    )
                    return True
                except Exception as e:
                    logger.writeError(
                        "RC:can_this_port_be_added_to_nvme_subsystem:Exception={}", e
                    )
                    raise ValueError(
                        VspNvmValidationMsg.CHANGE_PORT_MODE_TO_NVME_FAILED.value.format(
                            port_info.portId
                        )
                    )
        return False

    @log_entry_exit
    def remove_nvme_ports(self, nvme_subsystem_id, ports):
        for port in ports:
            self.provisioner.remove_nvme_subsystem_port(nvme_subsystem_id, port)
            self.connection_info.changed = True
        return

    @log_entry_exit
    def delete_nvme_subsystem(self, nvme_subsystem):
        ret_value = self.provisioner.delete_nvme_subsystem(
            nvme_subsystem.nvmSubsystemId
        )
        self.connection_info.changed = True
        logger.writeDebug("RC:delete_nvme_subsystem:ret_value={}", ret_value)
        return "NVM Subsystem deleted successfully."

    @log_entry_exit
    def delete_nvme_subsystem_force(self, nvme_subsystem):
        self.remove_all_namespace_paths(nvme_subsystem.nvmSubsystemId)
        self.remove_all_namespaces(nvme_subsystem.nvmSubsystemId)
        ret_value = self.provisioner.delete_nvme_subsystem(
            nvme_subsystem.nvmSubsystemId
        )
        self.connection_info.changed = True
        logger.writeDebug("RC:delete_nvme_subsystem:ret_value={}", ret_value)
        return "NVM Subsystem deleted successfully."

    @log_entry_exit
    def remove_all_namespace_paths(self, nvme_subsystem_id):
        namespace_paths = self.provisioner.get_namespace_paths(nvme_subsystem_id)
        for path in namespace_paths.data:
            self.provisioner.delete_host_namespace_path_by_id(path.namespacePathId)
            self.connection_info.changed = True
        return

    @log_entry_exit
    def remove_all_namespaces(self, nvme_subsystem_id):
        namespaces = self.provisioner.get_namespaces(nvme_subsystem_id)
        for ns in namespaces.data:
            self.provisioner.delete_namespace(nvme_subsystem_id, ns.namespaceId)
            self.connection_info.changed = True
        return

    @log_entry_exit
    def get_nvme_subsystem_facts(self, spec):
        nvme_subsystems = self.provisioner.get_nvme_subsystems(spec)
        logger.writeDebug("RC:nvme_subsystems={}", nvme_subsystems)
        extracted_data = NvmeSubsystemDetailInfoExtractor(
            self.storage_serial_number
        ).extract(nvme_subsystems.data_to_list())
        return extracted_data

    @log_entry_exit
    def get_nvme_subsystems(self, spec):
        nvme_subsystems = self.provisioner.get_nvme_subsystems(spec)
        # extracted_data = TrueCopyInfoExtractor(self.storage_serial_number).extract(tc_pairs)
        # return extracted_data

        return nvme_subsystems

    @log_entry_exit
    def get_nvme_subsystem_by_name(self, name):
        nvme_subsystem = self.provisioner.get_nvme_subsystem_by_name(name)
        return nvme_subsystem

    @log_entry_exit
    def get_nvme_subsystem_by_id(self, id):
        nvme_subsystem = self.provisioner.get_nvme_subsystem_by_id(id)
        return nvme_subsystem

    @log_entry_exit
    def get_host_nqns(self, nvm_system_id):
        host_nqns = self.provisioner.get_host_nqns(nvm_system_id)
        return host_nqns

    @log_entry_exit
    def get_namespaces(self, nvm_system_id):
        namespaces = self.provisioner.get_namespaces(nvm_system_id)
        return namespaces

    @log_entry_exit
    def get_namespace_paths(self, nvm_system_id):
        namespace_paths = self.provisioner.get_namespaces(nvm_system_id)
        return namespace_paths

    @log_entry_exit
    def get_nvme_ports(self, nvm_system_id):
        nvme_ports = self.provisioner.get_nvme_ports(nvm_system_id)
        return nvme_ports

    @log_entry_exit
    def get_host_nqn(self, host_nqn_id):
        host_nqn = self.provisioner.get_host_nqn(host_nqn_id)
        return host_nqn

    @log_entry_exit
    def register_host_nqn(self, nvm_subsystem_id, host_nqn):
        host_nqn = self.provisioner.register_host_nqn(nvm_subsystem_id, host_nqn)
        return host_nqn

    @log_entry_exit
    def set_host_namespace_path(self, nvm_subsystem_id, host_nqn, namespace_id):
        host_ns_path_id = self.provisioner.set_host_namespace_path(
            nvm_subsystem_id, host_nqn, namespace_id
        )
        return host_ns_path_id

    @log_entry_exit
    def get_nvme_subsystems_by_namespace(self):
        nvme_subsystems = self.provisioner.get_nvme_subsystems_by_namespace()
        return nvme_subsystems

    @log_entry_exit
    def delete_namespace(self, nvm_subsystem_id, namespace_id):
        ns_data = self.provisioner.delete_namespace(nvm_subsystem_id, namespace_id)
        return ns_data


class NvmeSubsystemDetailInfoExtractor:
    def __init__(self, serial):
        self.storage_serial_number = serial
        self.common_properties = {
            "nvmSubsystemInfo": dict,
            "portInfo": list,
            "namespacesInfo": list,
            "namespacePathsInfo": list,
            "hostNqnInfo": list,
        }

    @log_entry_exit
    def change_keys(self, response_key):
        new_dict = {}
        if not response_key:
            return new_dict
        for key, value in response_key.items():
            key = camel_to_snake_case(key)
            value_type = type(value)
            if value is None:
                default_value = get_default_value(value_type)
                value = default_value
            new_dict[key] = value
            if new_dict.get("ldev_id_hex") == "" or new_dict.get("ldev_id_hex") is None:
                if new_dict.get("ldev_id") is not None or new_dict.get("ldev_id"):
                    new_dict["ldev_id_hex"] = volume_id_to_hex_format(
                        new_dict.get("ldev_id")
                    )
        return new_dict

    def process_list(self, response_key):
        new_items = []

        if response_key is None:
            return []

        for item in response_key:
            new_dict = {}
            for key, value in item.items():
                key = camel_to_snake_case(key)
                value_type = type(value)
                if value is None:
                    default_value = get_default_value(value_type)
                    value = default_value
                new_dict[key] = value
                if (
                    new_dict.get("ldev_id_hex") == ""
                    or new_dict.get("ldev_id_hex") is None
                ):
                    if new_dict.get("ldev_id") is not None or new_dict.get("ldev_id"):
                        new_dict["ldev_id_hex"] = volume_id_to_hex_format(
                            new_dict.get("ldev_id")
                        )
                if (
                    new_dict.get("capacity_in_unit") == ""
                    or new_dict.get("capacit_in_unit") is None
                ):
                    if new_dict.get("byte_format_capacity") is not None or new_dict.get(
                        "byte_format_capacity"
                    ):
                        old_value = new_dict.pop("byte_format_capacity")
                        if " M" in old_value:
                            new_value = old_value.replace(" M", "MB")
                        else:
                            new_value = old_value.replace(" G", "GB")
                        new_dict["capacity_in_unit"] = new_value
                        mb_capacity = convert_to_mb(new_dict["capacity_in_unit"])
                        new_dict["capacity_in_mb"] = mb_capacity
            new_items.append(new_dict)
        return new_items

    def extract(self, responses):
        new_items = []
        for response in responses:
            new_dict = {"storage_serial_number": self.storage_serial_number}
            for key, value_type in self.common_properties.items():
                # Get the corresponding key from the response or its mapped key
                response_key = response.get(key)
                if value_type == dict:
                    response_key = self.change_keys(response_key)
                if value_type == list:
                    response_key = self.process_list(response_key)
                # Assign the value based on the response key and its data type
                cased_key = camel_to_snake_case(key)
                if response_key is not None:
                    new_dict[cased_key] = value_type(response_key)
                else:
                    # Handle missing keys by assigning default values
                    default_value = get_default_value(value_type)
                    new_dict[cased_key] = default_value
            new_items.append(new_dict)
        return new_items


class NvmeSubsystemInfoExtractor:
    def __init__(self, serial):
        self.storage_serial_number = serial
        self.common_properties = {
            "nvmSubsystemId": int,
            "nvmSubsystemName": str,
            "resourceGroupId": int,
            "namespaceSecuritySetting": str,
            "t10piMode": str,
            "hostMode": str,
        }

    def extract(self, responses):
        new_items = []
        for response in responses:
            new_dict = {"storage_serial_number": self.storage_serial_number}
            for key, value_type in self.common_properties.items():
                # Get the corresponding key from the response or its mapped key
                response_key = response.get(key)
                # Assign the value based on the response key and its data type
                cased_key = camel_to_snake_case(key)
                if response_key is not None:
                    new_dict[cased_key] = value_type(response_key)
                else:
                    # Handle missing keys by assigning default values
                    default_value = get_default_value(value_type)
                    new_dict[cased_key] = default_value
            new_items.append(new_dict)
        return new_items
