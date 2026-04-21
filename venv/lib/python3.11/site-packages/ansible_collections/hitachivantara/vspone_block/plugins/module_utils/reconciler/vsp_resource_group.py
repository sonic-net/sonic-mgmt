import time

try:
    from ..common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        volume_id_to_hex_format,
    )
    from ..common.hv_log import Log
    from ..common.hv_constants import StateValue
    from ..provisioner.vsp_resource_group_provisioner import VSPResourceGroupProvisioner
    from ..provisioner.vsp_volume_prov import VSPVolumeProvisioner
    from ..gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from ..message.vsp_resource_group_msgs import VSPResourceGroupValidateMsg


except ImportError:
    from common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        volume_id_to_hex_format,
    )
    from common.hv_log import Log
    from common.hv_constants import StateValue
    from provisioner.vsp_resource_group_provisioner import VSPResourceGroupProvisioner
    from provisioner.vsp_volume_prov import VSPVolumeProvisioner
    from gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from message.vsp_resource_group_msgs import VSPResourceGroupValidateMsg


logger = Log()
MAX_RETRY_COUNT = 5


class VSPResourceGroupSubstates:
    """
    Enum class for Resource Group Substates
    """

    ADD_RESOURCE = "add_resource"
    REMOVE_RESOURCE = "remove_resource"


class VSPResourceGroupReconciler:
    def __init__(self, connection_info, serial=None, state=None):

        self.connection_info = connection_info
        self.storage_serial_number = serial
        if self.storage_serial_number is None:
            self.storage_serial_number = self.get_storage_serial_number()
        self.provisioner = VSPResourceGroupProvisioner(
            connection_info, self.storage_serial_number
        )
        self.volume_provisioner = VSPVolumeProvisioner(
            connection_info, self.storage_serial_number
        )

        if state:
            self.state = state

    @log_entry_exit
    def get_resource_group_facts(self, spec):
        resource_groups = self.provisioner.get_resource_groups(spec)
        logger.writeDebug("RC:resource_groups={}", resource_groups)
        if resource_groups is None or not resource_groups.data_to_list():
            return []

        extracted_data = ResourceGroupInfoExtractor(self.storage_serial_number).extract(
            resource_groups.data_to_list()
        )
        return extracted_data

    @log_entry_exit
    def get_storage_serial_number(self):
        storage_gw = VSPStorageSystemDirectGateway(self.connection_info)
        storage_system = storage_gw.get_current_storage_system_info()
        return storage_system.serialNumber

    @log_entry_exit
    def reconcile_resource_group(self, spec):
        """Reconciler for resource group management"""

        if self.state == StateValue.PRESENT:
            rg = None
            if spec.id:
                rg = self.provisioner.get_resource_group_by_id(spec.id)
                if rg is None:
                    raise ValueError(VSPResourceGroupValidateMsg.RG_NOT_FOUND.value)
            else:
                if spec.name:
                    rg = self.provisioner.get_resource_group_by_name(spec.name)
            self.provisioner.spec = spec
            comment = None
            if not rg:
                spec.id = self.create_resource_group(spec)
            else:
                spec.id = rg.resourceGroupId
                self.update_resource_group(rg, spec)

            sp_ids = None
            sp_ids = self.provisioner.handle_storage_pools()

            logger.writeDebug("RC:reconcile_resource_group:spec.id={}", spec.id)
            rg3 = self.provisioner.get_resource_group_by_id(spec.id)
            logger.writeDebug("RC:reconcile_resource_group:rg3={}", rg3)

            rg2 = self.provisioner.convert_rg_to_display_rg(rg3, sp_ids)
            logger.writeDebug("RC:reconcile_resource_group:rg2={}", rg2)
            if not rg2:
                return None, "Resource Group not found."
            extracted_data = ResourceGroupInfoExtractor(
                self.storage_serial_number
            ).extract([rg2.to_dict()])
            if spec.storage_pool_ids:
                comment = f"Pool volumes for Storage Pool(s) {spec.storage_pool_ids} are incorporated in the Resource Group Ldevs."
            return extracted_data, comment

        elif self.state == StateValue.ABSENT:
            if spec.id:
                rg = self.provisioner.get_resource_group_by_id(spec.id)
            else:
                if spec.name:
                    rg = self.provisioner.get_resource_group_by_name(spec.name)
            if not rg:
                return None, "Resource Group not found."
            logger.writeDebug(
                "RC:reconcile_resource_group:state=absent:resource_group={}", rg
            )

            if spec.force and spec.force is True:
                comment = self.delete_resource_group_force(rg)
                return None, comment
            else:
                comment = self.delete_resource_group(rg, spec)
                return None, comment

    @log_entry_exit
    def create_resource_group(self, spec):
        if spec.state:
            if spec.state.lower() == VSPResourceGroupSubstates.REMOVE_RESOURCE:
                raise ValueError(VSPResourceGroupValidateMsg.CONTRADICT_INFO.value)

        rg_id = self.provisioner.create_resource_group(spec)
        logger.writeDebug("RC:create_resource_group:ret_value={}", rg_id)
        # self.connection_info.changed = True

        if (
            spec.state is None
            or spec.state.lower() == VSPResourceGroupSubstates.ADD_RESOURCE
        ):
            rg = self.provisioner.get_resource_group_by_id(rg_id)
            if rg is None:
                retry_count = 0
                while retry_count < MAX_RETRY_COUNT:
                    time.sleep(30)
                    logger.writeDebug(f"try number {retry_count + 1}")
                    new_rg = self.provisioner.get_resource_group_by_id(rg_id)
                    logger.writeDebug(f"new_rg={new_rg}")
                    if new_rg:
                        rg = new_rg
                        break
                    else:
                        retry_count += 1
                if retry_count == MAX_RETRY_COUNT:
                    err_msg = VSPResourceGroupValidateMsg.UPDATED_RG_INFO_NOT_RCVD.value
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)

            self.add_resource(rg, spec)

        return rg_id

    @log_entry_exit
    def update_resource_group(self, rg, spec):

        if (
            spec.state is None
            or spec.state.lower() == VSPResourceGroupSubstates.ADD_RESOURCE
        ):
            self.update_add_resource(rg, spec)
        elif spec.state.lower() == VSPResourceGroupSubstates.REMOVE_RESOURCE:
            self.remove_resource(rg, spec)

        return

    @log_entry_exit
    def construct_simple_hg_list(self, spec):
        hg_list = []
        if spec.host_groups:
            for hg in spec.host_groups:
                if "id" in hg:
                    hg_list.append(f"{hg['port']},{hg['id']}")
                elif "name" in hg:
                    id = self.provisioner.get_host_group_id(hg["port"], hg["name"])
                    if id:
                        hg_list.append(f"{hg['port']},{id}")
        return hg_list

    @log_entry_exit
    def construct_simple_iscsi_list(self, spec):
        iscsi_list = []
        if spec.iscsi_targets:
            for hg in spec.iscsi_targets:
                if "id" in hg:
                    iscsi_list.append(f"{hg['port']},{hg['id']}")
                elif "name" in hg:
                    id = self.provisioner.get_iscsi_id(hg["port"], hg["name"])
                    if id is None:
                        logger.writeInfo(
                            f"Could not find ID for iSCSI {hg['name']} on port {hg['port']}."
                        )
                        continue
                    logger.writeDebug("RC:construct_simple_iscsi_list:id={}", id)
                    iscsi_list.append(f"{hg['port']},{id}")
        logger.writeDebug("RC:construct_simple_iscsi_list:iscsi_list={}", iscsi_list)
        return iscsi_list

    @log_entry_exit
    def get_vsm_ldevs(self, ldevs):
        vsm_ldevs = []
        for ldev in ldevs:
            ldev_info = self.volume_provisioner.get_volume_by_ldev(ldev)
            if ldev_info:
                logger.writeDebug("RC:get_vsm_ldevs:ldev_info={}", ldev_info)

                if ldev_info.resourceGroupId == 0:
                    if ldev_info.nvmSubsystemId or ldev_info.namespaceId:
                        logger.writeDebug(
                            "RC:get_vsm_ldevs:ldev_info={}  is part of nvm subsystem.",
                            ldev_info,
                        )
                        continue

                    if ldev_info.ports and len(ldev_info.ports) > 0:
                        logger.writeDebug(
                            "RC:get_vsm_ldevs:ldev_info={}  is connected to host groups.",
                            ldev_info,
                        )
                        continue

                    self.volume_provisioner.unassign_vldev(
                        ldev_info.ldevId, ldev_info.ldevId
                    )
                    vsm_ldevs.append(ldev)
        return vsm_ldevs

    @log_entry_exit
    def update_add_resource(self, rg, spec):
        if rg:
            logger.writeDebug("RC:update_add_resource:rg={}", rg)
        ldevs_to_add = None

        if spec.ldevs:
            # if virtual storage id is not 0, then this is a VSM
            if rg.virtualStorageId != 0:
                vsm_ldevs = self.get_vsm_ldevs(spec.ldevs)
                logger.writeDebug("RC:get_vsm_ldevs:vsm_ldevs={}", vsm_ldevs)
                if vsm_ldevs and len(vsm_ldevs) > 0 and rg.ldevIds:
                    ldevs_to_add = list(set(spec.ldevs) - set(rg.ldevIds))
                    spec.ldevs = ldevs_to_add
                if vsm_ldevs and len(vsm_ldevs) > 0:
                    spec.ldevs = vsm_ldevs
                else:
                    spec.ldevs = []

                # if rg.ldevIds:
                #     ldevs_to_add = list(set(spec.ldevs) - set(rg.ldevIds))
                #     spec.ldevs = ldevs_to_add
                logger.writeDebug("RC:get_vsm_ldevs:spec.ldev={}", spec.ldevs)
            else:
                if rg.ldevIds:
                    ldevs_to_add = list(set(spec.ldevs) - set(rg.ldevIds))
                    spec.ldevs = ldevs_to_add
        if spec.parity_groups:
            if rg.parityGroupIds:
                parity_groups_to_add = list(
                    set(spec.parity_groups) - set(rg.parityGroupIds)
                )
                spec.parity_groups = parity_groups_to_add
        if spec.ports:
            if rg.portIds:
                ports_to_add = list(set(spec.ports) - set(rg.portIds))
                spec.ports = ports_to_add
        if spec.nvm_subsystem_ids:
            if rg.nvmSubsystemIds:
                nvm_subsystems_to_add = list(
                    set(spec.nvm_subsystem_ids) - set(rg.nvmSubsystemIds)
                )
                spec.nvm_subsystem_ids = nvm_subsystems_to_add
        # Handle host groups and iscsi targets in the add resource case
        self.add_resource(rg, spec)
        return

    @log_entry_exit
    def fix_host_groups_for_add(self, rg, spec):
        host_groups_to_add = None
        if spec.host_groups:
            hg_list = self.construct_simple_hg_list(spec)
            logger.writeDebug(
                "RC:fix_host_groups_for_add:updated hg simple list ={}", hg_list
            )
            spec.host_groups_simple = hg_list
            if rg.hostGroupIds:
                host_groups_to_add = []  # list(set(hg_list) - set(rg.hostGroupIds))
                for hg in hg_list:
                    logger.writeDebug(
                        "RC:update_add_resource:updated hg={} {}", hg, rg.hostGroupIds
                    )
                    if str(hg) not in rg.hostGroupIds:
                        logger.writeDebug(
                            "RC:update_add_resource:updated2 hg={} {}",
                            hg,
                            rg.hostGroupIds,
                        )
                        host_groups_to_add.append(hg)
                spec.host_groups_simple = host_groups_to_add
                logger.writeDebug(
                    "RC:update_add_resource:updated2 hg={} {}", hg, host_groups_to_add
                )

        if spec.iscsi_targets:
            iscsi_list = self.construct_simple_iscsi_list(spec)
            iscsi_targets_to_add = []

            if rg.hostGroupIds:
                for iscsi in iscsi_list:
                    if str(iscsi) not in rg.hostGroupIds:
                        iscsi_targets_to_add.append(iscsi)
                logger.writeDebug(
                    "RC:update_add_resource:updated2 iscsi={}", iscsi_targets_to_add
                )
                if (
                    host_groups_to_add
                    and len(host_groups_to_add) > 0
                    and iscsi_targets_to_add
                    and len(iscsi_targets_to_add) > 0
                ):
                    new_host_groups_to_add = list(
                        set(host_groups_to_add) | set(iscsi_targets_to_add)
                    )
                    spec.host_groups_simple = new_host_groups_to_add
                else:
                    spec.host_groups_simple = iscsi_targets_to_add
            else:
                spec.host_groups_simple = iscsi_list

        return

    @log_entry_exit
    def fix_host_groups_for_remove(self, rg, spec):
        host_groups_to_remove = []
        iscsi_targets_to_remove = []
        if spec.host_groups:
            hg_list = self.construct_simple_hg_list(spec)
            rg_host_list = rg.hostGroupIds
            if rg_host_list:
                host_groups_to_remove = list(set(hg_list) & set(rg_host_list))
            spec.host_groups_simple = host_groups_to_remove

        if spec.iscsi_targets:
            iscsi_list = self.construct_simple_iscsi_list(spec)
            rg_host_list = rg.hostGroupIds
            if rg_host_list:
                iscsi_targets_to_remove = list(set(iscsi_list) & set(rg_host_list))

            if (
                host_groups_to_remove
                and len(host_groups_to_remove) > 0
                and iscsi_targets_to_remove
                and len(iscsi_targets_to_remove) > 0
            ):
                new_host_groups_to_remove = list(
                    set(host_groups_to_remove) | set(iscsi_targets_to_remove)
                )
                spec.host_groups_simple = new_host_groups_to_remove
            else:
                spec.iscsi_targets_simple = iscsi_targets_to_remove

    @log_entry_exit
    def fix_ldevs_for_remove(self, rg, spec):
        if spec.ldevs:
            if rg.ldevIds:
                ldevs_to_remove = list(set(spec.ldevs) & set(rg.ldevIds))
                spec.ldevs = ldevs_to_remove

        if spec.storage_pool_ids:
            pool_ldevs = self.provisioner.get_pool_ldevs(spec.storage_pool_ids)
            if pool_ldevs:
                if spec.ldevs:
                    ldevs_to_remove = list(set(spec.ldevs) + set(pool_ldevs))
                    spec.ldevs = ldevs_to_remove
                    if rg.ldevIds:
                        ldevs_to_remove = list(set(spec.ldevs) & set(rg.ldevIds))
                        spec.ldevs = ldevs_to_remove
                else:
                    spec.ldevs = pool_ldevs
                    if rg.ldevIds:
                        ldevs_to_remove = list(set(spec.ldevs) & set(rg.ldevIds))
                        spec.ldevs = ldevs_to_remove

    @log_entry_exit
    def fix_ldevs_for_add(self, rg, spec):
        if spec.ldevs:
            if rg.ldevIds:
                ldevs_to_add = list(set(spec.ldevs) - set(rg.ldevIds))
                spec.ldevs = ldevs_to_add
        if spec.storage_pool_ids:
            pool_ldevs = self.provisioner.get_pool_ldevs(spec.storage_pool_ids)
            if pool_ldevs:
                if spec.ldevs:
                    ldevs_to_add = list(set(spec.ldevs) + set(pool_ldevs))
                    spec.ldevs = ldevs_to_add
                    if rg.ldevIds:
                        ldevs_to_add = list(set(spec.ldevs) - set(rg.ldevIds))
                        spec.ldevs = ldevs_to_add
                else:
                    spec.ldevs = pool_ldevs
                    if rg.ldevIds:
                        ldevs_to_add = list(set(spec.ldevs) - set(rg.ldevIds))
                        spec.ldevs = ldevs_to_add

    @log_entry_exit
    def add_resource(self, rg, spec):
        if not self.provisioner.is_update_needed(spec):
            return
        self.fix_host_groups_for_add(rg, spec)
        self.fix_ldevs_for_add(rg, spec)
        rg_id = self.provisioner.add_resource(rg, spec)

        return rg_id

    @log_entry_exit
    def remove_resource(self, rg, spec):
        if not self.provisioner.is_update_needed(spec):
            return
        self.fix_host_groups_for_remove(rg, spec)
        self.fix_ldevs_for_remove(rg, spec)

        rg_id = self.provisioner.remove_resource(rg, spec)
        logger.writeDebug("RC:remove_resource:ret_data={}", rg_id)

        # if remove resource is not needed provision layer will return None
        if rg_id is None:
            return

        return rg_id

    @log_entry_exit
    def is_resource_group_changed(self, rg, new_rg):
        changed = False
        if rg is None or new_rg is None:
            return changed
        if rg.volumes != new_rg.volumes:
            changed = True
        if rg.parityGroups != new_rg.parityGroups:
            changed = True
        if rg.ports != new_rg.ports:
            changed = True
        if rg.hostGroups != new_rg.hostGroups:
            changed = True
        if rg.iscsiTargets != new_rg.iscsiTargets:
            changed = True
        # if rg.nvmSubsystemIds != new_rg.nvmSubsystemIds:
        #     changed = True
        if rg.pools != new_rg.pools:
            changed = True
        return changed

    @log_entry_exit
    def delete_resource_group(self, resource_group, spec):
        ret_value = self.provisioner.delete_resource_group(resource_group, spec)
        logger.writeDebug("RC:delete_resource_group:ret_value={}", ret_value)
        return "Resource group deleted successfully."

    @log_entry_exit
    def delete_resource_group_force(self, resource_group):
        ret_value = self.provisioner.delete_resource_group_force(resource_group)
        logger.writeDebug("RC:delete_resource_group_force:ret_value={}", ret_value)
        return "Resource group deleted successfully."


class ResourceGroupInfoExtractor:
    def __init__(self, serial):
        self.storage_serial_number = serial
        self.common_properties = {
            "name": str,
            "id": int,
            "lockStatus": str,
            "selfLock": bool,
            "lockOwner": str,
            "lockHost": str,
            "lockSessionId": int,
            "virtualStorageId": int,
            "ldevs": list[int],
            "ldevs_hex": list[str],
            "parityGroups": list[str],
            "externalParityGroups": list[str],
            "ports": list[str],
            "hostGroups": list[dict],
            "iscsiTargets": list[dict],
            "nvmSubsystemIds": list[int],
            "storagePoolIds": list[int],
            "virtualStorageDeviceId": str,
            "virtualSerialNumber": str,
            "virtualModel": str,
            "virtualDeviceType": str,
        }

    def process_list(self, response_key):
        new_items = []

        if response_key is None:
            return []
        # logger.writeDebug("RC:process_list:response_key={}", response_key)
        for item in response_key:
            new_dict = {}
            for key, value in item.items():
                key = camel_to_snake_case(key)

                if value is None:
                    # default_value = get_default_value(value_type)
                    # value = default_value
                    continue
                new_dict[key] = value
            new_items.append(new_dict)

        return new_items

    def extract(self, responses):
        new_items = []
        for response in responses:
            new_dict = {"storage_serial_number": self.storage_serial_number}
            for key, value_type in self.common_properties.items():
                # Get the corresponding key from the response or its mapped key
                response_key = response.get(key)
                # logger.writeDebug("RC:extract:value_type={}", value_type)
                if value_type == list[dict]:
                    response_key = self.process_list(response_key)
                # Assign the value based on the response key and its data type
                cased_key = camel_to_snake_case(key)
                if response_key is not None:
                    new_dict[cased_key] = value_type(response_key)
                else:
                    pass
                    # DO NOT HANDLE MISSING KEYS
                    # Handle missing keys by assigning default values
                    # default_value = get_default_value(value_type)
                    # new_dict[cased_key] = default_value
            if new_dict.get("ldevs_hex") == "" or new_dict.get("ldevs_hex") is None:
                if new_dict.get("ldevs") is not None and new_dict.get("ldevs") != []:
                    ldev_ids = new_dict.get("ldevs", None)
                    new_dict["ldevs_hex"] = [
                        volume_id_to_hex_format(ldev_id) for ldev_id in ldev_ids
                    ]
            new_items.append(new_dict)
        return new_items
