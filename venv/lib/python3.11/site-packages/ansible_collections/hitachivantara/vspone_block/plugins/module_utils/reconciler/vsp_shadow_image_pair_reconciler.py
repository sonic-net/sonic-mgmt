try:
    from ..provisioner.vsp_storage_port_provisioner import VSPStoragePortProvisioner
    from ..provisioner.vsp_shadow_image_pair_provisioner import (
        VSPShadowImagePairProvisioner,
    )
    from ..common.ansible_common import (
        camel_to_snake_case,
        snake_to_camel_case,
        log_entry_exit,
        volume_id_to_hex_format,
        get_default_value,
    )
    from ..common.hv_constants import (
        StateValue,
    )
    from ..common.hv_log import Log
    from ..common.hv_constants import ConnectionTypes
    from ..gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
except ImportError:
    from ..provisioner.vsp_storage_port_provisioner import VSPStoragePortProvisioner
    from provisioner.vsp_shadow_image_pair_provisioner import (
        VSPShadowImagePairProvisioner,
    )
    from common.ansible_common import (
        camel_to_snake_case,
        snake_to_camel_case,
        log_entry_exit,
        volume_id_to_hex_format,
        get_default_value,
    )
    from common.hv_constants import StateValue
    from common.hv_log import Log
    from common.hv_constants import ConnectionTypes
    from gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
logger = Log()


class VSPShadowImagePairReconciler:

    def __init__(self, connectionInfo, serial, shadowImagePairSpec=None):
        self.logger = Log()
        self.connectionInfo = connectionInfo
        self.serial = serial
        self.shadowImagePairSpec = shadowImagePairSpec
        self.provisioner = VSPShadowImagePairProvisioner(self.connectionInfo)
        self.port_provisioner = VSPStoragePortProvisioner(connectionInfo)
        self.port_type_dict = {}
        self.get_port_type_dict()
        if self.serial is None:
            self.serial = self.get_storage_serial_number()

    def get_port_type_dict(self):
        port_info = self.port_provisioner.get_all_storage_ports().data_to_list()
        # self.logger.writeDebug(f"20250324 port_info: {port_info}")
        for port in port_info:
            self.port_type_dict[port["portId"]] = port["portType"]
        self.logger.writeDebug(f"20250324 self.port_type_dict: {self.port_type_dict}")

    @log_entry_exit
    def shadow_image_pair_facts(self, shadowImagePairSpec):
        if (
            shadowImagePairSpec.pvol is None
            and shadowImagePairSpec.copy_group_name is None
            and shadowImagePairSpec.copy_pair_name is None
        ):
            data = self.provisioner.get_all_shadow_image_pairs(
                self.serial, None, shadowImagePairSpec.refresh
            )
        elif shadowImagePairSpec.copy_pair_name and shadowImagePairSpec.copy_group_name:
            data = self.provisioner.get_shadow_image_pair_by_copy_pair_name(
                self.serial,
                shadowImagePairSpec.copy_pair_name,
                shadowImagePairSpec.copy_group_name,
            )
            data = (
                ShadowImagePairPropertyExtractor(self.serial).extract(
                    [data], self.port_type_dict
                )[0]
                if isinstance(data, dict)
                else data
            )
            return data
        else:
            data = self.provisioner.get_all_shadow_image_pairs(
                self.serial, shadowImagePairSpec.pvol, None
            )
        return ShadowImagePairPropertyExtractor(self.serial).extract(
            data, self.port_type_dict
        )

    @log_entry_exit
    def get_storage_serial_number(self):
        storage_gw = VSPStorageSystemDirectGateway(self.connectionInfo)
        storage_system = storage_gw.get_current_storage_system_info()
        return storage_system.serialNumber

    @log_entry_exit
    def shadow_image_pair_module(self, state):

        shadow_image_response = None
        copy_group_name = None
        shadow_image_data = None
        # if self.shadowImagePairSpec.pvol and self.shadowImagePairSpec.svol:
        #     shadow_image_data = self.shadow_image_pair_get_by_pvol_and_svol(
        #         self.shadowImagePairSpec.pvol, self.shadowImagePairSpec.svol
        #     )
        # elif (
        #     self.shadowImagePairSpec.copy_pair_name
        #     and self.shadowImagePairSpec.copy_group_name
        # ):
        #     shadow_image_data = self.get_shadow_image_pair_by_copy_pair_name(
        #         self.shadowImagePairSpec.copy_pair_name,
        #         self.shadowImagePairSpec.copy_group_name,
        #     )
        # else:
        #     raise ValueError(
        #         "Either pvol and svol or copy_pair_name and copy_group_name must be provided."
        #     )
        if (
            self.shadowImagePairSpec.pvol is None
            or self.shadowImagePairSpec.svol is None
        ) and (
            self.shadowImagePairSpec.copy_pair_name is None
            or self.shadowImagePairSpec.copy_group_name is None
        ):

            raise ValueError(
                "Either pvol and svol or copy_pair_name and copy_group_name must be provided."
            )
        shadow_image_data = self.provisioner.get_specific_cg_pair_by_pvol_svol(
            self.shadowImagePairSpec.pvol,
            self.shadowImagePairSpec.svol,
            self.shadowImagePairSpec.copy_group_name,
            self.shadowImagePairSpec.copy_pair_name,
            self.shadowImagePairSpec.primary_volume_device_group_name,
            self.shadowImagePairSpec.secondary_volume_device_group_name,
        )
        shadow_image_data = shadow_image_data.to_dict() if shadow_image_data else None

        pairId = None
        if shadow_image_data is not None:
            pairId = shadow_image_data.get("resourceId")
            pvolId = shadow_image_data.get("primaryVolumeId")
            svolId = shadow_image_data.get("secondaryVolumeId")
            copy_group_name = shadow_image_data.get("copyGroupName")
            self.shadowImagePairSpec.secondary_volume_id = svolId
        if pairId is not None:
            self.shadowImagePairSpec.pair_id = pairId
        try:
            if state == StateValue.PRESENT:
                if (
                    (pairId is not None)
                    and (int(self.shadowImagePairSpec.primary_volume_id) == int(pvolId))
                    and (self.shadowImagePairSpec.secondary_volume_id is not None)
                    and (
                        int(self.shadowImagePairSpec.secondary_volume_id) == int(svolId)
                    )
                ):
                    shadow_image_response = shadow_image_data
                    self.connectionInfo.changed = False
                else:
                    if copy_group_name is not None:
                        if self.shadowImagePairSpec.copy_group_name == copy_group_name:
                            self.shadowImagePairSpec.is_new_group_creation = False
                            elements = pairId.split(",")
                            if elements is not None and len(elements) > 2:
                                self.shadowImagePairSpec.primary_volume_device_group_name = elements[
                                    1
                                ]
                                self.shadowImagePairSpec.secondary_volume_device_group_name = elements[
                                    2
                                ]
                        else:
                            self.shadowImagePairSpec.is_new_group_creation = True
                    try:
                        shadow_image_response = self.shadow_image_pair_create(
                            self.shadowImagePairSpec
                        )
                        self.connectionInfo.changed = True
                    except Exception as e:
                        logger.writeError(f"Error creating shadow image pair: {e}")
                        if (
                            "Another copy pair might already be using the specified LDEV"
                            in str(e)
                        ):
                            raise Exception(
                                f"Another copy pair might already be using the specified primary volume {self.shadowImagePairSpec.primary_volume_id}. "
                                f"and secondary volume {self.shadowImagePairSpec.secondary_volume_id}. "
                                "Please verify and try again with correct copy group name and copy pair name."
                            )
                        else:
                            raise e
            elif state == StateValue.SPLIT:
                if pairId is not None:
                    if (
                        shadow_image_data.get("status") == "PSUS"
                        and self.shadowImagePairSpec.should_force_split is None
                    ):
                        shadow_image_response = shadow_image_data
                        self.connectionInfo.changed = False
                    else:
                        shadow_image_response = self.shadow_image_pair_split(
                            self.shadowImagePairSpec
                        )
                        self.connectionInfo.changed = True
                else:
                    self.shadowImagePairSpec.auto_split = True
                    shadow_image_response = self.shadow_image_pair_create(
                        self.shadowImagePairSpec
                    )
                    self.connectionInfo.changed = True
            elif state == StateValue.SYNC:
                if pairId is not None:
                    if shadow_image_data.get("status") == "PAIR":
                        shadow_image_response = shadow_image_data
                        self.connectionInfo.changed = False
                    else:
                        shadow_image_response = self.shadow_image_pair_resync(
                            self.shadowImagePairSpec
                        )
                        self.connectionInfo.changed = True
                else:
                    shadow_image_response = "Shadow image pair is not available."
                    self.connectionInfo.changed = False
            elif state == StateValue.RESTORE:
                if pairId is not None:
                    if shadow_image_data.get("status") == "PAIR":
                        shadow_image_response = shadow_image_data
                        self.connectionInfo.changed = False
                    else:
                        shadow_image_response = self.shadow_image_pair_restore(
                            self.shadowImagePairSpec
                        )
                        self.connectionInfo.changed = True
                else:
                    shadow_image_response = "Shadow image pair is not available."
                    self.connectionInfo.changed = False
            elif state == StateValue.ABSENT:
                if pairId is not None:
                    shadow_image_response = self.shadow_image_pair_delete(
                        self.shadowImagePairSpec
                    )
                    self.connectionInfo.changed = True
                else:
                    shadow_image_response = "Shadow image pair is not available."
                    self.connectionInfo.changed = False
            elif state == StateValue.MIGRATE:
                if pairId is not None:
                    shadow_image_response = self.shadow_image_pair_migrate(
                        self.shadowImagePairSpec
                    )
                    self.connectionInfo.changed = True
                else:
                    shadow_image_response = "Shadow image pair is not available."
                    self.connectionInfo.changed = False

        except Exception as e:
            logger.writeError(f"An error occurred: {str(e)}")
            if (
                self.connectionInfo.connection_type is None
                or self.connectionInfo.connection_type == ConnectionTypes.DIRECT
            ):
                if e.args is not list:
                    for elm in e.args[0]:
                        if "message" == elm:
                            raise Exception(e.args[0]["message"])
                    raise Exception(e.args[0])
                    # if e.args[0]['message'] is not None:
                    #     raise Exception(e.args[0]['message'])
                    # else:
                    #     raise Exception(e.args[0])
                    # try:
                    #     if e.args[0]['message'] is not None:
                    #         raise Exception(e.args[0]['message'])
                    # except Exception as ex:
                    #     raise Exception(ex.args)
                elif "message" in e.args[0]:
                    raise Exception(e.args[0].get("message"))

                else:
                    raise Exception(e)
            logger.writeError(f"An error occurred: {str(e)}")
            raise Exception(str(e))

        shadow_image_response = (
            ShadowImagePairPropertyExtractor(self.serial).extract(
                [shadow_image_response], self.port_type_dict
            )[0]
            if isinstance(shadow_image_response, dict)
            else shadow_image_response
        )
        return shadow_image_response

    @log_entry_exit
    def shadow_image_pair_create(self, shadowImagePairSpec):
        data = self.provisioner.create_shadow_image_pair(
            self.serial, shadowImagePairSpec
        )
        return data

    @log_entry_exit
    def shadow_image_pair_split(self, shadowImagePairSpec):
        data = self.provisioner.split_shadow_image_pair(
            self.serial, shadowImagePairSpec
        )
        return data

    @log_entry_exit
    def shadow_image_pair_resync(self, shadowImagePairSpec):
        data = self.provisioner.resync_shadow_image_pair(
            self.serial, shadowImagePairSpec
        )
        return data

    @log_entry_exit
    def shadow_image_pair_restore(self, shadowImagePairSpec):
        data = self.provisioner.restore_shadow_image_pair(
            self.serial, shadowImagePairSpec
        )
        return data

    @log_entry_exit
    def shadow_image_pair_migrate(self, shadowImagePairSpec):
        data = self.provisioner.migrate_shadow_image_pair(
            self.serial, shadowImagePairSpec
        )
        return data

    @log_entry_exit
    def shadow_image_pair_get_by_pvol_and_svol(self, pvol, svol):
        data = self.provisioner.get_shadow_image_pair_by_pvol_and_svol(
            self.serial, pvol, svol
        )
        return data

    @log_entry_exit
    def get_shadow_image_pair_by_copy_pair_name(self, copy_pair_name, copy_group_name):
        data = self.provisioner.get_shadow_image_pair_by_copy_pair_name(
            self.serial, copy_pair_name, copy_group_name
        )
        return data

    @log_entry_exit
    def shadow_image_pair_delete(self, shadowImagePairSpec):
        data = self.provisioner.delete_shadow_image_pair(
            self.serial, shadowImagePairSpec
        )
        return data


class ShadowImagePairPropertyExtractor:
    def __init__(self, serial):
        self.common_properties = {
            # "resource_id": str,
            "consistency_group_id": int,
            "copy_pace_track_size": str,
            "copy_rate": int,
            "mirror_unit_id": int,
            "primary_volume_id_hex": str,
            "primary_volume_id": int,
            "storage_serial_number": str,
            "secondary_volume_id_hex": str,
            "secondary_volume_id": int,
            "status": str,
            "copy_group_name": str,
            "copy_pair_name": str,
            "pvol_nvm_subsystem_name": str,
            "svol_nvm_subsystem_name": str,
            "pvol_host_groups": list,
            "svol_host_groups": list,
        }
        self.serial = serial

    def extract(self, responses, port_type_dict):
        new_items = []
        for response in responses:
            new_dict = {"storage_serial_number": self.serial}

            for key, value_type in self.common_properties.items():
                # Assign the value based on the response key and its data type
                cased_key = snake_to_camel_case(key)
                # Get the corresponding key from the response or its mapped key

                response_key = response.get(cased_key)

                if response_key is not None:
                    new_dict[key] = value_type(response_key)
                else:
                    # Handle missing keys by assigning default values
                    default_value = get_default_value(value_type)
                    new_dict[key] = default_value

                if value_type == list and response_key:
                    logger.writeDebug(f"20250324 key: {key}")
                    logger.writeDebug(f"20250324 response_key: {response_key}")
                    new_dict[key] = self.process_list(response_key)
                    logger.writeDebug(f"20250324 new_dict[key]: {new_dict[key]}")

            if new_dict.get("pvol_host_groups"):
                self.split_host_groups(
                    new_dict["pvol_host_groups"],
                    new_dict,
                    "pvolHostGroups",
                    port_type_dict,
                )
                # del new_dict["pvolHostGroups"]
            if new_dict.get("svol_host_groups"):
                self.split_host_groups(
                    new_dict["svol_host_groups"],
                    new_dict,
                    "svolHostGroups",
                    port_type_dict,
                )
                # del new_dict["svolHostGroups"]
            if new_dict.get("primary_volume_id_hex") == "":
                new_dict["primary_volume_id_hex"] = volume_id_to_hex_format(
                    new_dict.get("primary_volume_id")
                )
            if new_dict.get("secondary_volume_id_hex") == "":
                new_dict["secondary_volume_id_hex"] = volume_id_to_hex_format(
                    new_dict.get("secondary_volume_id")
                )
            new_items.append(new_dict)
        return new_items

    def split_host_groups(self, items, new_dict, key, port_type_dict):
        logger = Log()
        logger.writeDebug(f"20250324 key: {key}")
        logger.writeDebug(f"20250324 items: {items}")
        if items is None:
            return

        its = []
        hgs = []
        for item in items:
            if item is None:
                continue
            # logger.writeDebug(f"20250324 item: {item}")
            port_id = item["port_id"]
            port_type = port_type_dict[port_id]
            logger.writeDebug(f"20250324 port_id: {port_id}")
            logger.writeDebug(f"20250324 port_type: {port_type}")
            if port_type == "ISCSI":
                its.append(item)
            else:
                hgs.append(item)
            # if self.port_type_dict[item[]]
            # new_dict["pvol_host_groups"] = items
            # new_dict["pvol_iscsi_targets"] = items

        if key == "pvolHostGroups":
            new_dict["pvol_iscsi_targets"] = its
            new_dict["pvol_host_groups"] = hgs
        else:
            new_dict["svol_iscsi_targets"] = its
            new_dict["svol_host_groups"] = hgs

        return

    def extract_object(self, response):

        new_dict = {"storage_serial_number": self.serial}
        for key, value_type in self.common_properties.items():
            # Assign the value based on the response key and its data type
            cased_key = snake_to_camel_case(key)
            # Get the corresponding key from the response or its mapped key
            response_key = response.get(cased_key)

            if response_key is not None:
                new_dict[key] = value_type(response_key)
            else:
                # Handle missing keys by assigning default values
                default_value = get_default_value(value_type)
                new_dict[key] = default_value

        if new_dict.get("primary_volume_id_hex") == "":
            new_dict["primary_volume_id_hex"] = volume_id_to_hex_format(
                new_dict.get("primary_volume_id")
            )
        if new_dict.get("secondary_volume_id_hex") == "":
            new_dict["secondary_volume_id_hex"] = volume_id_to_hex_format(
                new_dict.get("secondary_volume_id")
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
            new_items.append(new_dict)
        return new_items
