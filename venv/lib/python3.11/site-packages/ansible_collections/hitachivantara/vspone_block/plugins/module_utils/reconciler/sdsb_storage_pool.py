from typing import Any

try:
    from ..provisioner.sdsb_storage_pool_provisioner import SDSBStoragePoolProvisioner
    from ..common.hv_constants import StateValue
    from ..common.hv_log import Log
    from ..common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
    )
    from ..message.sdsb_storage_pool_msgs import SDSBStoragePoolValidationMsg
except ImportError:
    from provisioner.sdsb_storage_pool_provisioner import SDSBStoragePoolProvisioner
    from common.hv_log import Log
    from common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
    )
    from message.sdsb_storage_pool_msgs import SDSBStoragePoolValidationMsg

logger = Log()


class SDSBStoragePoolReconciler:

    def __init__(self, connection_info, state=None):
        self.connection_info = connection_info
        self.provisioner = SDSBStoragePoolProvisioner(self.connection_info)
        self.state = state

    @log_entry_exit
    def get_storage_pools(self, spec=None):
        try:
            extracted_data = None
            if spec is None:
                s_pools = self.provisioner.get_storage_pools()
                logger.writeDebug("RC:get_storage_pools:s_pools={}", s_pools)
                extracted_data = SDSBStoragePoolExtractor().extract(
                    s_pools.data_to_list()
                )
                return extracted_data
            else:
                if spec.id:
                    s_pool = self.provisioner.get_storage_pool_by_id(spec.id)
                    logger.writeDebug("RC:get_storage_pools:s_pool={}", s_pool)
                    extracted_data = SDSBStoragePoolExtractor().extract(
                        [s_pool.to_dict()]
                    )
                else:
                    if spec.names:
                        s_pools = self.provisioner.get_storage_pools(spec.names)
                        logger.writeDebug("RC:get_storage_pools:s_pools={}", s_pools)
                        extracted_data = SDSBStoragePoolExtractor().extract(
                            s_pools.data_to_list()
                        )

                logger.writeDebug(
                    "RC:get_storage_pools:extracted_data={}", extracted_data
                )
                return extracted_data
        except Exception as e:
            if "HTTP Error 404: Not Found" in str(e):
                raise ValueError(SDSBStoragePoolValidationMsg.WRONG_POOL_ID.value)
            else:
                raise Exception(e)

    @log_entry_exit
    def reconcile_storage_pool(self, spec: Any) -> Any:
        state = self.state.lower()

        resp_data = None
        if state == StateValue.PRESENT:
            resp_data = self.edit_storage_pool_settings(spec=spec)
        elif state == StateValue.EXPAND:
            resp_data = self.expand_storage_pool(spec=spec)

        if resp_data:
            s_pool = self.provisioner.get_storage_pool_by_id(resp_data)
            logger.writeDebug("RC:expand_storage_pool:s_pool={}", s_pool)
            extracted_data = SDSBStoragePoolExtractor().extract([s_pool.to_dict()])
            return extracted_data
        else:
            return None

    @log_entry_exit
    def edit_storage_pool_settings(self, spec):

        if spec.id is None:
            pool = self.provisioner.get_pool_by_pool_name(spec.name)
            if pool:
                spec.id = pool.id
            logger.writeDebug("RC:edit_storage_pool_settings:spec.id={} ", spec.id)
        else:
            try:
                pool = self.provisioner.get_storage_pool_by_id(spec.id)
            except Exception as e:
                if "HTTP Error 404: Not Found" in str(e):
                    raise ValueError(SDSBStoragePoolValidationMsg.WRONG_POOL_ID.value)
                else:
                    raise Exception(e)
        if spec.id is None:
            raise ValueError(
                SDSBStoragePoolValidationMsg.STORAGE_POOL_NOT_FOUND.value.format(
                    spec.name
                )
            )
        if not self.is_edit_pool_needed(pool, spec):
            return pool.id

        # Handle encryption settings separately if specified
        if spec.is_encryption_enabled is not None:
            self.provisioner.update_storage_pool_encryption(
                spec.id, spec.is_encryption_enabled
            )
            self.connection_info.changed = True

        if (
            spec.rebuild_capacity_policy is not None
            or spec.number_of_tolerable_drive_failures is not None
        ):
            unused = self.provisioner.edit_storage_pool_settings(
                spec.id,
                spec.rebuild_capacity_policy,
                spec.number_of_tolerable_drive_failures,
            )
            self.connection_info.changed = True
        return spec.id

    @log_entry_exit
    def is_edit_pool_needed(self, pool, spec):
        changed = False
        if spec.rebuild_capacity_policy != pool.rebuildCapacityPolicy:
            changed = True
        if (
            spec.number_of_tolerable_drive_failures
            != pool.rebuildCapacityResourceSetting["numberOfTolerableDriveFailures"]
        ):
            changed = True
        return changed

    @log_entry_exit
    def expand_storage_pool(self, spec):
        self.validate_expand_spec(spec)
        if spec.id is None:
            spec.id = self.provisioner.get_pool_id_by_pool_name(spec.name)
            logger.writeDebug("RC:expand_storage_pool:spec.id={} ", spec.id)
        else:
            try:
                pool = self.provisioner.get_storage_pool_by_id(spec.id)
            except Exception as e:
                if "HTTP Error 404: Not Found" in str(e):
                    raise ValueError(SDSBStoragePoolValidationMsg.WRONG_POOL_ID.value)
                else:
                    raise Exception(e)
        if spec.id is None:
            raise ValueError(
                SDSBStoragePoolValidationMsg.STORAGE_POOL_NOT_FOUND.value.format(
                    spec.name
                )
            )
        resp = self.provisioner.expand_storage_pool(spec.id, spec.drive_ids)
        self.connection_info.changed = True
        return resp

    @log_entry_exit
    def validate_expand_spec(self, spec: Any) -> None:
        if spec.drive_ids is None or len(spec.drive_ids) == 0:
            raise ValueError(
                SDSBStoragePoolValidationMsg.DRIVE_IDS_REQD_FOR_EXPAND.value
            )


class SDSBStoragePoolExtractor:
    def __init__(self):
        self.common_properties = {
            "id": str,
            "name": str,
            "protectionDomainId": str,
            "statusSummary": str,
            "status": str,
            "totalCapacity": int,
            "totalRawCapacity": int,
            "usedCapacity": int,
            "freeCapacity": int,
            "totalPhysicalCapacity": int,
            "metaDataPhysicalCapacity": int,
            "reservedPhysicalCapacity": int,
            "usablePhysicalCapacity": int,
            "blockedPhysicalCapacity": int,
            "capacityManage": dict,
            "savingEffects": dict,
            "numberOfVolumes": int,
            "redundantPolicy": str,
            "redundantType": str,
            "dataRedundancy": int,
            "storageControllerCapacitiesGeneralStatus": str,
            "totalVolumeCapacity": int,
            "provisionedVolumeCapacity": int,
            "otherVolumeCapacity": int,
            "temporaryVolumeCapacity": int,
            "rebuildCapacityPolicy": str,
            "rebuildCapacityResourceSetting": dict,
            "rebuildCapacityStatus": str,
            "rebuildableResources": dict,
            "encryptionStatus": str,
        }
        self.parameter_mapping = {
            "total_capacity": "total_capacity_mb",
            "total_raw_capacity": "total_raw_capacity_mb",
            "used_capacity": "used_capacity_mb",
            "free_capacity": "free_capacity_mb",
            "total_physical_capacity": "total_physical_capacity_mb",
            "meta_data_physical_capacity": "meta_data_physical_capacity_mb",
            "reserved_physical_capacity": "reserved_physical_capacity_mb",
            "usable_physical_capacity": "usable_physical_capacity_mb",
            "blocked_physical_capacity": "blocked_physical_capacity_mb",
            "total_volume_capacity": "total_volume_capacity_mb",
            "provisioned_volume_capacity": "provisioned_volume_capacity_mb",
            "other_volume_capacity": "other_volume_capacity_mb",
            "temporary_volume_capacity": "temporary_volume_capacity_mb",
        }

    def process_list(self, response_key):
        new_items = []

        if response_key is None:
            return []
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

    def process_dict(self, response_key):

        if response_key is None:
            return {}

        new_dict = {}
        for key in response_key.keys():
            value = response_key.get(key, None)
            key = camel_to_snake_case(key)

            if value is None:
                # default_value = get_default_value(value_type)
                # value = default_value
                continue
            new_dict[key] = value

        return new_dict

    def extract(self, responses):
        new_items = []

        for response in responses:
            new_dict = {}
            for key, value_type in self.common_properties.items():
                # Get the corresponding key from the response or its mapped key
                response_key = response.get(key)
                # logger.writeDebug("RC:extract:value_type={}", value_type)
                if value_type == list[dict]:
                    response_key = self.process_list(response_key)
                if value_type == dict:
                    response_key = self.process_dict(response_key)
                # Assign the value based on the response key and its data type
                cased_key = camel_to_snake_case(key)
                if cased_key in self.parameter_mapping.keys():
                    cased_key = self.parameter_mapping[cased_key]
                if response_key is not None:
                    new_dict[cased_key] = value_type(response_key)
                else:
                    pass
                    # DO NOT HANDLE MISSING KEYS
                    # Handle missing keys by assigning default values
                    # default_value = get_default_value(value_type)
                    # new_dict[cased_key] = default_value
            new_items.append(new_dict)
        return new_items
