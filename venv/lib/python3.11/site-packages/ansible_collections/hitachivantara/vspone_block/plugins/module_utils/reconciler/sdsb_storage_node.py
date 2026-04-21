from typing import Any

try:
    from ..provisioner.sdsb_storage_node_provisioner import SDSBStorageNodeProvisioner
    from ..common.hv_constants import StateValue
    from ..common.hv_log import Log
    from ..common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
    )
    from ..message.sdsb_storage_node_msgs import SDSBStorageNodeValidationMsg
    from ..model.sdsb_storage_node_models import SDSBStorageNodeInfo
except ImportError:
    from provisioner.sdsb_storage_node_provisioner import SDSBStorageNodeProvisioner
    from common.hv_log import Log
    from common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
    )
    from message.sdsb_storage_node_msgs import SDSBStorageNodeValidationMsg
    from model.sdsb_storage_node_models import SDSBStorageNodeInfo

logger = Log()


class SDSBStorageNodeReconciler:

    def __init__(self, connection_info, state=None):
        self.connection_info = connection_info
        self.provisioner = SDSBStorageNodeProvisioner(self.connection_info)
        self.state = state

    @log_entry_exit
    def get_storage_nodes(self, spec=None):
        try:
            snodes = self.provisioner.get_storage_nodes(spec)
            logger.writeDebug("RC:get_storage_nodes:cnodes={}", snodes)
            if isinstance(snodes, SDSBStorageNodeInfo):
                extracted_data = SDSBStorageNodeExtractor().extract([snodes.to_dict()])
            else:
                extracted_data = SDSBStorageNodeExtractor().extract(
                    snodes.data_to_list()
                )
            return extracted_data
        except Exception as e:
            if "HTTP Error 400: Bad Request" in str(e):
                raise ValueError(SDSBStorageNodeValidationMsg.BAD_ENTRY.value)

    @log_entry_exit
    def reconcile_storage_node(self, spec: Any) -> Any:
        state = self.state.lower()

        resp_data = None
        if state == StateValue.PRESENT:
            resp_data = self.edit_capacity_management_settings(spec=spec)
        elif state == StateValue.MAINTENANCE:
            resp_data = self.block_node_for_maintenance(spec=spec)
        elif state == StateValue.RESTORE:
            resp_data = self.restore_from_maintenance(spec=spec)
        if resp_data:
            s_node = self.provisioner.get_storage_node_by_id(resp_data)
            extracted_data = SDSBStorageNodeExtractor().extract([s_node.to_dict()])
            return extracted_data

    @log_entry_exit
    def edit_capacity_management_settings(self, spec):
        self.validate_operation_spec(spec)
        node = None
        if spec.id is None:
            spec.id = self.provisioner.get_node_id_by_node_name(spec.name)
            logger.writeDebug(
                "RC:edit_capacity_management_settings:spec.id={} ", spec.id
            )
        else:
            try:
                node = self.provisioner.get_storage_node_by_id(spec.id)
            except Exception as e:
                if "HTTP Error 404: Not Found" in str(e):
                    raise ValueError(SDSBStorageNodeValidationMsg.WRONG_NODE_ID.value)
                else:
                    raise Exception(e)

        if spec.id is None:
            raise ValueError(
                SDSBStorageNodeValidationMsg.STORAGE_NODE_NOT_FOUND.value.format(
                    spec.name
                )
            )

        if spec.is_capacity_balancing_enabled is None:
            return spec.id
        if (
            node
            and node.is_capacity_balancing_enabled == spec.is_capacity_balancing_enabled
        ):
            return spec.id

        resp = self.provisioner.edit_capacity_management_settings(
            spec.id, spec.is_capacity_balancing_enabled
        )
        logger.writeDebug("RC:edit_capacity_management_settings:resp={}", resp)
        self.connection_info.changed = True
        return resp

    @log_entry_exit
    def block_node_for_maintenance(self, spec):
        self.validate_operation_spec(spec)
        if spec.id is None:
            spec.id = self.provisioner.get_node_id_by_node_name(spec.name)
            logger.writeDebug("RC:block_node_for_maintenance:spec.id={} ", spec.id)
        else:
            try:
                node = self.provisioner.get_storage_node_by_id(spec.id)
            except Exception as e:
                if "HTTP Error 404: Not Found" in str(e):
                    raise ValueError(SDSBStorageNodeValidationMsg.WRONG_NODE_ID.value)
                else:
                    raise Exception(e)
        if spec.id is None:
            raise ValueError(
                SDSBStorageNodeValidationMsg.STORAGE_NODE_NOT_FOUND.value.format(
                    spec.name
                )
            )

        resp = self.provisioner.block_node_for_maintenance(spec.id)
        logger.writeDebug("RC:block_node_for_maintenance:resp={}", resp)
        self.connection_info.changed = True
        return resp

    @log_entry_exit
    def restore_from_maintenance(self, spec):
        self.validate_operation_spec(spec)
        if spec.id is None:
            spec.id = self.provisioner.get_node_id_by_node_name(spec.name)
            logger.writeDebug("RC:block_node_for_maintenance:spec.id={} ", spec.id)
        else:
            try:
                node = self.provisioner.get_storage_node_by_id(spec.id)
            except Exception as e:
                if "HTTP Error 404: Not Found" in str(e):
                    raise ValueError(SDSBStorageNodeValidationMsg.WRONG_NODE_ID.value)
                else:
                    raise Exception(e)
        if spec.id is None:
            raise ValueError(
                SDSBStorageNodeValidationMsg.STORAGE_NODE_NOT_FOUND.value.format(
                    spec.name
                )
            )
        resp = self.provisioner.restore_from_maintenance(spec.id)
        logger.writeDebug("RC:restore_from_maintenance:resp={}", resp)
        self.connection_info.changed = True
        return resp

    @log_entry_exit
    def validate_operation_spec(self, spec: Any) -> None:
        if spec.name is None and spec.id is None:
            raise ValueError(SDSBStorageNodeValidationMsg.BOTH_ID_AND_NAME_NONE.value)


class SDSBStorageNodeExtractor:
    def __init__(self):
        self.common_properties = {
            "id": str,
            "biosUuid": str,
            "protectionDomainId": str,
            "faultDomainId": str,
            "faultDomainName": str,
            "name": str,
            "clusterRole": str,
            "storageNodeAttributes": list,
            "statusSummary": str,
            "status": str,
            "driveDataRelocationStatus": str,
            "controlPortIpv4Address": str,
            "internodePortIpv4Address": str,
            "softwareVersion": str,
            "modelName": str,
            "serialNumber": str,
            "memory": int,
            "insufficientResourcesForRebuildCapacity": dict,
            "rebuildableResources": dict,
            "availabilityZoneId": str,
            "physicalZone": str,
            "logicalZone": str,
            "is_capacity_balancing_enabled": bool,
            "isStorageMasterNodePrimary": bool,
        }
        self.parameter_mapping = {
            "memory": "memory_mb",
            # "user_object_id": "id",
            # "user_storage_port": "group_names",
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
