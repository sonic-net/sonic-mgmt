try:
    from ..common.ansible_common import (
        log_entry_exit,
        snake_to_camel_case,
        get_response_key,
        get_default_value,
    )
    from ..common.hv_log import Log
    from ..common.hv_constants import StateValue
    from ..model.vsp_parity_group_models import ParityGroupSpec
    from ..provisioner.vsp_parity_group_provisioner import VSPParityGroupProvisioner
except ImportError:
    from common.ansible_common import (
        log_entry_exit,
        snake_to_camel_case,
        get_response_key,
        get_default_value,
    )
    from provisioner.vsp_parity_group_provisioner import VSPParityGroupProvisioner
    from common.hv_log import Log
    from common.hv_constants import StateValue
    from model.vsp_parity_group_models import ParityGroupSpec

logger = Log()


class VSPParityGroupReconciler:

    def __init__(self, connectionInfo, state=None):
        self.logger = Log()
        self.connectionInfo = connectionInfo
        self.state = state
        self.provisioner = VSPParityGroupProvisioner(self.connectionInfo)

    @log_entry_exit
    def parity_group_reconcile(self, state: str, spec: ParityGroupSpec):
        # reconcile the parity group based on the desired state in the specification
        state = state.lower()
        if state == StateValue.ABSENT:
            return self.provisioner.delete_parity_group(spec)
        elif state == StateValue.PRESENT:
            return self.provisioner.create_parity_group(spec)
        elif state == StateValue.UPDATE:
            return self.provisioner.update_parity_group(spec)
        elif state == StateValue.ASSIGN_CLPR_ID:
            return self.provisioner.assign_parity_group_to_clpr(spec)

    @log_entry_exit
    def get_all_parity_groups(self):
        return self.provisioner.get_all_parity_groups()

    @log_entry_exit
    def get_parity_group(self, pg_id):
        return self.provisioner.get_parity_group(pg_id)

    @log_entry_exit
    def get_all_drives(self, spec):
        if spec and spec.drive_location_id is not None:
            return self.provisioner.get_one_drive(spec)
        else:
            return self.provisioner.get_all_drives()


class VSPParityGroupCommonPropertiesExtractor:
    def __init__(self):
        self.common_properties = {
            # "resource_id": str,
            "parity_group_id": str,
            "free_capacity": str,
            "freeCapacity_mb": float,
            "resource_group_id": int,
            "total_capacity": str,
            "totalCapacity_mb": float,
            "ldev_ids": list,
            "raid_level": str,
            "drive_type": str,
            "copyback_mode": bool,
            # "status": str,
            "is_pool_array_group": bool,
            "is_accelerated_compression": bool,
            "is_encryption_enabled": bool,
            "clpr_id": int,
        }

    @log_entry_exit
    def extract_parity_group(self, response):
        new_dict = {}
        for key, value_type in self.common_properties.items():
            cased_key = snake_to_camel_case(key)
            # Get the corresponding key from the response or its mapped key
            response_key = get_response_key(response, cased_key, key)

            # Assign the value based on the response key and its data type
            if response_key is not None:
                if key == "ldev_ids":
                    tmp_ldev_ids = []
                    for ldev_id in response_key:
                        if ldev_id is None:
                            tmp_ldev_ids.append(-1)
                        else:
                            tmp_ldev_ids.append(ldev_id)
                    new_dict[key] = value_type(tmp_ldev_ids)
                else:
                    new_dict[key] = value_type(response_key)
            else:
                # Handle for case of None response_key or missing keys by assigning default values
                default_value = get_default_value(value_type)
                new_dict[key] = default_value
        return new_dict

    @log_entry_exit
    def extract_all_parity_groups(self, responses):
        new_items = []
        for response in responses:
            new_dict = self.extract_parity_group(response)
            new_items.append(new_dict)
        return new_items
