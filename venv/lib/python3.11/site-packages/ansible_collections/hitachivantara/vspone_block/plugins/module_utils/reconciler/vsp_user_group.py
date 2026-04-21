from typing import Any

try:
    from ..common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
    )
    from ..common.hv_log import Log
    from ..common.hv_constants import StateValue
    from ..provisioner.vsp_user_group_provisioner import VSPUserGroupProvisioner
    from ..message.vsp_user_group_msgs import (
        VSPUserGroupFailedMsg,
        VSPUserGroupValidateMsg,
    )


except ImportError:
    from common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
    )
    from common.hv_log import Log
    from common.hv_constants import StateValue
    from provisioner.vsp_user_group_provisioner import VSPUserGroupProvisioner
    from message.vsp_user_group_msgs import (
        VSPUserGroupFailedMsg,
        VSPUserGroupValidateMsg,
    )

logger = Log()


class VSPUserGroupReconciler:
    def __init__(self, connection_info, serial=None, state=None):

        self.connection_info = connection_info
        self.provisioner = VSPUserGroupProvisioner(connection_info, serial)
        if state:
            self.state = state
        if serial:
            self.storage_serial_number = serial

    @log_entry_exit
    def get_user_group_facts(self, spec):
        user_groups = self.provisioner.get_user_groups(spec)
        logger.writeDebug("RC:user_groups={}", user_groups)
        if user_groups is None or not user_groups.data_to_list():
            return []
        extracted_data = UserGroupInfoExtractor().extract(user_groups.data_to_list())
        return extracted_data

    @log_entry_exit
    def reconcile_user_group(self, spec):

        if self.state == StateValue.PRESENT:
            user_group = None
            comment = None
            if spec.id:
                user_group, comment = self.get_user_group_by_id(spec.id)
                if user_group is None:
                    err_msg = VSPUserGroupValidateMsg.USER_GROUP_NOT_FOUND.value
                    if comment:
                        err_msg = err_msg + comment
                    return None, comment
            else:
                if spec.name:
                    user_group = self.provisioner.get_user_group_by_name(spec.name)
            self.provisioner.spec = spec

            user_group_id = None
            if not user_group:
                user_group_id = self.create_user_group(spec)
            else:
                user_group_id, comment = self.update_user_group(user_group, spec)
                if user_group_id is None:
                    if comment:
                        return None, comment
            if user_group_id:
                user_group = self.provisioner.get_user_group_by_id(user_group_id)
            extracted_data = UserGroupInfoExtractor().extract([user_group.to_dict()])
            return extracted_data, None
        elif self.state == StateValue.ABSENT:
            if spec.id:
                user_group, comment = self.get_user_group_by_id(spec.id)
                if user_group is None:
                    err_msg = VSPUserGroupValidateMsg.USER_GROUP_NOT_FOUND.value
                    if comment:
                        err_msg = err_msg + comment
                    return None, comment
            else:
                if spec.name:
                    user_group = self.provisioner.get_user_group_by_name(spec.name)
            if not user_group:
                return None, VSPUserGroupValidateMsg.USER_GROUP_NOT_FOUND.value
            logger.writeDebug(
                "RC:reconcile_user:state=absent:user_group={}", user_group
            )
            comment = self.delete_user_group(user_group, spec)
            return None, comment

    @log_entry_exit
    def get_user_group_by_id(self, id):
        try:
            user_group = self.provisioner.get_user_group_by_id(id)
            return user_group, None
        except Exception as e:
            err_msg = str(e)
            logger.writeError(err_msg)
            return None, err_msg

    @log_entry_exit
    def create_user_group(self, spec):
        self.validate_create_spec(spec)
        user_group_id = self.provisioner.create_user_group(spec)
        logger.writeDebug("RC:create_user_group:user_group_id={}", user_group_id)
        return user_group_id

    @log_entry_exit
    def update_user_group(self, user_group, spec):
        self.validate_update_spec(spec)
        try:
            user_group_id = self.provisioner.update_user_group(user_group, spec)
            logger.writeDebug("RC:update_user_group:user_group_id={}", user_group_id)
            return user_group_id, None
        except Exception as e:
            err_msg = VSPUserGroupFailedMsg.UPDATE_FAILED.value + str(e)
            logger.writeError(err_msg)
            return None, err_msg

    @log_entry_exit
    def delete_user_group(self, user, spec):
        try:
            ret_value = self.provisioner.delete_user_group(user, spec)
            logger.writeDebug("RC:delete_user_group:ret_value={}", ret_value)
            return VSPUserGroupValidateMsg.USER_GROUP_DELETE_SUCCSESS.value
        except Exception as e:
            err_msg = VSPUserGroupFailedMsg.DELETE_FAILED.value + str(e)
            logger.writeError(err_msg)
            return err_msg

    @log_entry_exit
    def validate_create_spec(self, spec: Any) -> None:
        if not spec.name:
            raise ValueError(VSPUserGroupValidateMsg.USER_GROUP_NAME_REQD.value)
        if spec.role_names and not isinstance(spec.role_names, list):
            raise ValueError(VSPUserGroupValidateMsg.ROLE_NAME_MUST_BE_LIST.value)
        if spec.resource_group_ids and not isinstance(spec.resource_group_ids, list):
            raise ValueError(VSPUserGroupValidateMsg.RG_NAME_MUST_BE_LIST.value)

        return None

    @log_entry_exit
    def validate_update_spec(self, spec: Any) -> None:
        if spec.resource_group_ids and not isinstance(spec.resource_group_ids, list):
            raise ValueError(VSPUserGroupValidateMsg.RG_NAME_MUST_BE_LIST.value)

        return None


class UserGroupInfoExtractor:
    def __init__(self):
        self.common_properties = {
            "userGroupObjectId": str,
            "userGroupId": str,
            "roleNames": list[str],
            "resourceGroupIds": list[int],
            "isBuiltIn": bool,
            "hasAllResourceGroup": bool,
            "users": list[str],
        }
        self.parameter_mapping = {
            "user_group_id": "name",
            "user_group_object_id": "id",
        }

    def process_list(self, response_key):
        new_items = []

        if response_key is None:
            return []
        logger.writeDebug("RC:process_list:response_key={}", response_key)
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
        # new_dict = {"storage_serial_number": self.storage_serial_number}
        # new_items.append(new_dict)
        for response in responses:
            new_dict = {}
            for key, value_type in self.common_properties.items():
                # Get the corresponding key from the response or its mapped key
                response_key = response.get(key)
                # logger.writeDebug("RC:extract:value_type={}", value_type)
                if value_type == list[dict]:
                    response_key = self.process_list(response_key)
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
