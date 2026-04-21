from typing import Any

try:
    from ..common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
    )
    from ..common.hv_log import Log
    from ..common.hv_constants import StateValue
    from ..provisioner.vsp_user_provisioner import VSPUserProvisioner
    from ..message.vsp_user_msgs import VSPUserFailedMsg, VSPUserValidateMsg


except ImportError:
    from common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
    )
    from common.hv_log import Log
    from common.hv_constants import StateValue
    from provisioner.vsp_user_provisioner import VSPUserProvisioner
    from message.vsp_user_msgs import VSPUserFailedMsg, VSPUserValidateMsg

logger = Log()


class VSPUserReconciler:
    def __init__(self, connection_info, serial=None, state=None):

        self.connection_info = connection_info
        self.provisioner = VSPUserProvisioner(connection_info, serial)
        if state:
            self.state = state
        if serial:
            self.storage_serial_number = serial

    @log_entry_exit
    def get_user_facts(self, spec):
        users = self.provisioner.get_users(spec)
        logger.writeDebug("RC:users={}", users)
        if users is None or not users.data_to_list():
            return []
        extracted_data = UserInfoExtractor().extract(users.data_to_list())
        return extracted_data

    @log_entry_exit
    def reconcile_user(self, spec):

        if self.state == StateValue.PRESENT:
            user = None
            comment = None
            if spec.id:
                user, comment = self.get_user_by_id(spec.id)
                if user is None:
                    err_msg = VSPUserValidateMsg.USER_NOT_FOUND.value
                    if comment:
                        err_msg = err_msg + comment
                    return None, comment
            else:
                if spec.name:
                    user = self.provisioner.get_user_by_name(spec.name)
            self.provisioner.spec = spec

            user_id = None
            if not user:
                user_id = self.create_user(spec)
            else:
                user_id, comment = self.update_user(user, spec)

            if user_id is None:
                return None, comment

            user = self.provisioner.get_user_by_id(user_id)
            extracted_data = UserInfoExtractor().extract([user.to_dict()])
            return extracted_data, comment
        elif self.state == StateValue.ABSENT:
            if spec.id:
                user, comment = self.get_user_by_id(spec.id)
                if user is None:
                    err_msg = VSPUserValidateMsg.USER_NOT_FOUND.value
                    if comment:
                        err_msg = err_msg + comment
                    return None, comment
            else:
                if spec.name:
                    user = self.provisioner.get_user_by_name(spec.name)
            if not user:
                return None, VSPUserValidateMsg.USER_NOT_FOUND.value
            logger.writeDebug("RC:reconcile_user:state=absent:user={}", user)
            comment = self.delete_user(user, spec)
            return None, comment

    @log_entry_exit
    def get_user_by_id(self, id):
        try:
            user = self.provisioner.get_user_by_id(id)
            return user, None
        except Exception as e:
            err_msg = str(e)
            logger.writeError(err_msg)
            return None, err_msg

    @log_entry_exit
    def create_user(self, spec):
        self.validate_create_spec(spec)
        user_id = self.provisioner.create_user(spec)
        logger.writeDebug("RC:create_user:user_id={}", user_id)
        return user_id

    @log_entry_exit
    def update_user(self, user, spec):
        try:
            user_id = self.provisioner.update_user(user, spec)
            logger.writeDebug("RC:update_user:user_id={}", user_id)
            return user_id, None
        except Exception as e:
            if "error code = 30662-200156" in str(e):
                err_msg = (
                    VSPUserFailedMsg.UPDATE_FAILED.value
                    + VSPUserValidateMsg.PASSWORD_SAME.value
                )
            else:
                err_msg = VSPUserFailedMsg.UPDATE_FAILED.value + str(e)
            logger.writeError(err_msg)
            return None, err_msg

    @log_entry_exit
    def delete_user(self, user, spec):
        try:
            ret_value = self.provisioner.delete_user(user, spec)
            logger.writeDebug("RC:delete_user:ret_value={}", ret_value)
            return VSPUserValidateMsg.USER_DELETE_SUCCSESS.value
        except Exception as e:
            err_msg = VSPUserFailedMsg.DELETE_FAILED.value + str(e)
            logger.writeError(err_msg)
            return err_msg

    @log_entry_exit
    def validate_create_spec(self, spec: Any) -> None:
        if not spec.name:
            raise ValueError(VSPUserValidateMsg.USER_NAME_REQD.value)
        if not spec.authentication:
            raise ValueError(VSPUserValidateMsg.AUTH_REQD.value)
        if spec.authentication == "local" and not spec.password:
            raise ValueError(VSPUserValidateMsg.PASS_REQD.value)
        if not isinstance(spec.group_names, list):
            raise ValueError(VSPUserValidateMsg.GROUP_NAME_MUST_BE_LIST.value)
        return None


class UserInfoExtractor:
    def __init__(self):
        self.common_properties = {
            "userObjectId": str,
            "userId": str,
            "authentication": str,
            "userGroupNames": list[str],
            "isBuiltIn": bool,
            "isAccountStatus": bool,
        }
        self.parameter_mapping = {
            "user_id": "name",
            "user_object_id": "id",
            "user_storage_port": "group_names",
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
