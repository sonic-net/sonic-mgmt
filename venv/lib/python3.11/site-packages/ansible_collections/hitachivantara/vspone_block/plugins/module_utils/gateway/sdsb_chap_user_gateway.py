try:
    from ..common.sdsb_constants import SDSBlockEndpoints
    from ..common.ansible_common import dicts_to_dataclass_list
    from ..model.sdsb_chap_user_models import (
        SDSBChapUsersInfo,
        SDSBChapUserInfo,
        SDSBChapUserDetailInfo,
    )
    from .gateway_manager import SDSBConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit

except ImportError:
    from common.sdsb_constants import SDSBlockEndpoints
    from common.ansible_common import dicts_to_dataclass_list
    from model.sdsb_chap_user_models import (
        SDSBChapUsersInfo,
        SDSBChapUserInfo,
        SDSBChapUserDetailInfo,
    )
    from .gateway_manager import SDSBConnectionManager
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit

logger = Log()


class SDSBChapUserDirectGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_chap_users(self, spec=None):

        end_point = SDSBlockEndpoints.GET_CHAP_USERS

        if spec is not None and spec.target_chap_user_name is not None:
            end_point = SDSBlockEndpoints.GET_CHAP_USERS_AND_QUERY.format(
                spec.target_chap_user_name
            )
            logger.writeDebug("GW:get_chap_users:end_point={}", end_point)

        chap_user_data = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_chap_users:data={}", chap_user_data)
        return SDSBChapUsersInfo(
            dicts_to_dataclass_list(chap_user_data["data"], SDSBChapUserInfo)
        )

    @log_entry_exit
    def get_chap_user_by_id(self, id):
        try:
            end_point = SDSBlockEndpoints.GET_CHAP_USER_BY_ID.format(id)
            data = self.connection_manager.get(end_point)
            logger.writeDebug("GW:get_chap_user_by_id:data={}", data)
            return SDSBChapUserDetailInfo(**data)
        except Exception as ex:
            logger.writeDebug("GW:get_chap_user_by_id:=Exception{}", ex)
            return None

    @log_entry_exit
    def get_chap_user_by_name(self, name):
        end_point = SDSBlockEndpoints.GET_CHAP_USERS_AND_QUERY.format(name)
        data = self.connection_manager.get(end_point)
        logger.writeDebug(
            "GW:get_chap_user_by_name:data={} len={}", data, len(data.get("data"))
        )
        if data is not None and len(data.get("data")) > 0:
            return SDSBChapUserInfo(**data.get("data")[0])
        else:
            return None

    @log_entry_exit
    def delete_chap_user_by_id(self, id):
        try:
            end_point = SDSBlockEndpoints.DELETE_CHAP_USERS.format(id)
            data = self.connection_manager.delete(end_point)
            return data
        except Exception as ex:
            logger.writeDebug("GW:delete_chap_user_by_id:=Exception{}", ex)
            return None

    @log_entry_exit
    def create_chap_user(self, spec):
        end_point = SDSBlockEndpoints.POST_CHAP_USERS
        payload = {
            "targetChapUserName": spec.target_chap_user_name,
            "targetChapSecret": spec.target_chap_secret,
        }
        if spec.initiator_chap_user_name and spec.initiator_chap_secret:
            payload["initiatorChapUserName"] = spec.initiator_chap_user_name
            payload["initiatorChapSecret"] = spec.initiator_chap_secret

        return self.connection_manager.post(end_point, payload)

    @log_entry_exit
    def update_chap_user(self, spec):
        end_point = SDSBlockEndpoints.PATCH_CHAP_USERS.format(spec.id)
        payload = {
            "targetChapUserName": spec.target_chap_user_name,
            "targetChapSecret": spec.target_chap_secret,
        }
        if spec.initiator_chap_user_name and spec.initiator_chap_secret:
            payload["initiatorChapUserName"] = spec.initiator_chap_user_name
            payload["initiatorChapSecret"] = spec.initiator_chap_secret

        return self.connection_manager.patch(end_point, payload)
