try:
    from .gateway_manager import SDSBConnectionManager
    from ..common.ansible_common import log_entry_exit
    from ..common.hv_log import Log
    from ..model.sdsb_session_models import (
        SessionResponse,
        SessionResponseList,
    )
except ImportError:
    from .gateway_manager import SDSBConnectionManager
    from common.ansible_common import log_entry_exit
    from common.hv_log import Log
    from model.sdsb_session_models import (
        SessionResponse,
        SessionResponseList,
    )
logger = Log()

GET_SESSIONS = "v1/objects/sessions"
CREATE_SESSION = "v1/objects/sessions"
DELTE_SESSION = "v1/objects/sessions/{}"
GET_SESSION_BY_ID = "v1/objects/sessions/{}"


class SDSBSessionGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_sessions(self, vps_id=None, user_id=None):
        end_point = GET_SESSIONS
        query = []
        if vps_id:
            query.append(f"vpsId={vps_id}")
        if user_id:
            query.append(f"userId={user_id}")
        if query:
            end_point += "?" + "&".join(query)
        response = self.connection_manager.get(end_point)
        return SessionResponseList().dump_to_object(response)

    @log_entry_exit
    def get_session_by_id(self, id):
        try:
            end_point = GET_SESSION_BY_ID.format(id)
            data = self.connection_manager.get(end_point)
            logger.writeDebug("GW:get_session_by_id:data={}", data)
            return SessionResponse(**data)
        except Exception as ex:
            logger.writeDebug("GW:get_session_by_id:=Exception{}", ex)
            return None

    @log_entry_exit
    def create_session(self, alive_time=None):
        if alive_time is None:
            alive_time = 300
        payload = {"aliveTime": alive_time}
        end_point = CREATE_SESSION
        response = self.connection_manager.post(end_point, data=payload)
        return response

    @log_entry_exit
    def delete_session(self, id):
        end_point = DELTE_SESSION.format(id)
        response = self.connection_manager.delete(end_point)
        return response
