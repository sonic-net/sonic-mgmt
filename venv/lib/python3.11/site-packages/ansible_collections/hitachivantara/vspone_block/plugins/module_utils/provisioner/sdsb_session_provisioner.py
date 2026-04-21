try:
    from ..gateway.sdsb_session_gateway import SDSBSessionGateway
    from ..common.ansible_common import log_entry_exit

except ImportError:
    from gateway.sdsb_session_gateway import SDSBSessionGateway
    from common.ansible_common import log_entry_exit


class SDSBSessionProvisioner:

    def __init__(self, connection_info):
        self.gateway = SDSBSessionGateway(connection_info)

    @log_entry_exit
    def get_sessions(self, spec=None):
        response = self.gateway.get_sessions(spec.vps_id, spec.user_id)
        if response:
            return response.data_to_snake_case_list()
        else:
            return None

    @log_entry_exit
    def get_session_by_id(self, id):
        response = self.gateway.get_session_by_id(id)
        if response:
            return response.camel_to_snake_dict()
        else:
            return None

    @log_entry_exit
    def delete_session(self, id):
        return self.gateway.delete_session(id)

    @log_entry_exit
    def create_session(self, spec=None):
        alive_time = None
        if spec and spec.alive_time:
            alive_time = spec.alive_time
        return self.gateway.create_session(alive_time)
