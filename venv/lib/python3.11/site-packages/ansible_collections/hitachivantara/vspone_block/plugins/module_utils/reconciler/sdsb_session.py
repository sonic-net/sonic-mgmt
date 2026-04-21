try:
    from ..provisioner.sdsb_session_provisioner import SDSBSessionProvisioner
    from ..common.hv_constants import StateValue
    from ..common.hv_log import Log
    from ..common.ansible_common import (
        log_entry_exit,
    )
    from ..message.sdsb_session_msgs import SDSBSessionValidationMsg
except ImportError:
    from provisioner.sdsb_session_provisioner import SDSBSessionProvisioner
    from common.hv_constants import StateValue
    from common.hv_log import Log
    from common.ansible_common import (
        log_entry_exit,
    )
    from message.sdsb_session_msgs import SDSBSessionValidationMsg

logger = Log()


class SDSBSessionReconciler:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBSessionProvisioner(self.connection_info)

    @log_entry_exit
    def get_session_facts(self, spec=None):
        if spec and spec.id:
            return self.get_session_by_id(spec.id)
        ret_data = self.provisioner.get_sessions(spec)
        logger.writeDebug("RC:get_sesion_facts:ret_data = {}", ret_data)
        return ret_data

    @log_entry_exit
    def get_session_by_id(self, id):
        return self.provisioner.get_session_by_id(id)

    @log_entry_exit
    def delete_session(self, id):
        try:
            self.provisioner.delete_session(id)
            self.connection_info.changed = True
            return True
        except Exception as e:
            logger.writeException(e)
            return False

    @log_entry_exit
    def create_session(self, spec=None):
        if spec and spec.alive_time:
            if not (1 <= spec.alive_time <= 300):
                raise ValueError(SDSBSessionValidationMsg.INVALID_ALIVE_TIME.value)
        self.connection_info.changed = True
        response = self.provisioner.create_session(spec)
        logger.writeDebug("RC:create_session:response = {}", response)
        return response

    @log_entry_exit
    def reconcile_session(self, state, spec):

        if state.lower() == StateValue.PRESENT:
            return self.create_session(spec)

        if state.lower() == StateValue.ABSENT:
            if spec.id is None:
                raise ValueError(SDSBSessionValidationMsg.ID_MISSING_FOR_DELETE.value)

            response = self.delete_session(spec.id)
            if response:
                return f"Session with id {spec.id} is deleted successfully."
            else:
                self.connection_info.changed = False
                return (
                    f"Could not delete session, ensure session ID {spec.id} is valid. "
                )
