try:
    from ..provisioner.sdsb_login_message_provisioner import SDSBLoginMessageProvisioner
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..common.hv_constants import StateValue
except ImportError:
    from provisioner.sdsb_login_message_provisioner import SDSBLoginMessageProvisioner
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from common.hv_constants import StateValue
    from message.sdsb_journal_msgs import SDSBLoginMessageProvisioner

logger = Log()


class SDSBLoginMessageReconciler:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBLoginMessageProvisioner(self.connection_info)

    @log_entry_exit
    def get_login_message(self, state=None):
        if state == StateValue.PRESENT:
            return self.provisioner.get_login_message()
        else:
            raise ValueError(f"Unsupported state for login_message_facts: {state}")

    @log_entry_exit
    def update_login_message(self, spec, state=None):
        if state == "present":
            return self.provisioner.update_login_message(spec)
        else:
            raise ValueError(f"Unsupported state for login_message: {state}")
