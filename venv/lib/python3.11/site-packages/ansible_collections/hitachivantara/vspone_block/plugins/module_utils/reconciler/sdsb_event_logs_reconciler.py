try:
    from ..provisioner.sdsb_event_logs_provisioner import SDSBEventLogsProvisioner
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
except ImportError:
    from ..provisioner.sdsb_event_logs_provisioner import SDSBEventLogsProvisioner
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit

logger = Log()


class SDSBEventLogsReconciler:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBEventLogsProvisioner(self.connection_info)

    @log_entry_exit
    def get_event_logs(self, spec=None):
        return self.provisioner.get_event_logs(spec)
