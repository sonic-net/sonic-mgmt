try:
    from ..provisioner.sdsb_journal_provisioner import SDSBJournalProvisioner
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..common.hv_constants import StateValue
    from ..message.sdsb_journal_msgs import SDSBJournalValidationMsg
except ImportError:
    from ..provisioner.sdsb_journal_provisioner import SDSBJournalProvisioner
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from common.hv_constants import StateValue
    from message.sdsb_journal_msgs import SDSBJournalValidationMsg

logger = Log()


class SDSBJournalReconciler:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBJournalProvisioner(self.connection_info)

    @log_entry_exit
    def get_journals(self, spec=None):
        return self.provisioner.get_journals(spec)

    @log_entry_exit
    def reconcile_journal(self, spec, state=None):

        if spec is None:
            raise ValueError(SDSBJournalValidationMsg.NO_SPEC.value)

        if state == StateValue.PRESENT:
            return self.provisioner.create_update_journal(spec)

        elif state == StateValue.ABSENT:
            return self.provisioner.delete_journal(spec)

        elif state == StateValue.SHRINK_JOURNAL:
            return self.provisioner.delete_journal_volume(spec)

        elif state == StateValue.EXPAND_JOURNAL:
            return self.provisioner.expand_journal_volume(spec)
