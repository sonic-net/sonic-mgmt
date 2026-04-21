try:
    from ..provisioner.sdsb_ticket_management_provisioner import (
        SDSBTicketManagementProvisioner,
    )
    from ..common.hv_constants import StateValue
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
except ImportError:
    from provisioner.sdsb_ticket_management_provisioner import (
        SDSBTicketManagementProvisioner,
    )
    from common.hv_constants import StateValue
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit

logger = Log()


class SDSBTicketManagementReconciler:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBTicketManagementProvisioner(self.connection_info)

    @log_entry_exit
    def ticket_management_reconcile(self, state, spec):
        """
        Reconcile the ticket management based on the state and spec.
        :param state: The desired state (e.g., 'present', 'absent').
        :param spec: Specification for the ticket management.
        :return: Response from the provisioner.
        """
        if state.lower() == StateValue.ABSENT:
            response = self.provisioner.discard_all_tickets()
            logger.writeInfo("Discarded all tickets successfully.")
        else:
            max_age_days = spec.get("max_age_days", None) if spec else None
            response = self.provisioner.issue_ticket(max_age_days)
            logger.writeInfo("Issued a new ticket successfully.")

        return response
