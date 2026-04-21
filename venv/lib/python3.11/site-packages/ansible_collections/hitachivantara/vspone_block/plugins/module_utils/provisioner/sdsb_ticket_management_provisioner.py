try:
    from ..gateway.sdsb_ticket_management_gateway import TicketManagementGateway
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit

except ImportError:
    from gateway.sdsb_ticket_management_gateway import TicketManagementGateway
    from common.hv_log import Log
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit

logger = Log()


class SDSBTicketManagementProvisioner:
    """
    This class is responsible for managing the lifecycle of SDSB tickets.
    It provides methods to create, update, and delete tickets as needed.
    """

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.gateway = TicketManagementGateway(connection_info)

    @log_entry_exit
    def issue_ticket(self, max_age_days=None):
        """
        Issues a new ticket with the specified maximum age in days.
        :param max_age_days: Maximum age of the ticket in days.
        :return: Response from the SDSB connection manager.
        """
        response = self.gateway.issue_ticket(max_age_days)
        self.connection_info.changed = True
        return response

    @log_entry_exit
    def discard_all_tickets(self):
        """
        Discards all existing tickets.
        :return: Response from the SDSB connection manager.
        """
        self.gateway.discard_all_tickets()
        self.connection_info.changed = True
        return "All tickets discarded successfully."
