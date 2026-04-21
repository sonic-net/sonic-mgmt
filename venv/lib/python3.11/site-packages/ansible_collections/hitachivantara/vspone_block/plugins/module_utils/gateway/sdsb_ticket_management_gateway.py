try:
    from .gateway_manager import SDSBConnectionManager
    from ..common.ansible_common import log_entry_exit
    from ..common.sdsb_constants import SDSBlockEndpoints
except ImportError:
    from .gateway_manager import SDSBConnectionManager
    from ..common.sdsb_constants import SDSBlockEndpoints
    from common.ansible_common import log_entry_exit


class TicketManagementGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def discard_all_tickets(self):
        """
        Discard all tickets.
        """
        endPoint = SDSBlockEndpoints.DISCARD_TICKETS
        response = self.connection_manager.post(endPoint, None)
        return response

    @log_entry_exit
    def issue_ticket(self, max_age_days=None):
        """
        Create a new ticket.
        :param ticket_data: Dictionary containing ticket details.
        :return: Response from the server.
        """
        payload = None
        if max_age_days is not None:
            payload = {"maxAgeDays": max_age_days}

        endPoint = SDSBlockEndpoints.POST_TICKET
        response = self.connection_manager.post_wo_job(endPoint, data=payload)
        if response.get("expirationTime"):
            response["expiration_time"] = response.pop("expirationTime")

        return response
