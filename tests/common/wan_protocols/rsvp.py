import logging

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class RSVPprotocol:
    def __init__(self, dut_handler, neighbor_device_handler):
        self.device_a = dut_handler
        self.device_b = neighbor_device_handler

    def get_rsvp_nbr_ip(self):
        nbr_ip_addr = self.device_b.get_loopback_ip_addr()
        return nbr_ip_addr

    def validate_rsvp_neighbor(self):
        nbr_ip_address = self.get_rsvp_nbr_ip()
        nbr_result, nbr_message = self.device_a.check_rsvp_nbr(nbr_ip_address)
        return nbr_result, nbr_message
