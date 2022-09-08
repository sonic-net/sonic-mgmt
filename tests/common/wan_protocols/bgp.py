import logging
import ipaddress

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class BGPProtocol():
    def __init__(self, dut_handler, dut_interface=None, neighbor_device=None, neighbor_device_interface=None):
        self.device_a = dut_handler
        self.interface_a = dut_interface
        self.device_b = neighbor_device
        self.interface_b = neighbor_device_interface

    def check_bgp(self):
        """
        :return: bool, BGP session status for peers
        """
        bgp_session_status_log = "Checking required BGP sessions are UP..."
        status_down = {}
        status_up = {}
        self.device_a.get_bgp_status()
        bgp_status = self.device_a.get_bgp_status()
        for ip in bgp_status:
            if ip == "Result":
                return False, "{}".format(bgp_status["Result"])
            if "Established" in bgp_status[ip].values() or "Establ" in bgp_status[ip].values():
                status_up[ip] = bgp_status[ip]
            else:
                status_down[ip] = bgp_status[ip]
        if status_down:
            bgp_session_status_log += "Found some bgp sessions are down ... {}".format(status_down)
            return False, bgp_session_status_log
        bgp_session_status_log += "All bgp sessions are up ... {}".format(status_up)
        return True, bgp_session_status_log

    def check_bgp_session_status_list(self, peer_ip_list):
        """
        :param peer_ip_list:
        :return: list of BGP session status for each peer in that order
        """
        peer_status_list = list()
        for ip in peer_ip_list:
            status = self.device_a.get_bgp_session_status(ip)
            peer_status_list.append(status)
        return peer_status_list

    def verify_prefixes_advertised_to_peers(self, prefixes_list, peer_ip_list):
        """
        :param prefixes_list:
        :param peer_ip_list:
        :return: dictionary with prefixes provided as key. Value is also dictionary with keys as peer IPs and
        values as "Advertised" or "NotAdvertised"
        """
        bgp_agg_advertisement_status = dict()
        for prefix in prefixes_list:
            if ipaddress.ip_network(prefix).version == 4:
                for peer in peer_ip_list:
                    if ipaddress.ip_network(peer).version == 4:
                        if self.device_a.is_prefix_advertised_to_peer(prefix, peer):
                            if prefix not in bgp_agg_advertisement_status.keys():
                                bgp_agg_advertisement_status[prefix] = {peer: "Advertised"}
                            else:
                                bgp_agg_advertisement_status[prefix].update({peer: "Advertised"})
                        else:
                            if prefix not in bgp_agg_advertisement_status.keys():
                                bgp_agg_advertisement_status[prefix] = {peer: "NotAdvertised"}
                            else:
                                bgp_agg_advertisement_status[prefix].update({peer: "NotAdvertised"})
            else:
                for peer in peer_ip_list:
                    if ipaddress.ip_network(peer).version == 6:
                        if self.device_a.is_prefix_advertised_to_peer(prefix, peer):
                            if prefix not in bgp_agg_advertisement_status.keys():
                                bgp_agg_advertisement_status[prefix] = {peer: "Advertised"}
                            else:
                                bgp_agg_advertisement_status[prefix].update({peer: "Advertised"})
                        else:
                            if prefix not in bgp_agg_advertisement_status.keys():
                                bgp_agg_advertisement_status[prefix] = {peer: "NotAdvertised"}
                            else:
                                bgp_agg_advertisement_status[prefix].update({peer: "NotAdvertised"})

        return bgp_agg_advertisement_status
