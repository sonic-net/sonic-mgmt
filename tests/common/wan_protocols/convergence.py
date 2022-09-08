from tests.common.wan_utilities import wan_constants
import ipaddress
import logging

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class ConvergenceTests:
    def __init__(self, dut):
        self.device = dut

    def verify_traffic_matrix(self, dut):
        """
        Check the wan_constants file to verify traffic flows are set up for the DUT.
        The DUT should be listed in the matrix as either the A or Z device.
        Return the device on the other end of the traffic flow
        and the IP block associated with the traffic flow.
        """
        for routerdata in wan_constants.CONVERGENCE_TRAFFIC_FLOWS:
            if dut in routerdata:
                if routerdata[0] == dut:
                    remotedevice = routerdata[1]
                else:
                    remotedevice = routerdata[0]
                if ipaddress.ip_network(routerdata[2]):
                    ipblock = routerdata[2]

        if remotedevice:
            msg = "{} is in the traffic matrix".format(dut)
            return True, msg, remotedevice, ipblock
        else:
            msg = "{} is NOT in the traffic matrix.  Please update the wan_constants file.".format(dut)
            return False, msg, False, False

    def baseline_packet_loss(self, traffic_gen):
        # check the ixia packet loss counter prior to starting
        reply = traffic_gen.get_packet_loss_duration()
        baselineloss = sum(reply)

        if reply:
            msg = "base line packet loss - {}".format(baselineloss)
            return True, msg, baselineloss
        else:
            msg = "could not get baseline ixia loss calculation"
            return False, msg, False

    def check_packet_loss(self, traffic_gen, baselineloss):
        # check the ixia packet loss duration counter
        reply = traffic_gen.get_packet_loss_duration()
        currentloss = sum(reply)
        loss_ms = currentloss - baselineloss

        if reply:
            msg = "packet loss in milliseconds - {}".format(loss_ms)
            return True, msg, currentloss
        else:
            msg = "could not get current ixia loss calculation"
            return False, msg, False

    def verify_traffic_path(self, dut, remotedevice, ipblock):
        # identify the original LSP path and return a list of IP to hostnames
        result, message, hostnamepath, ippath, lspname, hostlist = self.device.check_traffic_path(
            dut, remotedevice, ipblock
        )
        return result, message, hostnamepath, ippath, lspname, hostlist

    def verify_traffic_path_change(self, dut, lspname, ippath, hostlist):
        # verify the LSP changes to a different path
        result, message = self.device.check_traffic_path_change(dut, lspname, ippath, hostlist)
        return result, message

    def fail_link(self, ibr, edgedevice, dut_handler_ibr):
        # identify and disable the edge interface
        result, message, edgeinterface = dut_handler_ibr.fail_ibr_link(ibr, edgedevice)
        return result, message, edgeinterface

    def restore_link(self, ibr, dut_handler_ibr, edgeinterface):
        # reactivate the edge interface
        result, message = dut_handler_ibr.restore_ibr_link(ibr, edgeinterface)
        return result, message

    def set_max_link_metric(self, ibr, dut_handler_ibr, edgeinterface):
        # set the max isis metric for the link
        result, message, premetric = dut_handler_ibr.max_link_metric(ibr, edgeinterface)
        return result, message, premetric

    def restore_link_metric(self, ibr, dut_handler_ibr, edgeinterface, premetric):
        # restore the original isis link metric
        result, message = dut_handler_ibr.restore_link_metric_ibr(ibr, edgeinterface, premetric)
        return result, message

    def isis_change_overload(self, ibr, dut_handler_ibr, action):
        # set or remove the ISIS overload bit on the router
        result, message = dut_handler_ibr.isis_overload_unoverload(ibr, action)
        return result, message
