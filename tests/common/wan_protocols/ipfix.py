from net_devices2.factory import PatchworkFactory
from tests.common.wan_utilities.utilities import WanPatchwork
from kusto_proxy.teams import PhyNetKustoProxy
import time


class IPFIXTests:
    def __init__(self, dut):
        self.device_a = dut

    def pull_prod_ipfix(self):
        result, message, prod_device = self.device_a.pull_prod_device()
        if not prod_device:
            return result, message
        else:
            wanfactory = PatchworkFactory.subclass_with(device_cls=WanPatchwork)
            prod_handler = wanfactory.get_device_handler(prod_device)
            (
                result,
                message,
                ipv4_ipfixserver,
                ipv4_ipfixport,
                ipv6_ipfixserver,
                ipv6_ipfixport,
            ) = prod_handler.pull_ipfix_configs()
            if not result:
                return result, message, False, False, False, False
            else:
                return result, message, ipv4_ipfixserver, ipv4_ipfixport, ipv6_ipfixserver, ipv6_ipfixport

    def apply_configs(self, ipv4_ipfixserver, ipv4_ipfixport, ipv6_ipfixserver, ipv6_ipfixport, ipfix_interface):
        result, message, routerid = self.device_a.apply_ipfix_configs(
            ipv4_ipfixserver, ipv4_ipfixport, ipv6_ipfixserver, ipv6_ipfixport, ipfix_interface
        )
        return result, message, routerid

    def verify_traffic(self, routerid):
        result, message = self.device_a.apply_ipfix_configs(routerid)
        return result, message, routerid

    def verify_traffic_in_kusto(self, routerid):
        # wait 10 minutes for kusto to update
        time.sleep(600)
        kusto_client = PhyNetKustoProxy(kusto_cluster="https://azwan.kusto.windows.net")
        query_command = f"""TestRealTimeIpfix
        | where TimeStamp >= ago(15m)
        | where IpAddress == '{routerid}'
        | where IpProtocolIdentifier == "61"
        | count"""
        ipv4_response = kusto_client.execute_query("WarpPPE", query_command)

        kusto_client = PhyNetKustoProxy(kusto_cluster="https://azwan.kusto.windows.net")
        query_command = f"""TestRealTimeIpfix
        | where TimeStamp >= ago(15m)
        | where IpAddress == '{routerid}'
        | where IpProtocolIdentifier == "59"
        | count"""
        ipv6_response = kusto_client.execute_query("WarpPPE", query_command)

        if not ipv4_response or not ipv6_response:
            message = "no response received from Kusto"
            return False, message
        else:
            if ipv4_response:
                ipv4_records = []
                for row in ipv4_response.fetchall():
                    ipv4_records.append(row["Count"])
                if ipv4_records[0] >= 1:
                    ipv4_record_found = True
                else:
                    ipv4_record_found = False
            if ipv6_response:
                ipv6_records = []
                for row in ipv6_response.fetchall():
                    ipv6_records.append(row["Count"])
                if ipv6_records[0] >= 1:
                    ipv6_record_found = True
                else:
                    ipv6_record_found = False
            if not ipv4_record_found:
                message = (
                    "could not verify Kusto logged an ipv4 flow."
                    "Check Azwan.WarpPPE.TestRealTimeIpfix | where IPAddress == '{routerid}'"
                )
                return False, message
            elif not ipv6_record_found:
                message = (
                    "could not verify Kusto logged an ipv6 flow."
                    "Check Azwan.WarpPPE.TestRealTimeIpfix | where IPAddress == '{routerid}'"
                )
                return False, message
            else:
                message = "IPFIX flows verified in Kusto"
                return True, message
