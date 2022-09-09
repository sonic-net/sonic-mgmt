from net_devices2.factory import PatchworkFactory
from tests.common.wan_utilities.utilities import WanPatchwork
from kusto_proxy.teams import PhyNetKustoProxy
from datetime import datetime
import pytz
import time


class TACACSTests:
    def __init__(self, dut_handler):
        self.device = dut_handler

    def pull_lab_tacacs(self):
        result, message, tacacsserver, sourceaddress = self.device.pull_tacacs_configs()
        if not result:
            return result, message, False, False
        else:
            return result, message, tacacsserver, sourceaddress

    def pull_prod_tacacs(self):
        result, message, prod_device = self.device.pull_prod_device()
        if not prod_device:
            return result, message, False, False, False, False
        else:
            wanfactory = PatchworkFactory.subclass_with(device_cls=WanPatchwork)
            prod_handler = wanfactory.get_device_handler(prod_device)
            result, message, prod_tacacsserver, sourceaddress = prod_handler.pull_tacacs_configs()
            if not prod_tacacsserver:
                return result, message, False, False, False, False
            else:
                result, message, tacacs_secret, accounting_secret = prod_handler.pull_tacplus_secret()
                if not tacacs_secret and not accounting_secret:
                    return result, message, False, False, False, False
                else:
                    return result, message, prod_tacacsserver, tacacs_secret, accounting_secret, prod_device

    def apply_and_check_tacacs(
        self, prod_tacacsserver, tacacs_secret, accounting_secret, sourceaddress, dut, prod_device, usr, pwd
    ):
        result, message = self.device.dualthread_apply_and_check(
            prod_tacacsserver, tacacs_secret, accounting_secret, sourceaddress, dut, prod_device, usr, pwd
        )

        return result, message

    def verify_auth_in_kusto(self, dut):
        tries = 1
        login_timestamp = None
        while tries < 20 and not login_timestamp:
            kusto_client = PhyNetKustoProxy(kusto_cluster="https://phynetval.kusto.windows.net")
            query_command = f"""AzureAaaMasterSessions | where componentId == "TacacsPlusService"
            | where deviceName contains '{dut}'
            | where TIMESTAMP >= ago(25m)
            | where user == 'netscript1_ro'
            | where command contains 'show configuration | display set | match tacplus'
            | project TIMESTAMP, deviceName,user, command
            | top 1 by TIMESTAMP"""
            response = kusto_client.execute_query("aznwmds", query_command)
            for row in response.fetchall():
                if row["TIMESTAMP"]:
                    login_timestamp = row["TIMESTAMP"]
                    break
            tries += 1
            time.sleep(60)
        if not login_timestamp:
            message = (
                "could not verify Kusto logged the event."
                " Check AzureAaaMasterSessions | where user == 'netscript1_ro'"
            )
            return False, message, False
        else:
            message = "login event verified in Kusto - time elapsed:"
            now_timestamp = pytz.utc.localize(datetime.utcnow()).astimezone(pytz.timezone("US/Pacific"))
            # calculate the time in seconds since the login even occurred
            time_diff = now_timestamp - login_timestamp
            return True, message, str(time_diff)
