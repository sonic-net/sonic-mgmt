import logging
import time
from abc import ABC, abstractmethod
from typing import Type, Dict

from azure.kusto.data.helpers import dataframe_from_result_table
from pandas import DataFrame


logger = logging.getLogger(__name__)

SONIC_DEVICE_TYPE = "sonic"
VENDOR_DEVICE_TYPE = "vendor"
AZDHMDS_DB = "azdhmds"
CISCO_8800_HWSKU = "Cisco-8800"


class HwSkuStrategy(ABC):
    @abstractmethod
    def get_hw_sku_name(self) -> str:
        pass

    @abstractmethod
    def get_all_units_df(self, azphynet_kusto_client) -> DataFrame:
        pass

    @abstractmethod
    def get_sonic_device_count(self, sonic_modules_df: DataFrame) -> int:
        pass


class Cisco8800Strategy(HwSkuStrategy):
    def get_hw_sku_name(self) -> str:
        return CISCO_8800_HWSKU

    def get_all_units_df(self, azphynet_kusto_client) -> DataFrame:
        logger.info("Starting Cisco 8800 device query")
        start_time = time.time()

        query = """
        DeviceStatic
        | where HardwareSku contains "Cisco-88" or HardwareSku contains "8800" or HardwareSku contains "Cisco-8808"
        | where OSVersion !contains "EntityNotFound"
        | where DeviceName !contains "stg" and DeviceName !contains "-temp"
        | where (
            (OSVersion contains "SONiC" and NgsDeviceType in~ ("SpineRouter", "Supervisor", "Linecard")) or
            (OSVersion !contains "SONiC" and NgsDeviceType contains "SpineRouter")
        )
        | extend DeviceType = iff(OSVersion contains "SONiC", "{}", "{}")
        | distinct DeviceName, OSVersion, NgsDeviceType, DeviceType, Regions, DcCode
        """.format(SONIC_DEVICE_TYPE, VENDOR_DEVICE_TYPE)

        query_result = azphynet_kusto_client.execute_query(AZDHMDS_DB, query)
        result_data = query_result.primary_results[0]
        device_df = dataframe_from_result_table(result_data)

        exec_time = time.time() - start_time
        logger.info("Cisco 8800 query completed in {:.2f}s, found {} devices".format(exec_time, len(device_df)))
        return device_df

    def get_sonic_device_count(self, sonic_modules_df):
        return sonic_modules_df[
            sonic_modules_df["NgsDeviceType"].str.contains("supervisor", case=False, na=False)
        ].shape[0]


class HwSkuFactory:
    _strategies: Dict[str, Type[HwSkuStrategy]] = {
        CISCO_8800_HWSKU: Cisco8800Strategy,
        # Future HWSKUs can be added here
    }

    @classmethod
    def create_strategy(cls, hw_sku_name: str) -> HwSkuStrategy:
        strategy_class = cls._strategies.get(hw_sku_name)
        if not strategy_class:
            raise ValueError("Unsupported HWSKU: {}".format(hw_sku_name))

        return strategy_class()

    @classmethod
    def get_available_hw_skus(cls) -> list:
        return list(cls._strategies.keys())
