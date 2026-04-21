import re

try:
    from ..common.vsp_constants import Endpoints, TimeZoneConst
    from ..common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from ..common.hv_log import Log
    from ..common.vsp_constants import PEGASUS_MODELS
    from ..model.vsp_storage_system_models import (
        VSPStorageSystemsInfoPfrestList,
        VSPStorageSystemsInfoPfrest,
        VSPStorageSystemInfoPfrest,
        VSPDetailedJournalPoolPfrestList,
        VSPDetailedJournalPoolPfrest,
        VSPBasicJournalPoolPfrestList,
        VSPBasicJournalPoolPfrest,
        VSPPortPfrestList,
        VSPPortPfrest,
        VSPPoolPfrestList,
        VSPPoolPfrest,
        VSPQuorumDiskPfrestList,
        VSPQuorumDiskPfrest,
        VSPFreeLunPfrestList,
        VSPFreeLunPfrest,
        VSPSyslogServerPfrest,
        VSPStorageCapacitiesPfrest,
        TotalEfficiency,
        StorageSystemDateTime,
        TimeZonesInfo,
    )
    from .gateway_manager import VSPConnectionManager
except ImportError:
    from common.vsp_constants import Endpoints, TimeZoneConst
    from common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from common.hv_log import Log
    from common.vsp_constants import PEGASUS_MODELS
    from model.vsp_storage_system_models import (
        VSPStorageSystemsInfoPfrestList,
        VSPStorageSystemsInfoPfrest,
        VSPStorageSystemInfoPfrest,
        VSPDetailedJournalPoolPfrestList,
        VSPDetailedJournalPoolPfrest,
        VSPBasicJournalPoolPfrestList,
        VSPBasicJournalPoolPfrest,
        VSPPortPfrestList,
        VSPPortPfrest,
        VSPPoolPfrestList,
        VSPPoolPfrest,
        VSPQuorumDiskPfrestList,
        VSPQuorumDiskPfrest,
        VSPFreeLunPfrestList,
        VSPFreeLunPfrest,
        VSPSyslogServerPfrest,
        VSPStorageCapacitiesPfrest,
        TotalEfficiency,
        StorageSystemDateTime,
        TimeZonesInfo,
    )
    from .gateway_manager import VSPConnectionManager

logger = Log()


class VSPStorageSystemDirectGateway:
    _instance = None
    _cache = {}

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(VSPStorageSystemDirectGateway, cls).__new__(cls)
        return cls._instance

    def __init__(self, connection_info):
        self.connectionManager = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )
        self.address = connection_info.address

    @log_entry_exit
    def get_site_cache(self):
        value = self._cache.get(self.address, None)
        if value is not None:
            return value
        else:
            site_cache = {}
            self._cache[self.address] = site_cache
            return site_cache

    @log_entry_exit
    def get_storage_systems(self):
        logger.writeDebug("get_storage_systems called")
        cache = self.get_site_cache()
        value = cache.get("get_storage_systems", None)
        if value is not None:
            return value
        else:
            endPoint = Endpoints.GET_STORAGE_SYSTEMS
            storageSystemsDict = self.connectionManager.get(endPoint)
            result = VSPStorageSystemsInfoPfrestList(
                dicts_to_dataclass_list(
                    storageSystemsDict["data"], VSPStorageSystemsInfoPfrest
                )
            )
            cache["get_storage_systems"] = result
            return result

    @log_entry_exit
    def get_storage_system(self, instance):
        logger.writeDebug("get_storage_system called")
        cache = self.get_site_cache()
        value = cache.get("get_storage_system", None)
        if value is not None:
            return value
        else:
            path = instance + "?detailInfoType=version"
            endPoint = Endpoints.GET_STORAGE_SYSTEM.format(path)
            storageSystemInfo = self.connectionManager.get(endPoint)
            result = VSPStorageSystemInfoPfrest(**storageSystemInfo)
            cache["get_storage_system"] = result
            return result

    @log_entry_exit
    def get_current_storage_system_info(self):
        logger.writeDebug("get_current_storage_system_info called")
        cache = self.get_site_cache()
        value = cache.get("get_current_storage_system_info", None)
        if value is not None:
            return value
        else:
            endPoint = Endpoints.GET_STORAGE_INFO
            storageSystemInfo = self.connectionManager.get(endPoint)
            result = VSPStorageSystemInfoPfrest(**storageSystemInfo)
            cache["get_current_storage_system_info"] = result
            return result

    @log_entry_exit
    def is_pegasus(self):
        cache = self.get_site_cache()
        value = cache.get("is_pegasus", None)
        if value is not None:
            return value
        else:
            storage_info = self.get_current_storage_system_info()
            pegasus_model = any(sub in storage_info.model for sub in PEGASUS_MODELS)
            cache["is_vsp_5000_series"] = pegasus_model
            return pegasus_model

    @log_entry_exit
    def is_vsp_5000_series(self):
        cache = self.get_site_cache()
        value = cache.get("is_vsp_5000_series", None)
        if value is not None:
            return value
        else:
            storage_system_info = self.get_current_storage_system_info()
            model = storage_system_info.model
            pattern = r"VSP 5[0-9]00*"
            match = re.search(pattern, model)
            if match:
                cache["is_vsp_5000_series"] = True
                return True
            else:
                cache["is_vsp_5000_series"] = False
                return False

    @log_entry_exit
    def is_svp_present(self):
        cache = self.get_site_cache()
        value = cache.get("is_svp_present", None)
        if value is not None:
            return value
        else:
            storage_system_info = self.get_current_storage_system_info()
            if storage_system_info.svpIp:
                cache["is_svp_present"] = True
                return True
            else:
                cache["is_svp_present"] = False
                return False

    @log_entry_exit
    def get_total_efficiency_of_storage_system(self):
        # logger = Log()
        endPoint = Endpoints.GET_TOTAL_EFFICIENCY
        totalEfficiency = self.connectionManager.get(endPoint)
        return TotalEfficiency(**totalEfficiency)

    @log_entry_exit
    def get_journal_pools(self, journal_info_query):
        endPoint = Endpoints.GET_JOURNAL_POOLS
        if journal_info_query is not None:
            endPoint += "?journalInfo=" + journal_info_query
        journal_pools = self.connectionManager.get(endPoint)
        if journal_info_query == "detail":
            return VSPDetailedJournalPoolPfrestList(
                dicts_to_dataclass_list(
                    journal_pools["data"], VSPDetailedJournalPoolPfrest
                )
            )
        elif journal_info_query == "basic":
            return VSPBasicJournalPoolPfrestList(
                dicts_to_dataclass_list(
                    journal_pools["data"], VSPBasicJournalPoolPfrest
                )
            )

    @log_entry_exit
    def get_ports(self):
        endPoint = Endpoints.GET_PORTS + "?detailInfoType=portMode"
        ports = self.connectionManager.get(endPoint)
        return VSPPortPfrestList(dicts_to_dataclass_list(ports["data"], VSPPortPfrest))

    @log_entry_exit
    def get_pools(self):
        endPoint = Endpoints.GET_POOLS
        pools = self.connectionManager.get(endPoint)
        return VSPPoolPfrestList(dicts_to_dataclass_list(pools["data"], VSPPoolPfrest))

    @log_entry_exit
    def get_quorum_disks(self):
        endPoint = Endpoints.GET_QUORUM_DISKS
        quorum_disks = self.connectionManager.get(endPoint)
        return VSPQuorumDiskPfrestList(
            dicts_to_dataclass_list(quorum_disks["data"], VSPQuorumDiskPfrest)
        )

    @log_entry_exit
    def get_free_luns(self):
        # endPoint = Endpoints.GET_LDEVS.format("?count=16384&ldevOption=undefined")
        endPoint = Endpoints.GET_LDEVS.format(
            "?count=100&resourceGroupId=0&ldevOption=undefined"
        )
        free_luns = self.connectionManager.get(endPoint)
        return VSPFreeLunPfrestList(
            dicts_to_dataclass_list(free_luns["data"], VSPFreeLunPfrest)
        )

    @log_entry_exit
    def get_syslog_servers(self):
        endPoint = Endpoints.GET_SYSLOG_SERVERS
        syslog_servers = self.connectionManager.get(endPoint)
        return VSPSyslogServerPfrest(**syslog_servers)

    @log_entry_exit
    def get_storage_capacity(self):
        endPoint = Endpoints.GET_STORAGE_CAPACITY
        capacity = self.connectionManager.get(endPoint)
        return VSPStorageCapacitiesPfrest(**capacity)

    @log_entry_exit
    def get_storage_systems_date_and_time(self):
        endPoint = Endpoints.GET_STORAGE_SYSTEMS_INFO
        try:
            storage_systems_info = self.connectionManager.get(endPoint)
            return StorageSystemDateTime(**storage_systems_info)
        except Exception as e:
            # If the endpoint is not available, return None
            return None

    @log_entry_exit
    def get_storage_systems_time_zone(self):
        endPoint = Endpoints.GET_TIME_ZONE_LIST
        try:
            storage_systems_info = self.connectionManager.get(endPoint)
            return TimeZonesInfo().dump_to_object(storage_systems_info)
        except Exception as e:
            # If the endpoint is not available, return None
            return None

    @log_entry_exit
    def set_storage_systems_time_zone(self, time_zone_spec):
        endPoint = Endpoints.SET_TIME_ZONE

        payload = {
            TimeZoneConst.isNtpEnabled: time_zone_spec.is_ntp_enabled,
            TimeZoneConst.systemTime: time_zone_spec.system_time,
            TimeZoneConst.timeZoneId: time_zone_spec.time_zone_id,
        }
        if time_zone_spec.ntp_server_names:
            payload[TimeZoneConst.ntpServerNames] = time_zone_spec.ntp_server_names
        if time_zone_spec.synchronizing_local_time:
            payload[TimeZoneConst.synchronizingLocalTime] = (
                time_zone_spec.synchronizing_local_time
            )
        if time_zone_spec.adjusts_daylight_saving_time:
            payload[TimeZoneConst.adjustsDaylightSavingTime] = (
                time_zone_spec.adjusts_daylight_saving_time
            )
        if time_zone_spec.synchronizes_now:
            payload[TimeZoneConst.synchronizesNow] = time_zone_spec.synchronizes_now
        return self.connectionManager.patch_wo_job(endPoint, payload)
