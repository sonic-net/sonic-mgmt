try:
    from .gateway_manager import SDSBConnectionManager
    from ..common.hv_log import Log
except ImportError:
    from .gateway_manager import SDSBConnectionManager
    from common.hv_log import Log

GET_STORAGE_DRIVES = "v1/objects/drives"

logger = Log()


class SDSBPlatformInfoGateway:
    _instance = None
    _platform = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(SDSBPlatformInfoGateway, cls).__new__(cls)
        return cls._instance

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    def get_platform(self):
        if self._platform is None:
            end_point = GET_STORAGE_DRIVES
            drives = self.connection_manager.get(end_point)
            logger.writeDebug("GW:get_drives:data={}", drives)
            self._platform = drives["data"][0]["vendorName"]
        return self._platform
