try:
    from .gateway_manager import VSPConnectionManager
    from ..model.vsp_mp_blade_models import MPBladesResponse
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..common.vsp_constants import Endpoints

except ImportError:
    from .gateway_manager import VSPConnectionManager
    from model.vsp_mp_blade_models import MPBladesResponse
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from ..common.vsp_constants import Endpoints

logger = Log()


class MPBladeGateway:
    """
    This class is used to interact with the VSP MP Blade API.
    """

    def __init__(self, connection_info):
        self.connection_manager = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )
        self.connection_info = connection_info
        self.serial = None

    @log_entry_exit
    def get_all_mp_blades(self) -> dict:
        """
        Get all MP blades from the VSP API.
        """
        response = self.connection_manager.get(Endpoints.GET_MP_BLADES)
        return MPBladesResponse().dump_to_object(response)
