try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit

except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit

logger = Log()


class SDSBJobProvisioner:

    def __init__(self, connection_info):

        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.SDSB_JOB
        )

    @log_entry_exit
    def get_jobs(self, spec=None):
        if spec and spec.count:
            return self.gateway.get_jobs(spec.count)
        return self.gateway.get_jobs()

    @log_entry_exit
    def get_job_by_id(self, id):
        return self.gateway.get_job_by_id(id)
