try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.ansible_common import log_entry_exit

except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.ansible_common import log_entry_exit


class SDSBFaultDomainProvisioner:

    def __init__(self, connection_info):

        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.SDSB_FAULT_DOMAIN
        )

    @log_entry_exit
    def get_fault_domains(self, spec=None):
        fault_domains = self.gateway.get_fault_domains(spec)
        controllers = None
        controllers = fault_domains.get("data", [])
        if spec is not None and spec.name:
            fault_domains = [fd for fd in controllers if fd.get("name") == spec.name]
        return fault_domains
