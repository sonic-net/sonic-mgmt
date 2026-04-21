from .gateway_oo import (
    OOGateway
)
from ..common.hv_log import (
    Log
)
from ..common.ansible_common_constants import (
    MAPI_FULL_URL_TEMPLATE_HTTPS
)
from ..common.hv_utilities import (
    DictUtilities,
)


class SerialNumberResource:
    def __init__(self, param, token):
        self.param = param
        self.token = token

    def query_current_serial_number(self):
        logger = Log()

        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(region=region, cluster_name=cluster_name)
        url = f"{mapi_full_url}/mapi/v1/serial_number/get"
        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=None
        )

    def set_serial_number(self):
        logger = Log()
        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(self.param.connection_info.cluster_name))
        logger.writeDebug("param: {}".format(self.param.json_spec))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name
        )

        serial_number = self.param.json_spec["serial_number"]
        self.param.json_spec = dict()
        self.param.json_spec["value"] = serial_number

        json_data = DictUtilities.snake_to_camel(self.param.json_spec)

        url = f"{mapi_full_url}/mapi/v1/serial_number/set"

        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=json_data
        )
