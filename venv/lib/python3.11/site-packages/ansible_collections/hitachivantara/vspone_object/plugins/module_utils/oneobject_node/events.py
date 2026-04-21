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
    DictUtilities
)


class SystemEventsResource:
    def __init__(self, param, token):
        self.param = param
        self.token = token

    def query_all(self):
        logger = Log()

        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name

        json_spec = self.param.json_spec
        json_spec = DictUtilities.snake_to_camel(json_spec)
        logger.writeDebug("json_spec system events: {}".format(json_spec))

        parameter_url = "?"

        for key, value in json_spec.items():
            if value is not None:
                parameter_url += f"{key}={value}&"
        if parameter_url.endswith("&"):
            parameter_url = parameter_url[:-1]
        elif parameter_url == "?":
            parameter_url = ""

        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(region=region, cluster_name=cluster_name)

        url = f"{mapi_full_url}/mapi/v1/system/events" + parameter_url
        logger.writeDebug("System events url: {}".format(url))
        return gateway.http_pd(
            "GET", self.param.connection_info, url, self.token, data=None
        )


class GMSEventsResource:
    def __init__(self, param, token):
        self.param = param
        self.token = token

    def query_all(self):
        logger = Log()

        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name

        json_spec = self.param.json_spec
        json_spec = DictUtilities.snake_to_camel(json_spec)
        logger.writeDebug("json_spec system events: {}".format(json_spec))

        parameter_url = "?"

        for key, value in json_spec.items():
            if value is not None:
                parameter_url += f"{key}={value}&"
        if parameter_url.endswith("&"):
            parameter_url = parameter_url[:-1]
        elif parameter_url == "?":
            parameter_url = ""

        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(region=region, cluster_name=cluster_name)

        url = f"{mapi_full_url}/mapi/v1/system/gms_events" + parameter_url
        logger.writeDebug("GMS events url: {}".format(url))
        return gateway.http_pd(
            "GET", self.param.connection_info, url, self.token, data=None
        )
