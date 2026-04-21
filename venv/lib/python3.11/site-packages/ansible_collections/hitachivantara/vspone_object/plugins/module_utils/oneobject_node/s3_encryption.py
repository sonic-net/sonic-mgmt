import urllib.error
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
    DictUtilities, ErrorUtilities,
)


class S3EncryptionResource:
    def __init__(self, param, token):
        self.param = param
        self.token = token

    def get_s3_encryption(self):
        logger = Log()
        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name)
        url = f"{mapi_full_url}/mapi/v1/s3_encryption/get"
        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=None
        )

    def set_s3_encryption(self):
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
        json_data = DictUtilities.snake_to_camel(self.param.json_spec)

        url = f"{mapi_full_url}/mapi/v1/s3_encryption/set"
        response = None
        try:
            response = gateway.http_pd(
                "POST",
                self.param.connection_info,
                url,
                self.token,
                data=json_data)
        except urllib.error.HTTPError as e:
            ErrorUtilities.format_MAPI_http_error(e)
        except Exception as e:
            logger.writeDebug(
                "Exception: {}".format(e)
            )
            raise e
        return response
