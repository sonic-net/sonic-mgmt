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
    ErrorUtilities,
)
import urllib.error


class LicenseResource:
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
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(region=region, cluster_name=cluster_name)
        url = f"{mapi_full_url}/mapi/v1/license/list"
        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=None
        )

    def add_license(self):
        logger = Log()

        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))
        logger.writeDebug("param: {}".format(self.param.json_spec))
        license_file_path = self.param.json_spec.get("license_file_path", "")
        logger.writeDebug("license_file_path: {}".format(license_file_path))
        license_data = None

        try:
            with open(license_file_path, 'r') as f:
                license_data = f.read()
        except Exception as e:
            logger.writeDebug("Failed to read license file: {}".format(e))
            raise

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(region=region, cluster_name=cluster_name)
        url = f"{mapi_full_url}/mapi/v1/license/add"
        logger.writeDebug("License Data: {}".format(license_data))
        response = None
        try:
            response = gateway.http_pd(
                "POST", self.param.connection_info, url,
                self.token, data=license_data, raw_data=True
            )
        except urllib.error.HTTPError as e:
            ErrorUtilities.format_MAPI_http_error(e)
        except Exception as e:
            logger.writeDebug("Failed to add license: {}".format(e))
            logger.writeDebug(
                "Exception: {}".format(e)
            )
            raise e
        return response, True
