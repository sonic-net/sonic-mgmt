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
from ..common.hv_constants import (
    Http as HttpConstants,
)
from .common_msg_catalog import (
    CommonMsgCatalog as CMCA
)
from .certificate_msg_catalog import (
    CertificateMsgCatalog as CMC
)
from ..common.hv_utilities import (
    ErrorUtilities,
)


class CertificateResource:
    def __init__(self, param, token):
        self.param = param
        self.token = token

    def query_all(self):
        logger = Log()

        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))

        # return True
        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(region=region, cluster_name=cluster_name)
        url = f"{mapi_full_url}/mapi/v1/certificates/list"
        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=None
        )

    def query_one(self):
        logger = Log()

        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))
        logger.writeDebug("param: {}".format(self.param.json_spec))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(region=region, cluster_name=cluster_name)
        url = f"{mapi_full_url}/mapi/v1/certificates/get"
        json_spec = self.param.json_spec
        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=json_spec
        )

    def query_by_subjectDn(self, subjectDn):
        logger = Log()

        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))
        logger.writeDebug("param: {}".format(self.param.json_spec))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(region=region, cluster_name=cluster_name)
        url = f"{mapi_full_url}/mapi/v1/certificates/get"
        json_spec = {"subjectDn": subjectDn}
        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=json_spec
        )

    def delete_cert(self):
        logger = Log()

        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))
        logger.writeDebug("param: {}".format(self.param.json_spec))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(region=region, cluster_name=cluster_name)
        url = f"{mapi_full_url}/mapi/v1/certificates/delete"
        subjectDn = self.param.json_spec.get("delete_cert_dn", "")
        json_spec = {"subjectDn": subjectDn}
        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=json_spec
        )

    def add_cert(self):
        logger = Log()

        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))
        logger.writeDebug("param: {}".format(self.param.json_spec))
        cert_path = self.param.json_spec.get("cert_file_path", "")
        logger.writeDebug("cert_path: {}".format(cert_path))
        cert_data = None

        try:
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
        except Exception as e:
            logger.writeDebug("Failed to read certificate file: {}".format(e))
            raise

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(region=region, cluster_name=cluster_name)
        url = f"{mapi_full_url}/mapi/v1/certificates/add"
        response = None
        try:
            response = gateway.http_pd(
                "POST", self.param.connection_info, url,
                self.token, data=cert_data, binary_data=True
            )
        except urllib.error.HTTPError as e:
            ErrorUtilities.format_MAPI_http_error(e)
        except Exception as e:
            logger.writeDebug("Failed to add certificate: {}".format(e))
            logger.writeDebug(
                "Exception: {}".format(e)
            )
            raise e
        return response, True

    def handle_error(self, err, query_one=False):
        logger = Log()
        err_str = str(err)
        logger.writeDebug(err_str)
        subject_dn = self.param.json_spec.get("subjectDn", "")

        if str(HttpConstants.ERR_400) in err_str:
            err_msg = CMC.ERR_INVALID_DN_VALUE.value.format(subject_dn) if query_one else err_str
            return err_msg

        if str(HttpConstants.ERR_404) in err_str:
            err_msg = CMC.ERR_CERT_NOT_FOUND.value.format(subject_dn) if query_one else err_str
            return err_msg

        return CMCA.HTTP_500_ERR.value
