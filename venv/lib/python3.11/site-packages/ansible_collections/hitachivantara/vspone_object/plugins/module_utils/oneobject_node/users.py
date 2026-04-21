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
    ErrorUtilities,
)


class UserResource:
    def __init__(self, param, token):
        self.param = param
        self.token = token

    def query_current_user(self):
        logger = Log()

        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(region=region, cluster_name=cluster_name)
        url = f"{mapi_full_url}/mapi/v1/user/info"
        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=None
        )

    def generate_s3_credentials(self):
        logger = Log()
        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(self.param.connection_info.cluster_name))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name
        )

        mask_fields = ["secretKey", "accessKey"]
        url = f"{mapi_full_url}/mapi/v1/s3/user/generate_credentials"

        response = None
        try:
            response = gateway.http_pd(
                "POST", self.param.connection_info, url,
                self.token, data=None, mask_fields=mask_fields)
        except urllib.error.HTTPError as e:
            ErrorUtilities.format_MAPI_http_error(e)
        except Exception as e:
            logger.writeDebug("Failed to generate s3 user: {}".format(e))
            logger.writeDebug(
                "Exception: {}".format(e)
            )
            raise e
        return response, True
        # return gateway.http_pd(
        #     "POST", self.param.connection_info, url, self.token, data=None, mask_fields=mask_fields
        # )

    def get_all_users(self):
        logger = Log()

        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        connection_info = self.param.connection_info
        users_list = gateway.get_users(connection_info)
        logger.writeDebug("users list: {}".format(users_list))
        user_list_updated = []
        for user_dict in users_list:
            user_id = user_dict.get("id", "")
            if not user_id:
                continue
            try:
                keycloak_user_details = self.get_keycloak_user_info_by_id(user_id)
                vsp_user_id = keycloak_user_details.get("id", {})
                user_dict["user_id"] = vsp_user_id.get("id", "")
                user_dict["user_uuid"] = user_dict.pop("id", "")
                user_list_updated.append(user_dict)
                logger.writeDebug("keycloak user details: {}".format(keycloak_user_details))
            except Exception as e:
                logger.writeDebug("get_keycloak_user_info_by_id error: {}".format(e))
                user_dict["user_uuid"] = user_dict.pop("id", "")
                user_dict["user_id"] = "not_found"
                user_list_updated.append(user_dict)
        return user_list_updated

    def get_user(self):
        logger = Log()

        # gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        # connection_info = self.param.connection_info
        json_spec = self.param.json_spec

        id = json_spec.get("id", "")
        return self.get_keycloak_user_info_by_id(id)

    def get_keycloak_user_info_by_id(self, id):
        logger = Log()

        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(region=region, cluster_name=cluster_name)
        url = f"{mapi_full_url}/mapi/v1/user/lookup"
        data = {
            "id": id
        }
        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=data
        )

    def revoke_s3_user(self, id):
        logger = Log()
        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(region=region, cluster_name=cluster_name)
        url = f"{mapi_full_url}/mapi/v1/user/revoke_credentials"

        data = {
            "id": id
        }
        response = None
        try:
            response = gateway.http_pd(
                "POST", self.param.connection_info, url,
                self.token, data=data)
        except urllib.error.HTTPError as e:
            ErrorUtilities.format_MAPI_http_error(e)
        except Exception as e:
            logger.writeDebug("Failed to revoke s3 user: {}".format(e))
            logger.writeDebug(
                "Exception: {}".format(e)
            )
            raise e
        return response, True
        # return gateway.http_pd(
        #     "POST", self.param.connection_info, url, self.token, data=data
        # )
