import json
import copy
import urllib.parse
from ansible.module_utils.urls import open_url
import time

from ..common.hv_log import (
    Log
)
from ..common.hv_utilities import (SecurityUtilities, DictUtilities)
from .ansible_url import open_url as open_telemetry
from ..common.ansible_common_constants import (
    MAPI_FULL_URL_TEMPLATE_HTTPS
)


class OOGateway:
    def __init__(self):
        pass

    def get_tokens(self, conn_info_param):
        logger = Log()

        # step 1. Get Bearer Token
        data = {
            'client_id': conn_info_param.oneobject_node_client_id,
            'username': conn_info_param.oneobject_node_username,
            'password': conn_info_param.oneobject_node_userpass,
            'grant_type': 'password',
        }

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        gms_full_url = f"https://admin.gms.{conn_info_param.cluster_name}"
        url = (
            f"{gms_full_url}/ui/auth/realms/vsp-object/"
            "protocol/openid-connect/token"
        )
        encoded_data = urllib.parse.urlencode(data).encode('utf-8')
        response_data = None

        try:
            response = open_url(
                url,
                method='POST',
                headers=headers,
                data=encoded_data,
                validate_certs=conn_info_param.ssl["validate_certs"],
            )
            response_data = json.loads(response.read())
        except Exception as err:
            logger.writeDebug(
                "Failed to get bear_token. url={}, error={}".format(url, err)
            )
            raise

        bearer_token = response_data.get('access_token')

        # step 2. Get XSRF Token
        mapi_full_url = (
            f"https://admin.{conn_info_param.region}."
            f"{conn_info_param.cluster_name}"
        )
        url = f"{mapi_full_url}/mapi/v1/csrf"

        logger.writeDebug("Full URL: {}".format(url))

        headers = {
            'Authorization': f'Bearer {bearer_token}'
        }

        cookies_dict = {}

        try:
            response = open_url(
                url,
                method='GET',
                # headers=headers,
                validate_certs=conn_info_param.ssl["validate_certs"],
            )

            cookies = response.info().get_all('Set-Cookie')

            cookies_dict = {
                cookie.split('=')[0].strip(): cookie.split('=')[1]
                .split(';')[0].strip()
                for cookie in cookies
            }

            cookie_response = response.read().decode('utf-8')
        except Exception as err:
            logger.writeDebug(
                "Failed to get XSRF token. url={}, error={}".format(url, err)
            )
            raise

        xsrf_token = ""
        vertx_session = ""

        xsrf_token = cookies_dict.get("XSRF-TOKEN", "")
        vertx_session = cookies_dict.get("vertx-web.session", "")

        return bearer_token, xsrf_token, vertx_session

    def get_users(self, conn_info_param):
        logger = Log()

        # step 1. Get Bearer Token
        data = {
            'client_id': "admin-cli",
            'username': conn_info_param.oneobject_node_username,
            'password': conn_info_param.oneobject_node_userpass,
            'grant_type': 'password',
        }

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        gms_full_url = f"https://admin.gms.{conn_info_param.cluster_name}"
        url = (
            f"{gms_full_url}/ui/auth/realms/vsp-object/"
            "protocol/openid-connect/token"
        )
        encoded_data = urllib.parse.urlencode(data).encode('utf-8')
        response_data = None

        try:
            response = open_url(
                url,
                method='POST',
                headers=headers,
                data=encoded_data,
                validate_certs=conn_info_param.ssl["validate_certs"],
            )
            response_data = json.loads(response.read())
        except Exception as err:
            logger.writeDebug(
                "Failed to get bear_token. url={}, error={}".format(url, err)
            )
            raise

        bearer_token = response_data.get('access_token')
        logger.writeDebug("Bearer token: {}".format(bearer_token))

        # step 2. Get Users List
        url = (
            f"{gms_full_url}/ui/auth/admin/realms/vsp-object/users"
        )

        logger.writeDebug("Full URL: {}".format(url))

        headers = {
            'Authorization': f'Bearer {bearer_token}'
        }
        response_data = None
        try:
            response = open_url(
                url,
                method='GET',
                headers=headers,
                validate_certs=False
            )
            response_data_unfiltered = response.read()
            if (response_data_unfiltered is not None or
                    response_data_unfiltered != ""):
                response_data = json.loads(response_data_unfiltered)
        except Exception as err:
            logger.writeDebug(
                "Failed to get Users. url={}, error={}".format(url, err)
            )
            raise

        logger.writeDebug("response_data: {}".format(response_data))
        filtered_response_data = [
            {
                'id': user.get("id", ""),
                'username': user.get("username", "")
            }
            for user in response_data
        ]

        return filtered_response_data

    def create_http_headers_oo(self, token, content_type=None):
        authorization_str = f"Bearer {token.bearer_token}"
        headers = {
            "Authorization": authorization_str,
            "X-XSRF-TOKEN": token.xsrf_token,
            "accept": "application/json",
            "Content-Type": "application/json",
        }

        if content_type is not None:
            headers["Content-Type"] = content_type

        return headers

    def http_pd(self, http_method, conn_info_param, url, token, data=None, mask_fields=None, binary_data=False, raw_data=False):
        logger = Log()
        headers = self.create_http_headers_oo(token, content_type=None)
        encoded_data = None

        if data is not None:
            logger.writeDebug("Data: {}".format(data))
            if binary_data:
                encoded_data = data
            elif raw_data:
                encoded_data = data.encode('utf-8')
            else:
                encoded_data = json.dumps(data)

        cookie_header = (
            f"XSRF-TOKEN={token.xsrf_token}; "
            f"vertx-web.session={token.vertx_session}"
        )
        headers["Cookie"] = cookie_header

        response_data = None
        connection_info = conn_info_param
        serial_number = "N/A"
        success = True

        try:
            serial_response = self.get_serial("POST", connection_info, url, token, data=None)
            serial_number = serial_response.get("value", "")
            logger.writeDebug("serial number response : {}".format(serial_number))
        except Exception as e:
            logger.writeDebug("Cannot get serial number : {}".format(e))

        start_time = time.time()
        success = False
        end_time = time.time()
        error_message = None

        try:
            logger.writeDebug("encoded_data: {}".format(encoded_data))
            response = open_url(
                url,
                method=http_method,
                headers=headers,
                data=encoded_data,
                validate_certs=conn_info_param.ssl["validate_certs"],
                timeout=180,
            )
            success = True
            end_time = time.time()
            logger.writeDebug("Response: {}".format(response))
            logger.writeDebug("Response status: {}".format(response.status))
            response_data_unfiltered = response.read()

            if (response_data_unfiltered is not None or
                    response_data_unfiltered != "") and response_data_unfiltered != b'':
                response_data = json.loads(response_data_unfiltered)
            # mask sensitive data when logging
            masked_data = copy.deepcopy(response_data)
            masked_data_unfiltered = copy.deepcopy(response_data_unfiltered)
            if mask_fields:
                masked_data = SecurityUtilities.mask_sensitive_data(masked_data, mask_fields)
                masked_data_unfiltered = SecurityUtilities.mask_sensitive_data(masked_data_unfiltered, mask_fields)
            logger.writeDebug("Response data: {}".format(masked_data))
            logger.writeDebug("Response data unfiltered: {}".format(masked_data_unfiltered))

        except Exception as err:
            logger.writeDebug(
                "Failed to get bear_token. url={}, error={}".format(url, err)
            )
            success = False
            end_time = time.time()
            error_message = err

        elapsed_time = float(f"{end_time - start_time:.2f}")

        response_telemetry = open_telemetry(
            url=url,
            headers=headers,
            method=http_method,
            validate_certs=conn_info_param.ssl["validate_certs"],
            data=encoded_data,
            serial_number=serial_number,
            operation_status=success,
            elapsed_time=elapsed_time
        )

        logger.writeDebug("Response telemetry: {}".format(response_telemetry))
        if not success:
            raise error_message

        response_data = DictUtilities.convert_keys_to_snake_case(response_data)

        return response_data

    def get_serial(self, http_method, conn_info_param, url, token, data=None):
        logger = Log()
        headers = self.create_http_headers_oo(token, content_type=None)
        encoded_data = None

        if data is not None:
            logger.writeDebug("Data: {}".format(data))
            encoded_data = json.dumps(data)

        cookie_header = (
            f"XSRF-TOKEN={token.xsrf_token}; "
            f"vertx-web.session={token.vertx_session}"
        )
        headers["Cookie"] = cookie_header

        response_data = None

        try:
            region = conn_info_param.region
            cluster_name = conn_info_param.cluster_name
            mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(region=region, cluster_name=cluster_name)
            url = f"{mapi_full_url}/mapi/v1/serial_number/get"

            response = open_url(
                url,
                method=http_method,
                headers=headers,
                data=encoded_data,
                validate_certs=conn_info_param.ssl["validate_certs"],
            )
            logger.writeDebug("Response: {}".format(response))
            logger.writeDebug("Response status: {}".format(response.status))
            response_data_unfiltered = response.read()

            if (response_data_unfiltered is not None or
                    response_data_unfiltered != ""):
                response_data = json.loads(response_data_unfiltered)
            logger.writeDebug("Response data: {}".format(response_data))
            logger.writeDebug(
                "Response data unfiltered: {}".format(response_data_unfiltered)
            )
            # response_data = json.loads(response.read())
            # logger.writeDebug("Response data: {}".format(response_data))
        except Exception as err:
            logger.writeDebug(
                "Failed to get bear_token. url={}, error={}".format(url, err)
            )
            raise

        return response_data
