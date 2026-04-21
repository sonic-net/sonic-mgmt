# http client module
import functools
import json as jsonModule
import urllib.parse
import urllib.error as urllib_error
from ansible.module_utils.urls import socket
from ansible.module_utils._text import to_native
from ansible.module_utils.six.moves.urllib import parse as urlparse
from ansible.module_utils.six.moves.http_client import HTTPException

try:
    from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
        Log,
    )

    from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_constants import (
        Http,
        LogMessages,
    )
    from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.gateway.ansible_url import (
        open_url,
    )
except ImportError:
    from common.hv_log import Log
    from common.hv_constants import (
        Http,
        LogMessages,
    )
    from gateway.ansible_url import open_url


def get_with_log(class_name=""):
    """Returns a decorator function for `class_name`"""
    logger = Log()

    def with_log(func):
        """Decorates `func` to output debug log before and after execution"""
        if class_name:
            name = class_name + "." + func.__name__ + "()"
        else:
            name = func.__name__ + "()"

        @functools.wraps(func)
        def traced(*args, **kwargs):
            logger.writeDebug(LogMessages.ENTER_METHOD.format(name))
            result = func(*args, **kwargs)
            logger.writeDebug(LogMessages.LEAVE_METHOD.format(name))
            return result

        return traced

    return with_log


class HTTPClientResponse(object):
    def __init__(self):
        self.ok = False
        self.status_code = 0
        self._json = {}
        self.content = None

    def json(self):
        return self._json


class HTTPClient(object):
    @staticmethod
    @get_with_log("HTTPClient")
    def get(url, params=None, **kwargs):
        return HTTPClient.request(Http.GET, url, params, **kwargs)

    @staticmethod
    @get_with_log("HTTPClient")
    def post(url, headers=None, json=None, **kwargs):
        return HTTPClient.request(Http.POST, url, headers=headers, json=json, **kwargs)

    @staticmethod
    @get_with_log("HTTPClient")
    def put(url, data=None, **kwargs):
        return HTTPClient.request(Http.PUT, url, data=data, **kwargs)

    @staticmethod
    @get_with_log("HTTPClient")
    def patch(url, data=None, **kwargs):
        return HTTPClient.request(Http.PATCH, url, data=data, **kwargs)

    @staticmethod
    @get_with_log("HTTPClient")
    def delete(url, **kwargs):
        return HTTPClient.request(Http.DELETE, url, **kwargs)

    @staticmethod
    @get_with_log("HTTPClient")
    def request(
        method,
        url,
        params=None,
        data=None,
        headers=None,
        cookies=None,
        files=None,
        auth=None,
        timeout=None,
        allow_redirects=True,
        proxies=None,
        hooks=None,
        stream=None,
        verify=None,
        cert=None,
        json=None,
        bytes=None,
    ):
        try:
            logger = Log()
            logger.writeDebug(
                "API Request: {} {}".format(method, urlparse.urlparse(url).path)
            )

            data = None
            if (
                method == Http.POST
                or method == Http.PUT
                or method == Http.PATCH
                or method == Http.DELETE
            ) and json is not None:
                data = jsonModule.dumps(json)

            if not headers:
                headers = {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                }
            elif "Content-Type" not in headers:
                headers["Content-Type"] = "application/json"
            elif "Accept" not in headers:
                headers["Accept"] = "application/json"

            if params is not None:
                logger.writeDebug(params)
                params = urllib.parse.urlencode(params)
                url = "{}?{}".format(url, params)
            response = open_url(
                url=url,
                headers=headers,
                # url_username=params.user if (params.session_id is None) else None,
                # url_password=params.password if (params.session_id is None) else None,
                method=method,
                # force_basic_auth=True if (params.session_id is None) else False,
                validate_certs=HTTPClient._is_validate_certs(json),
                timeout=Http.OPEN_URL_TIMEOUT,
                http_agent=Http.USER_AGENT,
                data=data,
            )
            return HTTPClient._load_response(response, bytes)
        except urllib_error.HTTPError as err:

            http_err = err
            err_body = err.read()
            err_str = str(err)

            # for 404, its the html text of the response page
            logger.writeDebug(f"147 err response body={err_body}")

            text = err_body.decode("utf-8")

            try:

                #  capture the error message. from porcelain response
                error_resp = jsonModule.loads(text)
                logger.writeDebug(f"164 err error_resp={error_resp}")
                error_dtls = error_resp.get("error").get("message")
                # problem above is that sometimes error is empty, but there is message
                if error_dtls is None:
                    error_dtls = error_resp.get("message")

            except Exception as err:
                logger.writeDebug("170 err={}", err)
                #  not able to json load the text
                #  return based on the http error
                if int(http_err.status) >= 300:
                    # err_str includes the http error string
                    raise Exception(f"{err_str} -> {url}")
                raise Exception(http_err)

            raise Exception(error_dtls)

        except (urllib_error.URLError, socket.timeout) as err:
            raise Exception(err)
        except HTTPException as err:
            raise Exception(err)

    @staticmethod
    @get_with_log("HTTPClient")
    def _is_validate_certs(params):
        return False

    @staticmethod
    @get_with_log("HTTPClient")
    def _load_response(response, bytes=None):
        """returns dict if json, native string otherwise"""
        logger = Log()
        text = response.read()
        # 2.4 MT - comment out if too verbose
        # logger.writeDebug(LogMessages.API_RESPONSE.format(to_native(text)))
        try:
            httpResponse = HTTPClientResponse()
            if response.status < 400:
                httpResponse.ok = True
            else:
                httpResponse.ok = False
            httpResponse.status_code = response.status
            logger.writeDebug(response.status)
            if bytes:
                httpResponse.content = text
                return httpResponse
            httpResponse._json = jsonModule.loads(text)
            return httpResponse
        except ValueError:
            return to_native(text)
