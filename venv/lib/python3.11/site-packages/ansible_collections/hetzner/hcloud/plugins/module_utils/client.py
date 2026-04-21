# Copyright: (c) 2023, Hetzner Cloud GmbH <info@hetzner-cloud.de>

from __future__ import annotations

from contextlib import contextmanager

from ansible.module_utils.basic import missing_required_lib

from .vendor.hcloud import APIException, Client as ClientBase

HAS_REQUESTS = True
HAS_DATEUTIL = True

try:
    import requests  # pylint: disable=unused-import
except ImportError:
    HAS_REQUESTS = False

try:
    import dateutil  # pylint: disable=unused-import
except ImportError:
    HAS_DATEUTIL = False


class ClientException(Exception):
    """An error related to the client occurred."""


def client_check_required_lib():
    if not HAS_REQUESTS:
        raise ClientException(missing_required_lib("requests"))
    if not HAS_DATEUTIL:
        raise ClientException(missing_required_lib("python-dateutil"))


def _client_resource_not_found(resource: str, param: str | int):
    return ClientException(f"resource ({resource.rstrip('s')}) does not exist: {param}")


def client_get_by_name_or_id(client: Client, resource: str, param: str | int):
    """
    Get a resource by name, and if not found by its ID.

    :param client: Client to use to make the call
    :param resource: Name of the resource client that implements both `get_by_name` and `get_by_id` methods
    :param param: Name or ID of the resource to query
    """
    resource_client = getattr(client, resource)

    result = resource_client.get_by_name(param)
    if result is not None:
        return result

    # If the param is not a valid ID, prevent an unnecessary call to the API.
    try:
        int(param)
    except ValueError as exception:
        raise _client_resource_not_found(resource, param) from exception

    try:
        return resource_client.get_by_id(param)
    except APIException as exception:
        if exception.code == "not_found":
            raise _client_resource_not_found(resource, param) from exception
        raise exception


if HAS_REQUESTS:

    class CachedSession(requests.Session):
        cache: dict[str, requests.Response]

        def __init__(self) -> None:
            super().__init__()
            self.cache = {}

        def send(self, request: requests.PreparedRequest, **kwargs) -> requests.Response:  # type: ignore[no-untyped-def]
            """
            Send a given PreparedRequest.
            """
            if request.method != "GET" or request.url is None:
                return super().send(request, **kwargs)

            if request.url in self.cache:
                return self.cache[request.url]

            response = super().send(request, **kwargs)
            if response.ok:
                self.cache[request.url] = response

            return response


class Client(ClientBase):
    @contextmanager
    def cached_session(self):
        """
        Swap the client session during the scope of the context. The session will cache
        all GET requests.

        Cached response will not expire, therefore the cached client must not be used
        for long living scopes.
        """
        self._client._session = CachedSession()
        try:
            yield
        finally:
            self._client._session = requests.Session()
