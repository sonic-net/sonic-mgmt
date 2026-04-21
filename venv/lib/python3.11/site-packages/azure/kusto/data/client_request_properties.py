import json
from typing import Any

from ._string_utils import assert_string_is_not_empty


class ClientRequestProperties:
    """This class is a POD used by client making requests to describe specific needs from the service executing the requests.
    For more information please look at: https://docs.microsoft.com/en-us/azure/kusto/api/netfx/request-properties
    """

    client_request_id: str
    application: str
    user: str
    _CLIENT_REQUEST_ID = "client_request_id"

    results_defer_partial_query_failures_option_name = "deferpartialqueryfailures"
    request_timeout_option_name = "servertimeout"
    no_request_timeout_option_name = "norequesttimeout"

    def __init__(self):
        self._options = {}
        self._parameters = {}
        self.client_request_id = None
        self.application = None
        self.user = None

    def set_parameter(self, name: str, value: str):
        """Sets a parameter's value"""
        assert_string_is_not_empty(name)
        self._parameters[name] = value

    def has_parameter(self, name: str) -> bool:
        """Checks if a parameter is specified."""
        return name in self._parameters

    def get_parameter(self, name: str, default_value: str) -> str:
        """Gets a parameter's value."""
        return self._parameters.get(name, default_value)

    def set_option(self, name: str, value: Any):
        """Sets an option's value"""
        assert_string_is_not_empty(name)
        self._options[name] = value

    def has_option(self, name: str) -> bool:
        """Checks if an option is specified."""
        return name in self._options

    def get_option(self, name: str, default_value: Any) -> str:
        """Gets an option's value."""
        return self._options.get(name, default_value)

    def to_json(self) -> str:
        """Safe serialization to a JSON string."""
        return json.dumps({"Options": self._options, "Parameters": self._parameters}, default=str)

    def get_tracing_attributes(self) -> dict:
        """Gets dictionary of attributes to be documented during tracing"""
        return {self._CLIENT_REQUEST_ID: str(self.client_request_id)}
