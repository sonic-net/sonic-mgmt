import functools
import os
import re
import sys
from dataclasses import dataclass
from typing import List, Tuple, Optional

from .env_utils import get_env
from azure.kusto.data._version import VERSION

NONE = "[none]"

REPLACE_REGEX = re.compile(r"[\r\n\s{}|]+")


@functools.lru_cache(maxsize=1)
def default_script() -> str:
    """Returns the name of the script that is currently running"""
    try:
        return os.path.basename(sys.argv[0]) or NONE
    except Exception:
        return NONE


@functools.lru_cache(maxsize=1)
def get_user_from_env() -> str:
    user = get_env("USERNAME", optional=True)
    domain = get_env("USERDOMAIN", optional=True)
    if domain and user:
        user = domain + "\\" + user
    if user:
        return user
    return NONE


@functools.lru_cache(maxsize=1)
def default_user():
    """Returns the name of the user that is currently logged in"""
    try:
        return os.getlogin() or get_user_from_env()
    except Exception:
        return get_user_from_env()


@functools.lru_cache(maxsize=1)
def format_version():
    return format_header(
        [
            ("Kusto.Python.Client", VERSION),
            (f"Runtime.{escape_field(sys.implementation.name)}", sys.version),
        ]
    )


def format_header(args: List[Tuple[str, str]]) -> str:
    return "|".join(f"{key}:{escape_field(val)}" for (key, val) in args if key and val)


def escape_field(field: str):
    return f"{{{REPLACE_REGEX.sub('_', field)}}}"


@dataclass
class ClientDetails:
    application_for_tracing: str
    user_name_for_tracing: str
    version_for_tracing: str = format_version()

    def __post_init__(self):
        self.application_for_tracing = self.application_for_tracing or default_script()
        self.user_name_for_tracing = self.user_name_for_tracing or default_user()

    @staticmethod
    def set_connector_details(
        name: str,
        version: str,
        app_name: Optional[str] = None,
        app_version: Optional[str] = None,
        send_user: bool = False,
        override_user: Optional[str] = None,
        additional_fields: Optional[List[Tuple[str, str]]] = None,
    ) -> "ClientDetails":
        params = [("Kusto." + name, version)]

        app_name = app_name or default_script()
        app_version = app_version or NONE

        params.append(("App." + escape_field(app_name), app_version))
        params.extend(additional_fields or [])

        user = NONE

        if send_user:
            user = override_user or default_user()

        return ClientDetails(application_for_tracing=format_header(params), user_name_for_tracing=user)
