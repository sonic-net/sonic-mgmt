import os
from dataclasses import dataclass, astuple
from typing import Optional


def get_env(*args, optional=False, default=None):
    """Return the first environment variable that is defined."""
    for arg in args:
        if arg in os.environ:
            return os.environ[arg]
    if optional or default:
        return default
    raise ValueError("No environment variables found: {}".format(args))


def set_env(key, value):
    """Set the environment variable."""
    os.environ[key] = value


def get_app_id(optional=False):
    """Return the app id."""
    result = get_env("APP_ID", "AZURE_CLIENT_ID", optional=optional)
    if result:
        set_env("AZURE_CLIENT_ID", result)
    return result


def get_auth_id(optional=False):
    """Return the auth id."""
    result = get_env("AUTH_ID", "APP_AUTH_ID", "AZURE_TENANT_ID", optional=optional)
    if result:
        set_env("AZURE_TENANT_ID", result)
    return result


def get_app_key(optional=False):
    """Return the app key."""
    result = get_env("APP_KEY", "AZURE_CLIENT_SECRET", optional=optional)
    if result:
        set_env("AZURE_CLIENT_SECRET", result)
    return result


@dataclass(frozen=True)
class AppKeyAuth:
    app_id: str
    app_key: str
    auth_id: str

    def __iter__(self):
        return iter(astuple(self))


def prepare_app_key_auth(optional=False) -> Optional[AppKeyAuth]:
    """Gets app key auth information from the env, sets the correct values for azidentity, and returns the AppKeyAuth object."""
    app_id = get_app_id(optional=optional)
    app_key = get_app_key(optional=optional)
    auth_id = get_auth_id(optional=optional)
    if app_id and app_key and auth_id:
        return AppKeyAuth(app_id, app_key, auth_id)
    return None
