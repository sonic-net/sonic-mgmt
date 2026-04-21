from enum import Enum


class VSPRemoteConnectionMSG(Enum):
    REMOTE_STORAGE_IS_NOT_REGISTERED = (
        "Remote storage with serial number {0} is not registered."
    )
    REMOTE_CONNECTION_ALREADY_EXISTS = (
        "Remote connection with path group id {0} already exists."
    )
    REMOTE_CONNECTION_NOT_EXITS = (
        "Remote connection with path group id {0} does not exist."
    )
    REMOTE_PATHS_NOT_PROVIDED = (
        "For new remote connection, at least one remote path is required."
    )
    REMOTE_CONNECTIONS_NOT_FOUND = "No remote connections found."
