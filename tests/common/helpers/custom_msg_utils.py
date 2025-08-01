"""
A helper module for log custom msg to be collected by kusto query.
"""
from tests.common.helpers.constants import (
    CUSTOM_MSG_PREFIX
)


def add_custom_msg(request, key, val):
    """
    Add a custom message to the cache with a specified prefix.

    At the end of each test, cached custom messages will be logged and collected
    by Kusto for debugging purposes.

    Args:
        request: The pytest request object.
        key (str): The key for the custom message. Use '.' to separate different
                   levels of keys (e.g., "foo.bar.baz" will be stored as
                   { "foo": { "bar": { "baz": val } } }).
        val: The value to be stored in the cache under the specified key.
    """
    request.config.cache.set(f"{CUSTOM_MSG_PREFIX}.{key}", val)
