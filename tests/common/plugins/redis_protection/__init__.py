"""Explicit Redis mode options; ordinary test jobs retain their behavior."""
from .options import add_mode_option


def pytest_addoption(parser):
    group = parser.getgroup('Redis write protection')
    add_mode_option(group)
    group.addoption('--redis-allow-tcp-exceptions', action='store_true', default=False,
                    help='Validate protected processes and report configured TCP exceptions as unprotected')
