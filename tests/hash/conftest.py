"""
    Pytest configuration used by the read generic hash tests.
"""
from generic_hash_helper import HASH_FIELDS_SUPPORTED_BY_TEST


def pytest_addoption(parser):
    parser.addoption("--hash_field", action="store", default="random",
                     choices=['all', 'random'] + HASH_FIELDS_SUPPORTED_BY_TEST,
                     help="The hash field to test, can be 'all', 'random' or a designated one")
    parser.addoption("--ip_version", action="store", default="random", choices=('all', 'random', 'ipv4', 'ipv6'),
                     help="The outer ip version to test.")
    parser.addoption("--inner_ip_version", action="store", default="random", choices=('all', 'random', 'ipv4', 'ipv6'),
                     help="The inner ip version to test, only needed when hash field is an inner field.")
    parser.addoption("--encap_type", action="store", default="random",
                     choices=('random', 'all', 'ipinip', 'vxlan', 'nvgre'),
                     help="The encapsulation type for the inner fields, "
                          "only needed when hash field is an inner field.")
    parser.addoption("--reboot", action="store", default="random",
                     choices=('random', 'all', 'cold', 'fast', 'warm', 'reload'),
                     help="The reboot type for the reboot test, only needed for the reboot test case.")
