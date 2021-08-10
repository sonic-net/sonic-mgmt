import pytest
from jinja2 import Template


# Pytest configuration used by the route tests.
def pytest_addoption(parser):
    # Add options to pytest that are used by route tests

    route_group = parser.getgroup("Route test suite options")

    route_group.addoption("--num_routes", action="store", default=10000, type=int,
                     help="Number of routes for add/delete")


@pytest.fixture(scope='package', autouse=True)
def prepare_arp_responder_conf(ptfhost):
    arp_responder_conf = Template(open("../ansible/roles/test/templates/arp_responder.conf.j2").read())
    ptfhost.copy(content=arp_responder_conf.render(arp_responder_args="--conf /tmp/from_t1.json"),
                 dest="/etc/supervisor/conf.d/arp_responder.conf")