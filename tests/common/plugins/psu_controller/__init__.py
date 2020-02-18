import logging

import pytest


def psu_controller_factory(controller_ip, controller_protocol, dut_hostname):
    """
    @summary: Factory function for creating PSU controller according to different management protocol.
    @param controller_ip: IP address of the PSU controller host.
    @param controller_protocol: Management protocol supported by the PSU controller host.
    @param dut_hostname: Hostname of the DUT to be controlled by the PSU controller.
    """
    logging.info("Creating psu controller object")
    if controller_protocol == "snmp":
        import snmp_psu_controllers
        return snmp_psu_controllers.get_psu_controller(controller_ip, dut_hostname)


@pytest.fixture(scope="module")
def psu_controller(duthost):
    """
    @summary: Fixture for controlling power supply to PSUs of DUT
    @param duthost: Fixture duthost defined in sonic-mgmt/tests/conftest.py
    @returns: Returns a psu controller object implementing the BasePsuController interface defined in
              controller_base.py.
    """

    logging.info("Creating psu_controller fixture")
    inv_mgr = duthost.host.options["inventory_manager"]
    pdu_host = inv_mgr.get_host(duthost.hostname).get_vars().get("pdu_host")
    if not pdu_host:
        logging.info("No 'pdu_host' is defined in inventory file for '%s'. Unable to create psu_controller" %
                     duthost.hostname)
        yield None

    controller_vars = inv_mgr.get_host(pdu_host).get_vars()

    controller_ip = controller_vars.get("ansible_host")
    if not controller_ip:
        logging.info("No 'ansible_host' is defined in inventory file for '%s'" % pdu_host)
        logging.info("Unable to create psu_controller for %s" % duthost.hostname)
        yield None

    controller_protocol = controller_vars.get("protocol")
    if not controller_protocol:
        logging.info("No protocol is defined in inventory file for '%s'. Try to use default 'snmp'" % pdu_host)
        controller_protocol = "snmp"

    controller = psu_controller_factory(controller_ip, controller_protocol, duthost.hostname)

    yield controller

    logging.info("psu_controller fixture teardown, ensure that all PSUs are turned on after test")
    if controller:
        psu_status = controller.get_psu_status()
        if psu_status:
            for psu in psu_status:
                if not psu["psu_on"]:
                    controller.turn_on_psu(psu["psu_id"])
        controller.close()
