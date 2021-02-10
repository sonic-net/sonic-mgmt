import logging

import pytest


def pdu_controller_factory(controller_ip, controller_protocol, dut_hostname, pdu):
    """
    @summary: Factory function for creating PDU controller according to different management protocol.
    @param controller_ip: IP address of the PDU controller host.
    @param controller_protocol: Management protocol supported by the PDU controller host.
    @param dut_hostname: Hostname of the DUT to be controlled by the PDU controller.
    """
    logging.info("Creating pdu controller object")
    if controller_protocol == "snmp":
        import snmp_pdu_controllers
        return snmp_pdu_controllers.get_pdu_controller(controller_ip, dut_hostname, pdu)


@pytest.fixture(scope="module")
def pdu_controller(duthosts, rand_one_dut_hostname, pdu):
    """
    @summary: Fixture for controlling power supply to PSUs of DUT
    @param duthost: Fixture duthost defined in sonic-mgmt/tests/conftest.py
    @returns: Returns a pdu controller object implementing the BasePduController interface defined in
              controller_base.py.
    """
    duthost = duthosts[rand_one_dut_hostname]

    logging.info("Creating pdu_controller fixture")
    inv_mgr = duthost.host.options["inventory_manager"]
    pdu_host = inv_mgr.get_host(duthost.hostname).get_vars().get("pdu_host")
    if not pdu_host:
        logging.info("No 'pdu_host' is defined in inventory file for '%s'. Unable to create pdu_controller" %
                     duthost.hostname)
        yield None
        return

    controller_vars = inv_mgr.get_host(pdu_host).get_vars()

    controller_ip = controller_vars.get("ansible_host")
    if not controller_ip:
        logging.info("No 'ansible_host' is defined in inventory file for '%s'" % pdu_host)
        logging.info("Unable to create pdu_controller for %s" % duthost.hostname)
        yield None
        return

    controller_protocol = controller_vars.get("protocol")
    if not controller_protocol:
        logging.info("No protocol is defined in inventory file for '%s'. Try to use default 'snmp'" % pdu_host)
        controller_protocol = "snmp"

    controller = pdu_controller_factory(controller_ip, controller_protocol, duthost.hostname, pdu)

    yield controller

    logging.info("pdu_controller fixture teardown, ensure that all PDU outlets are turned on after test")
    if controller:
        outlet_status = controller.get_outlet_status()
        if outlet_status:
            for outlet in outlet_status:
                if not outlet["outlet_on"]:
                    controller.turn_on_outlet(outlet["outlet_id"])
        controller.close()
