import logging

from tests.common.reboot import (
    sync_reboot_history_queue_with_dut,
    reboot,
    REBOOT_TYPE_HISTOYR_QUEUE,
    REBOOT_TYPE_COLD,
    wait_for_startup,
)


def reboot_and_check(localhost, dut, interfaces, xcvr_skip_list,
                     reboot_type=REBOOT_TYPE_COLD, reboot_helper=None,
                     reboot_kwargs=None, duthosts=None, invocation_type="cli_based", ptf_gnoi=None,
                     interfaces_checker=None):
    """
    Perform the specified type of reboot and check platform status.
    @param localhost: The Localhost object.
    @param dut: The AnsibleHost object of DUT.
    @param interfaces: DUT's interfaces defined by minigraph
    @param xcvr_skip_list: list of DUT's interfaces for which transeiver checks are skipped
    @param reboot_type: The reboot type, pre-defined const that has name convention of REBOOT_TYPE_XXX.
    @param reboot_helper: The helper function used only by power off reboot
    @param reboot_kwargs: The argument used by reboot_helper
    @param interfaces_checker: Optional callable(dut, interfaces, xcvr_skip_list, reboot_type=None)
                               that performs interface/service checks after reboot.
                               When None, interface checks are skipped.
    """

    logging.info(
        "Sync reboot cause history queue with DUT reboot cause history queue")
    sync_reboot_history_queue_with_dut(dut)

    logging.info("Run %s reboot on DUT" % reboot_type)
    reboot(dut, localhost, reboot_type=reboot_type,
           reboot_helper=reboot_helper, reboot_kwargs=reboot_kwargs, invocation_type=invocation_type,
           ptf_gnoi=ptf_gnoi)

    # Append the last reboot type to the queue
    logging.info("Append the latest reboot type to the queue")
    REBOOT_TYPE_HISTOYR_QUEUE.append(reboot_type)

    if interfaces_checker is not None:
        interfaces_checker(dut, interfaces, xcvr_skip_list, reboot_type=reboot_type)
        if dut.is_supervisor_node():
            for lc in duthosts.frontend_nodes:
                wait_for_startup(lc, localhost, delay=10, timeout=600)
                interfaces_checker(lc, interfaces, xcvr_skip_list)
