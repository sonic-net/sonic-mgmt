"""
combined_utils.py — helpers for combined AAA protocol switching tests.
"""
import logging

logger = logging.getLogger(__name__)


def set_aaa_authentication(duthost, method):
    """
    Set AAA authentication method string on DUT.
    method examples: 'local', 'radius local', 'tacacs+ local', 'radius'
    """
    duthost.shell("config aaa authentication login {}".format(method))
    logger.info("AAA authentication set to: %s", method)


def set_aaa_authorization(duthost, method):
    """
    Set AAA authorization method on DUT.
    method examples: 'local', 'tacacs+', 'radius'
    Note: SONiC CLI does NOT use 'login' keyword for authorization/accounting.
    """
    duthost.shell("config aaa authorization {}".format(method))
    logger.info("AAA authorization set to: %s", method)


def restore_local_aaa(duthost):
    """
    Restore DUT to local-only AAA and SAVE config to prevent lockout on reload.
    """
    duthost.shell("config aaa authentication login local", module_ignore_errors=True)
    duthost.shell("config aaa authorization local", module_ignore_errors=True)
    duthost.shell("config aaa accounting disable", module_ignore_errors=True)
    duthost.shell("config save -y", module_ignore_errors=True)
    logger.info("AAA restored to local-only and config saved")
