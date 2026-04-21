import os
from .ansible_common_constants import (
    # REGISTRATION_FILE_NAME,
    # REGISTRATION_FILE_PATH,
    USER_CONSENT_FILE_PATH,
    CONSENT_FILE_NAME,
)
from ..oneobject_node.common_msg_catalog import (
    CommonMsgCatalog as CMCA
)


def validate_ansible_product_registration():

    if not os.path.exists(
        os.path.join(USER_CONSENT_FILE_PATH, CONSENT_FILE_NAME)
    ):
        return CMCA.USER_CONSENT_MISSING.value
    return
