try:
    from ..provisioner.sdsb_chap_user_provisioner import SDSBChapUserProvisioner
    from ..common.hv_constants import StateValue
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..message.sdsb_chap_user_msgs import SDSBChapUserValidationMsg
except ImportError:
    from provisioner.sdsb_chap_user_provisioner import SDSBChapUserProvisioner
    from common.hv_constants import StateValue
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from message.sdsb_chap_user_msgs import SDSBChapUserValidationMsg

logger = Log()


class SDSBChapUserReconciler:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBChapUserProvisioner(self.connection_info)

    @log_entry_exit
    def get_chap_users(self, spec=None):
        return self.provisioner.get_chap_users(spec)

    @log_entry_exit
    def get_chap_user_by_id(self, id):
        return self.provisioner.get_chap_user_by_id(id)

    @log_entry_exit
    def get_chap_user_by_name(self, name):
        return self.provisioner.get_chap_user_by_name(name)

    @log_entry_exit
    def delete_chap_user_by_id(self, id):
        self.connection_info.changed = True
        return self.provisioner.delete_chap_user_by_id(id)

    @log_entry_exit
    def update_sdsb_chap_user(self, chap_user, spec):
        if spec.id is None:
            raise ValueError(SDSBChapUserValidationMsg.UPDATE_REQD_FIELD.value)

        if spec.target_chap_user_name == chap_user.targetChapUserName:
            raise ValueError(SDSBChapUserValidationMsg.SAME_TARGET_CHAP_NAME.value)

        ret_val = self.update_chap_user(spec)
        logger.writeDebug("RC:update_sdsb_chap_user:ret_val={}", ret_val)
        return self.get_chap_user_by_id(chap_user.id)

    @log_entry_exit
    def update_chap_user(self, spec):
        self.connection_info.changed = True
        return self.provisioner.update_chap_user(spec)

    @log_entry_exit
    def create_chap_user(self, spec):
        self.connection_info.changed = True
        return self.provisioner.create_chap_user(spec)

    @log_entry_exit
    def create_sdsb_chap_user(self, spec):
        if spec.target_chap_user_name is None or spec.target_chap_secret is None:
            raise ValueError(SDSBChapUserValidationMsg.CREATE_REQD_FIELD.value)

        if len(spec.target_chap_secret) < 12 or len(spec.target_chap_secret) > 32:
            raise ValueError(SDSBChapUserValidationMsg.SECRET_LENGTH_ERR.value)

        if spec.initiator_chap_user_name and spec.initiator_chap_secret:
            if (
                len(spec.initiator_chap_secret) < 12
                or len(spec.initiator_chap_secret) > 32
            ):
                raise ValueError(SDSBChapUserValidationMsg.SECRET_LENGTH_ERR.value)

        chap_user_id = self.create_chap_user(spec)
        if not chap_user_id:
            raise Exception("Failed to create CHAP user")

        return self.get_chap_user_by_id(chap_user_id)

    @log_entry_exit
    def reconcile_chap_user(self, state, spec):
        logger.writeDebug("RC:=== reconcile_CHAP user ===")

        if spec is None:
            raise ValueError(SDSBChapUserValidationMsg.NO_SPEC.value)

        if state.lower() == StateValue.PRESENT:
            if spec.id is not None:
                logger.writeDebug("RC:=== spec.id is not None ===")
                # user provided an id of the chap user, so this must be an update
                chap_user = self.get_chap_user_by_id(spec.id)
                if chap_user is None:
                    raise ValueError(
                        SDSBChapUserValidationMsg.INVALID_CHAP_USER_ID.value
                    )
                else:
                    logger.writeDebug("RC:chap_user={}", chap_user)
                    return self.update_sdsb_chap_user(chap_user, spec)

            else:
                # this could be a create or an update
                if spec.target_chap_user_name is not None:
                    logger.writeDebug(
                        "RC:=== spec.target_chap_username is not None ==="
                    )
                    cuser = self.get_chap_user_by_name(spec.target_chap_user_name)

                    if cuser is not None:
                        # this is an update
                        logger.writeDebug("RC:volume={}", cuser)
                        return self.update_sdsb_chap_user(cuser, spec)
                    else:
                        # this is a create
                        return self.create_sdsb_chap_user(spec)
                else:
                    raise ValueError(SDSBChapUserValidationMsg.NO_NAME_ID.value)

        if state.lower() == StateValue.ABSENT:
            logger.writeDebug("RC:=== Delete CHAP user ===")
            logger.writeDebug("RC:state = {}", state)
            logger.writeDebug("RC:spec = {}", spec)
            if spec.id is not None:
                # user provided an id of the CHAP user, so this must be a delete
                chap_user_id = spec.id
            elif spec.target_chap_user_name is not None:
                # user provided an compute node name, so this must be a delete
                chap_user = self.get_chap_user_by_name(spec.target_chap_user_name)
                if chap_user is None:
                    self.connection_info.changed = False
                    raise ValueError(
                        SDSBChapUserValidationMsg.CHAP_USER_NAME_ABSENT.value.format(
                            spec.target_chap_user_name
                        )
                    )
                logger.writeDebug("RC:chap_user 2={}", chap_user)
                chap_user_id = chap_user.id
            else:
                raise ValueError(SDSBChapUserValidationMsg.NO_NAME_ID.value)

            cu_id = self.delete_chap_user_by_id(chap_user_id)
            if cu_id is not None:
                return "CHAP user has been deleted successfully."
            else:
                self.connection_info.changed = False
                return "Could not delete CHAP user, ensure CHAP user ID is valid. "
