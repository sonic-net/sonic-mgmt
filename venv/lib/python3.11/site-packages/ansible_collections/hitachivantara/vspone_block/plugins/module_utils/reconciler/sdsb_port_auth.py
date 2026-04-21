try:
    from ..provisioner.sdsb_port_auth_provisioner import SDSBPortAuthProvisioner
    from ..provisioner.sdsb_chap_user_provisioner import SDSBChapUserProvisioner
    from ..common.hv_constants import StateValue
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..message.sdsb_port_auth_msgs import SDSBPortAuthValidationMsg
    from .sdsb_port import SDSBPortReconciler
except ImportError:
    from provisioner.sdsb_port_auth_provisioner import SDSBPortAuthProvisioner
    from provisioner.sdsb_chap_user_provisioner import SDSBChapUserProvisioner
    from common.hv_constants import StateValue
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from message.sdsb_port_auth_msgs import SDSBPortAuthValidationMsg
    from .sdsb_port import SDSBPortReconciler

logger = Log()


class SDSBPortAuthSubstates:
    ADD_CHAP_USER = "add_chap_user"
    REMOVE_CHAP_USER = "remove_chap_user"


port_auth_mode_dict = {
    "chap": "CHAP",
    "chap_complying_with_initiator_setting": "CHAPComplyingWithInitiatorSetting",
    "none": "None",
}


class SDSBPortAuthReconciler:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBPortAuthProvisioner(self.connection_info)

    @log_entry_exit
    def reconcile_port_auth(self, state, spec):
        logger.writeDebug("RC:=== reconcile PORT AUTH===")

        if spec is None:
            raise ValueError(SDSBPortAuthValidationMsg.NO_SPEC.value)

        if state is None:
            state = StateValue.PRESENT
        if state.lower() == StateValue.PRESENT:
            if spec.port_name is None:
                raise ValueError(SDSBPortAuthValidationMsg.PORT_NAME_ABSENT.value)

            if spec.authentication_mode is not None:
                auth_mode = port_auth_mode_dict.get(spec.authentication_mode.lower())
                if auth_mode is None:
                    raise ValueError(
                        SDSBPortAuthValidationMsg.INVALID_AUTH_MODE.value.format(
                            spec.authentication_mode
                        )
                    )
                spec.authentication_mode = auth_mode

            port = self.get_port_by_name(spec.port_name)
            logger.writeDebug("RC:reconcile_port_auth:port = {}", port)
            if port is None:
                raise ValueError(
                    SDSBPortAuthValidationMsg.PORT_NOT_FOUND.value.format(
                        spec.port_name
                    )
                )
            port_id = port.id

            if spec.target_chap_users is not None and len(spec.target_chap_users) > 0:
                logger.writeDebug(
                    "RC:reconcile_port_auth:target_chap_users = {}",
                    spec.target_chap_users,
                )
                if spec.target_chap_users[0] is None:
                    raise ValueError(
                        SDSBPortAuthValidationMsg.INVALID_CHAP_USER_LIST.value
                    )
                if spec.state is None:
                    spec.state = SDSBPortAuthSubstates.ADD_CHAP_USER
                    self.add_chap_user_to_port(port_id, spec.target_chap_users)
                else:
                    if spec.state.lower() == SDSBPortAuthSubstates.ADD_CHAP_USER:
                        self.add_chap_user_to_port(port_id, spec.target_chap_users)
                    elif spec.state.lower() == SDSBPortAuthSubstates.REMOVE_CHAP_USER:
                        self.remove_chap_user_from_port(port_id, spec.target_chap_users)
                    else:
                        raise ValueError(
                            SDSBPortAuthValidationMsg.INVALID_SPEC_STATE.value.format(
                                SDSBPortAuthSubstates.ADD_CHAP_USER,
                                SDSBPortAuthSubstates.REMOVE_CHAP_USER,
                            )
                        )

            self.update_sdsb_port_auth_settings(port_id, spec)

            port_recon = SDSBPortReconciler(self.connection_info)
            # return self.get_port_by_name(spec.port_name)
            return port_recon.get_detail_port(port_id)

        if state.lower() == StateValue.ABSENT:
            logger.writeDebug("RC:=== Delete Port Auth ===")
            logger.writeDebug("RC:state = {}", state)
            logger.writeDebug("RC:spec = {}", spec)

            raise ValueError(SDSBPortAuthValidationMsg.NOT_SUPPORTED.value)

    @log_entry_exit
    def add_chap_user_to_port(self, port_id, target_chap_users):
        chap_user_prov = SDSBChapUserProvisioner(self.connection_info)
        all_chap_users = chap_user_prov.get_chap_users(spec=None)
        logger.writeDebug(
            "RC:add_chap_user_to_port:all_chap_users = {}", all_chap_users
        )

        target_chaps_dict = dict()
        for tcu in target_chap_users:
            for cu in all_chap_users.data:
                if cu.targetChapUserName == tcu:
                    target_chaps_dict[tcu] = cu.id

        logger.writeDebug(
            "RC:add_chap_user_to_port:target_chaps_dict = {}", target_chaps_dict
        )
        if len(target_chaps_dict) != len(target_chap_users):
            raise ValueError(SDSBPortAuthValidationMsg.CHAP_USERS_ABSENT.value)

        port_chap_users = self.get_port_chap_users(port_id)
        logger.writeDebug(
            "RC:add_chap_user_to_port:port_chap_users = {}", port_chap_users
        )
        chap_ids_to_add = []
        for pcu in port_chap_users.data:
            key = pcu.targetChapUserName
            if key in target_chaps_dict:
                del target_chaps_dict[key]
        chap_ids_to_add = target_chaps_dict.values()
        logger.writeDebug(
            "RC:add_chap_user_to_port:chap_ids_to_add = {}", chap_ids_to_add
        )
        if len(chap_ids_to_add) == 0:
            return
        self.allow_chap_users_to_access_port(port_id, chap_ids_to_add)

    @log_entry_exit
    def allow_chap_users_to_access_port(self, port_id, chap_ids_to_add):
        for chap_user_id in chap_ids_to_add:
            self.provisioner.allow_chap_users_to_access_port(port_id, chap_user_id)
        self.connection_info.changed = True

    @log_entry_exit
    def remove_chap_user_from_port(self, port_id, target_chap_users):
        port_chap_users = self.get_port_chap_users(port_id)
        chap_ids_to_remove = []
        for tcu in target_chap_users:
            for pcu in port_chap_users.data:
                if pcu.targetChapUserName == tcu:
                    chap_ids_to_remove.append(pcu.id)
        if len(chap_ids_to_remove) == 0:
            return
        self.remove_chap_user_access_from_port(port_id, chap_ids_to_remove)

    @log_entry_exit
    def remove_chap_user_access_from_port(self, port_id, chap_ids_to_remove):
        logger.writeDebug(
            "RC:remove_chap_user_access_from_port:chap_ids_to_remove = {}",
            chap_ids_to_remove,
        )
        for chap_user_id in chap_ids_to_remove:
            self.provisioner.remove_chap_user_access_from_port(port_id, chap_user_id)
        self.connection_info.changed = True

    @log_entry_exit
    def get_port_chap_users(self, port_id):
        return self.provisioner.get_port_chap_users(port_id)

    @log_entry_exit
    def get_port_by_name(self, port_name):
        return self.provisioner.get_port_by_name(port_name)

    @log_entry_exit
    def get_port_auth_settings(self, port_id):
        return self.provisioner.get_port_auth_settings(port_id)

    @log_entry_exit
    def update_sdsb_port_auth_settings(self, port_id, spec):
        changed = False
        port_auth_setting = self.get_port_auth_settings(port_id)
        logger.writeDebug(
            "RC:update_sdsb_port_auth_settings:port_auth_setting = {}",
            port_auth_setting,
        )

        if spec.authentication_mode is None:
            auth_mode = port_auth_setting.authMode
        else:
            if spec.authentication_mode != port_auth_setting.authMode:
                changed = True
                auth_mode = spec.authentication_mode

        is_discovery_chap_auth = False
        if spec.is_discovery_chap_authentication is None:
            is_discovery_chap_auth = port_auth_setting.isDiscoveryChapAuth
        else:
            if (
                spec.is_discovery_chap_authentication
                != port_auth_setting.isDiscoveryChapAuth
            ):
                changed = True
                is_discovery_chap_auth = spec.is_discovery_chap_authentication

        if changed is True:
            if auth_mode == "CHAP":
                is_mutual_chap_auth = True
            else:
                is_mutual_chap_auth = False
            self.update_port_auth_settings(
                port_id, auth_mode, is_discovery_chap_auth, is_mutual_chap_auth
            )

    @log_entry_exit
    def update_port_auth_settings(
        self, port_id, auth_mode, is_discovery_chap_auth, is_mutual_chap_auth
    ):
        self.connection_info.changed = True
        self.provisioner.update_port_auth_settings(
            port_id, auth_mode, is_discovery_chap_auth, is_mutual_chap_auth
        )
