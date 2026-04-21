try:
    from ..provisioner.vsp_iscsi_target_provisioner import VSPIscsiTargetProvisioner
    from ..common.ansible_common import (
        camel_to_snake_case,
        camel_array_to_snake_case,
        camel_dict_to_snake_case,
        generate_random_name_prefix_string,
    )
    from ..common.hv_log import Log
    from ..model.vsp_iscsi_target_models import (
        IscsiTargetPayLoad,
        VSPIscsiTargetModificationInfo,
        IscsiTargetSpec,
    )
    from ..common.hv_constants import VSPIscsiTargetConstant, StateValue
    from ..gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from ..message.vsp_iscsi_target_msgs import VSPIscsiTargetMessage
except ImportError:
    from provisioner.vsp_iscsi_target_provisioner import VSPIscsiTargetProvisioner
    from common.ansible_common import (
        camel_to_snake_case,
        camel_array_to_snake_case,
        camel_dict_to_snake_case,
        generate_random_name_prefix_string,
    )
    from common.hv_log import Log
    from model.vsp_iscsi_target_models import (
        IscsiTargetPayLoad,
        VSPIscsiTargetModificationInfo,
        IscsiTargetSpec,
    )
    from common.hv_constants import VSPIscsiTargetConstant, StateValue
    from gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from message.vsp_iscsi_target_msgs import VSPIscsiTargetMessage


class VSPIscsiTargetReconciler:

    def __init__(self, connection_info, serial):
        self.connection_info = connection_info
        self.serial = serial
        if self.serial is None:
            self.serial = self.get_storage_serial_number()
        self.provisioner = VSPIscsiTargetProvisioner(self.connection_info)

    def get_iscsi_targets(self, spec):
        return self.provisioner.get_iscsi_targets(spec, self.serial)

    def get_storage_serial_number(self):
        storage_gw = VSPStorageSystemDirectGateway(self.connection_info)
        storage_system = storage_gw.get_current_storage_system_info()
        return storage_system.serialNumber

    def pre_check_sub_state(self, spec):
        sub_state = spec.state
        if sub_state not in (
            StateValue.PRESENT,
            StateValue.ABSENT,
            VSPIscsiTargetConstant.STATE_ADD_INITIATOR,
            VSPIscsiTargetConstant.STATE_REMOVE_INITIATOR,
            VSPIscsiTargetConstant.STATE_ATTACH_LDEV,
            VSPIscsiTargetConstant.STATE_DETACH_LDEV,
            VSPIscsiTargetConstant.STATE_ADD_CHAP_USER,
            VSPIscsiTargetConstant.STATE_REMOVE_CHAP_USER,
        ):
            raise Exception(VSPIscsiTargetMessage.SPEC_STATE_INVALID.value)

        if (
            sub_state == VSPIscsiTargetConstant.STATE_ATTACH_LDEV
            or sub_state == VSPIscsiTargetConstant.STATE_DETACH_LDEV
        ):
            spec.chap_users = None
            spec.iqn_initiators = None
        elif (
            sub_state == VSPIscsiTargetConstant.STATE_ADD_INITIATOR
            or sub_state == VSPIscsiTargetConstant.STATE_REMOVE_INITIATOR
        ):
            spec.chap_users = None
            spec.ldevs = None
        elif (
            sub_state == VSPIscsiTargetConstant.STATE_ADD_CHAP_USER
            or sub_state == VSPIscsiTargetConstant.STATE_REMOVE_CHAP_USER
        ):
            spec.ldevs = None
            spec.iqn_initiators = None

    def pre_check_port(self, port):
        logger = Log()
        logger.writeDebug("port = {}", port)
        if not port:
            raise Exception("Port {} is not in the storage system.".format(port))
        if port:
            # before the subobjState change
            # make sure all the ports are defined in the storage
            # so we can add comments properly
            sports = self.provisioner.get_ports(self.serial).data
            logger.writeDebug("sports = {}", sports)
            found = [x for x in sports if x.portId == port]
            logger.writeDebug("found={}", found)
            if found is None or len(found) == 0:
                raise Exception("Port {} is not in the storage system.".format(port))

    def handle_create_iscsi_target(self, spec, result):
        if not spec.port:
            raise Exception(VSPIscsiTargetMessage.PORTS_PARAMETER_INVALID.value)
        logger = Log()
        spec.name = generate_random_name_prefix_string() if not spec.name else spec.name
        logger.writeDebug("spec.port={0}".format(spec.port))
        try:
            self.provisioner.create_one_iscsi_target(
                IscsiTargetPayLoad(
                    name=spec.name,
                    port=spec.port,
                    host_mode=spec.host_mode,
                    host_mode_options=spec.host_mode_options,
                    luns=spec.ldevs,
                    iqn_initiators=spec.iqn_initiators,
                    chap_users=spec.chap_users,
                    iscsi_id=spec.iscsi_id,
                ),
                self.serial,
            )
        except Exception as e:
            if VSPIscsiTargetMessage.CATCH_MSG_ISCSI_TARGET.value in str(e):
                spec.name = generate_random_name_prefix_string()
                return self.handle_create_iscsi_target(spec, result)
            else:
                raise e
        one_iscsi_info = self.provisioner.get_one_iscsi_target(
            spec.port, spec.name, self.serial
        ).data
        logger.writeDebug("060525 one_iscsi_info={}", one_iscsi_info)
        result["iscsiTarget"] = one_iscsi_info
        result["changed"] = True
        return one_iscsi_info

    def handle_update_iscsi_target(self, spec, iscsi_target, result):
        logger = Log()
        sub_state = spec.state
        logger.writeDebug("sub_state={}", sub_state)

        logger.writeDebug("update iscsi_target={}", iscsi_target)
        logger.writeDebug("update HgName={}", iscsi_target.iscsiName)
        logger.writeDebug("update Port={}", iscsi_target.portId)

        port = iscsi_target.portId
        logger.writeDebug("processing port={}", port)

        logger.writeDebug("check host_mode and host_optlist for update")
        if spec.host_mode is not None or spec.host_mode_options is not None:
            self.handle_update_host_mode(
                spec.state, spec.host_mode, spec.host_mode_options, iscsi_target, result
            )

        logger.writeDebug("check iqn_initiators for update")
        if spec.iqn_initiators:  # If iqn_initiators is present, update iqn_initiators
            self.handle_update_iqn_initiators(
                spec.state, spec.iqn_initiators, iscsi_target, result
            )

        logger.writeDebug("check luns for update")
        if spec.ldevs:  # If ldevs is present, present or overwrite ldevs
            self.handle_update_luns(spec.state, spec.ldevs, iscsi_target, result)

        logger.writeDebug("check chap users for update")
        if spec.chap_users:  # If chap_users is present, update chap_users
            self.handle_update_chap_users(
                spec.state, spec.chap_users, iscsi_target, result
            )

    def handle_update_host_mode(
        self, state, host_mode, host_mode_options, iscsi_target, result
    ):
        logger = Log()
        if host_mode is None:
            host_mode = iscsi_target.hostMode.hostMode
        # for host_mode, you can only update, no delete
        logger.writeDebug("update host_mode={}", host_mode)
        logger.writeDebug(
            "iscsi_target.hostMode.hostMode={}", iscsi_target.hostMode.hostMode
        )

        iscsi_target_hmo = [
            opt.raidOptionNumber for opt in iscsi_target.hostMode.hostModeOptions or []
        ]
        logger.writeDebug("iscsi_target_hmo={}", iscsi_target_hmo)
        logger.writeDebug("host_mode_options={}", host_mode_options)
        if host_mode_options is not None:
            old_list = set(iscsi_target_hmo)
            new_list = set(host_mode_options)
            new_list - old_list

            # if state == VSPIscsiTargetConstant.STATE_ADD_HOST_MODE or state == StateValue.PRESENT:
            #     # # add = new - old
            #     host_opt = iscsi_target_hmo + list(add_list)
            # elif state == VSPIscsiTargetConstant.STATE_REMOVE_HOST_MODE or state == StateValue.ABSENT:
            #     # del = old & new
            #     host_opt = list(set(iscsi_target_hmo) - set(host_mode_options))
            # else:
            #     logger.writeInfo("No changed")
            #     return
            host_opt = host_mode_options
        else:
            host_opt = iscsi_target_hmo
        logger.writeDebug("update host_opt={}", host_opt)

        if host_mode != iscsi_target.hostMode.hostMode or set(host_opt) != set(
            iscsi_target_hmo
        ):
            logger.writeDebug("call set_host_mode()")
            self.provisioner.set_host_mode(
                iscsi_target, host_mode, list(host_opt), self.serial
            )
            result["changed"] = True

    def handle_update_iqn_initiators(
        self, state, iqn_initiators_new, iscsi_target, result
    ):
        logger = Log()
        iqn_initiators = set(iqn.iqn for iqn in iqn_initiators_new)
        iscsi_target_iqn_initiators = set(
            iqnInitiator.iqn for iqnInitiator in iscsi_target.iqnInitiators or []
        )
        logger.writeDebug("iqn_initiators={0}", iqn_initiators)
        add_iqn_initiators = iqn_initiators - iscsi_target_iqn_initiators
        del_iqn_initiators = iscsi_target_iqn_initiators.intersection(iqn_initiators)
        logger.writeDebug(
            "iscsi_target_iqn_initiators={0}", iscsi_target_iqn_initiators
        )
        logger.writeDebug("add_iqn_initiators={0}", add_iqn_initiators)
        logger.writeDebug("del_iqn_initiators={0}", del_iqn_initiators)
        add_iqns_with_nick_names = [
            iqn for iqn in iqn_initiators_new if iqn.iqn in add_iqn_initiators
        ]

        if (
            state == VSPIscsiTargetConstant.STATE_ADD_INITIATOR
            or state == StateValue.PRESENT
        ) and add_iqn_initiators:
            if len(add_iqn_initiators) > 0:
                self.provisioner.add_iqn_initiators_to_iscsi_target(
                    iscsi_target, add_iqns_with_nick_names, self.serial
                )
                result["changed"] = True

        if (
            state == VSPIscsiTargetConstant.STATE_REMOVE_INITIATOR
            or state == StateValue.ABSENT
        ):
            if del_iqn_initiators:
                logger.writeDebug(
                    "delete_iqn_initiators_from_iscsi_target del_iqn_initiators={0}",
                    del_iqn_initiators,
                )
                if len(del_iqn_initiators) > 0:
                    self.provisioner.delete_iqn_initiators_from_iscsi_target(
                        iscsi_target, list(del_iqn_initiators), self.serial
                    )
                    result["changed"] = True
            else:
                result["comment"] = (
                    VSPIscsiTargetMessage.IQN_IS_NOT_IN_ISCSI_TARGET.value
                )

        for iqn_initiator in iqn_initiators_new:
            match_iqn = next(
                (
                    iqn
                    for iqn in iscsi_target.iqnInitiators
                    if iqn.iqn == iqn_initiator.iqn
                ),
                None,
            )
            if (
                match_iqn
                and iqn_initiator.nick_name is not None
                and match_iqn.nick_name != iqn_initiator.nick_name
            ):
                self.provisioner.update_iqn_nick_name(iscsi_target, iqn_initiator)
                result["changed"] = True

    def handle_update_luns(self, state, luns, iscsi_target, result):
        logger = Log()
        luns = set(luns)
        iscsi_target_luns = set(
            logicalUnit.logicalUnitId for logicalUnit in iscsi_target.logicalUnits or []
        )
        logger.writeDebug("newLun={0}", luns)
        add_luns = luns - iscsi_target_luns
        del_luns = iscsi_target_luns.intersection(luns)
        logger.writeDebug("iscsi_target_lun={0}", iscsi_target_luns)
        logger.writeDebug("add_luns={0}", add_luns)
        logger.writeDebug("del_luns={0}", del_luns)

        if (
            state == VSPIscsiTargetConstant.STATE_ATTACH_LDEV
            or state == StateValue.PRESENT
        ) and add_luns:
            if len(add_luns) > 0:
                self.provisioner.add_luns_to_iscsi_target(
                    iscsi_target, list(add_luns), self.serial
                )
                result["changed"] = True

        if (
            state == VSPIscsiTargetConstant.STATE_DETACH_LDEV
            or state == StateValue.ABSENT
        ):
            if del_luns:
                logger.writeDebug(
                    "delete_luns_from_iscsi_target del_luns={0}", del_luns
                )
                if len(del_luns) > 0:
                    self.provisioner.delete_luns_from_iscsi_target(
                        iscsi_target, list(del_luns), self.serial
                    )
                    result["changed"] = True
            else:
                result["comment"] = (
                    VSPIscsiTargetMessage.LUN_IS_NOT_IN_ISCSI_TARGET.value
                )

    def handle_update_chap_users(self, state, chap_users, iscsi_target, result):
        logger = Log()
        chap_user_names = set(chap_user.chap_user_name for chap_user in chap_users)
        iscsi_target_chap_users = set(
            chapUser for chapUser in iscsi_target.chapUsers or []
        )
        logger.writeDebug("chap_user_names={0}", chap_user_names)
        add_chap_users = []
        for chap_user in chap_users:
            if chap_user.chap_secret is not None:
                add_chap_users.append(chap_user)
            else:
                if chap_user.chap_user_name not in iscsi_target_chap_users:
                    add_chap_users.append(chap_user)
        del_chap_users = iscsi_target_chap_users.intersection(chap_user_names)
        logger.writeDebug("iscsi_target_chap_users={0}", iscsi_target_chap_users)
        logger.writeDebug("add_chap_users={0}", add_chap_users)
        logger.writeDebug("del_chap_users={0}", del_chap_users)

        if (
            state == VSPIscsiTargetConstant.STATE_ADD_CHAP_USER
            or state == StateValue.PRESENT
        ) and add_chap_users:
            if len(add_chap_users) > 0:
                self.provisioner.add_chap_users_to_iscsi_target(
                    iscsi_target, list(add_chap_users), self.serial
                )
                result["changed"] = True

        if (
            state == VSPIscsiTargetConstant.STATE_REMOVE_CHAP_USER
            or state == StateValue.ABSENT
        ):
            if del_chap_users:
                logger.writeDebug(
                    "delete_chap_users_from_iscsi_target del_chap_users={0}",
                    del_chap_users,
                )
                if len(del_chap_users) > 0:
                    self.provisioner.delete_chap_users_from_iscsi_target(
                        iscsi_target, list(del_chap_users), self.serial
                    )
                    result["changed"] = True
            else:
                result["comment"] = (
                    VSPIscsiTargetMessage.CHAP_USER_IS_NOT_IN_ISCSI_TARGET.value
                )

    def handle_delete_iscsi_target(self, spec, iscsi_target, result):
        Log()
        self.provisioner.delete_iscsi_target(
            iscsi_target, spec.should_delete_all_ldevs, self.serial
        )
        result["changed"] = True
        result["iscsiTarget"] = None

    def iscsi_target_reconciler(self, state, spec: IscsiTargetSpec):
        logger = Log()
        result = {"changed": False}
        self.pre_check_sub_state(spec)
        self.pre_check_port(spec.port)
        iscsi_target = None
        if spec.iscsi_id:
            iscsi_target = self.provisioner.get_one_iscsi_target_using_id(
                spec.port, spec.iscsi_id
            ).data
        elif spec.name and not iscsi_target:
            iscsi_target = self.provisioner.get_one_iscsi_target(
                spec.port, spec.name, self.serial
            ).data
        else:
            iscsi_target = None
        if state == StateValue.PRESENT:
            result["iscsiTarget"] = iscsi_target
            if iscsi_target is None:
                # Handle create iscsi target
                iscsi_target = self.handle_create_iscsi_target(spec, result)
            else:
                # Handle update iscsi target
                self.handle_update_iscsi_target(spec, iscsi_target, result)
            target_id = iscsi_target.iscsiId if iscsi_target else spec.iscsi_id
            logger.writeDebug(f"060525 target_id = {target_id}")

            if spec.should_release_host_reserve:
                self.provisioner.release_host_reservation_status(
                    spec.port, target_id, spec.lun
                )
                result["changed"] = True
                result["comment"] = (
                    VSPIscsiTargetMessage.RELEASE_HOST_RESERVE.value
                    if spec.lun is None
                    else VSPIscsiTargetMessage.RELEASE_HOST_RESERVE_LU.value.format(
                        spec.lun
                    )
                )
            if result["changed"]:
                result["iscsiTarget"] = self.provisioner.get_one_iscsi_target_using_id(
                    spec.port, target_id
                ).data

        elif state == StateValue.ABSENT:
            if iscsi_target is None:
                logger.writeInfo("No iscsi target found, state is absent, no change")
                result["comment"] = (
                    VSPIscsiTargetMessage.ISCSI_TARGET_HAS_BEEN_DELETED.value
                )
            else:
                if (
                    len(iscsi_target.logicalUnits) > 0
                    and not spec.should_delete_all_ldevs
                ):
                    result["comment"] = VSPIscsiTargetMessage.LDEVS_PRESENT.value
                else:
                    # Handle delete iscsi target
                    self.handle_delete_iscsi_target(spec, iscsi_target, result)

        return VSPIscsiTargetModificationInfo(**result)


class VSPIscsiTargetCommonPropertiesExtractor:
    def __init__(self):
        self.common_properties = {
            "portId": str,
            "hostMode": dict,
            "resourceGroupId": int,
            "iqn": str,
            "iqnInitiators": list,
            "logicalUnits": list,
            "authParam": dict,
            # "subscriberId": str,
            # "partnerId": str,
            "storageId": str,
            "chapUsers": list,
            "iscsiName": str,
            "iscsiId": int,
            # "entitlementStatus": str,
        }

        self.modification_properties = {
            "changed": bool,
            "comment": str,
            "comments": list,
            "iscsiTarget": dict,
        }

    def extract_iscsi_target(self, new_dict, response):
        for key, value_type in self.common_properties.items():
            # Get the corresponding key from the response or its mapped key
            response_key = None
            if key in response:
                response_key = response.get(key)
            # Assign the value based on the response key and its data type
            cased_key = camel_to_snake_case(key)
            if response_key is not None:
                new_dict[cased_key] = value_type(response_key)

    def extract(self, responses):
        new_items = []
        for response in responses:
            new_dict = {}
            self.extract_iscsi_target(new_dict, response)
            new_items.append(new_dict)
        new_items = camel_array_to_snake_case(new_items)
        return new_items

    def extract_dict(self, response):
        new_dict = {}
        for key, value_type in self.modification_properties.items():
            # Get the corresponding key from the response or its mapped key
            response_key = None
            if key in response:
                response_key = response.get(key)
            # Assign the value based on the response key and its data type
            cased_key = camel_to_snake_case(key)
            if response_key is not None:
                if key == "iscsiTarget":
                    new_dict[cased_key] = {}
                    self.extract_iscsi_target(new_dict[cased_key], response_key)
                else:
                    new_dict[cased_key] = value_type(response_key)
        new_dict = camel_dict_to_snake_case(new_dict)
        return new_dict
