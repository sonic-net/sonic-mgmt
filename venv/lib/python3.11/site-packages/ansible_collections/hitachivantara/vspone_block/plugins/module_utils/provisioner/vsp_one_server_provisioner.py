from ..common.ansible_common import log_entry_exit
from ..common.hv_log import (
    Log,
)
from ..gateway.vsp_one_server_gateway import VspServerSimpleApiGateway
from ..message.vsp_lun_msgs import VSPVolumeMSG
from ..message.vsp_one_server_msgs import VSPOneServerMSG
import re
from ..model.vsp_one_server_models import (
    CreateServerSpec,
    ServerFactsSpec,
    VspOneServerResponse,
)

logger = Log()


FC = "FC"
ISCSI = "ISCSI"


def check_server_exists(func):
    """
    Decorator to check if server exists before executing the method
    """

    def wrapper(self, *args, **kwargs):
        # Extract server_id from arguments
        server_id = None
        if len(args) == 1:
            # Check if first argument is server_id (int)
            if args and isinstance(args[0], int):
                server_id = args[0]
            # Check if spec object has server_id attribute
            elif (
                args and hasattr(args[0], "server_id") and args[0].server_id is not None
            ):
                server_id = args[0].server_id
            # Check in kwargs
            elif "server_id" in kwargs and kwargs["server_id"] is not None:
                server_id = kwargs["server_id"]
            # Check if spec object has nick_name and get server_id by nick_name
            elif args and hasattr(args[0], "nick_name") and args[0].nick_name:

                existing_server = self.get_server_by_nick_name(args[0].nick_name)
                if existing_server:
                    server_id = existing_server.id

            # Validate that either server_id or nick_name was provided and resolved
            if server_id is None:
                # Check if nick_name was provided but server not found
                if args and hasattr(args[0], "nick_name") and args[0].nick_name:
                    raise ValueError(
                        VSPOneServerMSG.SERVER_WITH_NICKNAME_NOT_FOUND.value.format(
                            nickname=args[0].nick_name
                        )
                    )
                else:
                    raise ValueError(
                        VSPOneServerMSG.SERVER_ID_OR_NICKNAME_REQUIRED.value
                    )

            # Check if server exists
            try:
                existing_server = self.get_server_by_id(server_id)
                if not existing_server:
                    raise ValueError(
                        VSPOneServerMSG.SERVER_WITH_ID_NOT_EXIST.value.format(
                            server_id=server_id
                        )
                    )
                # Ensure spec has server_id set
                args[0].server_id = server_id
                args = list(args)
                if len(args) < 2:
                    # Pass server object to method
                    args.append(existing_server)
                else:
                    # Pass server object to method
                    args[1] = existing_server
                args = tuple(args)
            except Exception as e:
                raise ValueError(
                    VSPOneServerMSG.ERROR_CHECKING_SERVER_EXISTENCE.value.format(
                        error=str(e)
                    )
                )

        func(self, *args, **kwargs)
        server = self.get_server_by_id_with_details(server_id)
        return server.camel_to_snake_dict() if server else None

    return wrapper


class VSPServerSimpleApiProvisioner:
    """
    VSPServerSimpleApiProvisioner
    """

    def __init__(self, connection_info):
        self.gateway = VspServerSimpleApiGateway(connection_info)
        self.connection_info = connection_info
        if not self.gateway.is_pegasus:
            raise Exception(VSPVolumeMSG.ONLY_SUPPORTED_ON_PEGASUS.value)

    @log_entry_exit
    def create_update_server(self, spec: CreateServerSpec):
        """
        Create server
        """
        existing_server = None
        if spec.server_id is not None:
            existing_server = (
                self.get_server_by_id(spec.server_id) if spec.server_id else None
            )
        elif spec.nick_name is not None:
            existing_server = self.get_server_by_nick_name(spec.nick_name)

        if existing_server:
            spec.server_id = existing_server.id
            self.update_server_settings(spec, existing_server)
        else:
            try:
                response = self.register_server(spec)
                spec.server_id = response
                self.connection_info.changed = True

            except Exception as e:
                logger.writeError(
                    VSPOneServerMSG.ERROR_CREATING_SERVER.value.format(str(e))
                )

                spec.errors.append(
                    VSPOneServerMSG.ERROR_CREATING_SERVER.value.format(str(e))
                )
                return None

            if spec.hbas and len(spec.hbas) > 0:
                self.add_wwn_of_hba(spec, spec.server_id)

            if spec.paths is not None:
                self.add_path_to_server(spec, spec.server_id)

            if spec.host_groups is not None:
                self.add_hg_to_server(spec, spec.server_id)

            if spec.iscsi_targets is not None:
                self.add_hg_to_server(spec, spec.server_id)

        existing_server = self.get_server_by_id_with_details(spec.server_id)

        return existing_server.camel_to_snake_dict()

    @log_entry_exit
    def register_server(self, spec: CreateServerSpec):
        """
        Register server
        """
        if spec.protocol == ISCSI and spec.hbas and spec.hbas[0].iscsi_name is None:
            raise ValueError(VSPOneServerMSG.ISCSI_NAME_REQUIRED_FOR_ISCSI.value)
        elif spec.protocol == FC and spec.hbas and spec.hbas[0].hba_wwn is None:
            raise ValueError(VSPOneServerMSG.HBA_WWN_REQUIRED_FOR_FC.value)

        return self.gateway.register_server(spec)

    @log_entry_exit
    def delete_server(self, spec: CreateServerSpec, server_object=None):
        """
        Delete server

        """
        if spec.server_id is not None:
            existing_server = (
                self.get_server_by_id(spec.server_id) if spec.server_id else None
            )
        elif spec.nick_name is not None:
            existing_server = self.get_server_by_nick_name(spec.nick_name)

        if not existing_server:
            spec.comments.append(VSPOneServerMSG.SERVER_NOT_FOUND_OR_DELETED.value)
            return
        spec.server_id = existing_server.id
        try:
            self.gateway.delete_server(spec.server_id, spec)
            self.connection_info.changed = True
            spec.comments.append(VSPOneServerMSG.SERVER_DELETED_SUCCESS.value)
        except Exception as e:
            logger.writeError(
                VSPOneServerMSG.ERROR_DELETING_SERVER.value.format(error=e)
            )
            spec.errors.append(
                VSPOneServerMSG.ERROR_DELETING_SERVER.value.format(error=e)
            )
        return

    @log_entry_exit
    def update_server_settings(self, spec: CreateServerSpec, server):
        """
        Handle existing server
        """
        if spec.os_type is not None and spec.os_type == server.osType:
            spec.os_type = None  # No change needed
        if spec.nick_name is not None and spec.nick_name == server.nickname:
            spec.nick_name = None  # No change needed

        try:
            response = self.gateway.change_server_settings(spec.server_id, spec)
            if response:
                self.connection_info.changed = True
                spec.comments.append(VSPOneServerMSG.SERVER_UPDATED_SUCCESS.value)
        except Exception as e:
            logger.writeError(
                VSPOneServerMSG.ERROR_UPDATING_SERVER.value.format(error=e)
            )
            spec.errors.append(
                VSPOneServerMSG.ERROR_UPDATING_SERVER.value.format(error=e)
            )

    @check_server_exists
    @log_entry_exit
    def add_hg_to_server(self, spec: CreateServerSpec, server_object=None):
        """
        Add host group to server
        """
        try:
            self.gateway.add_hg_to_server(spec.server_id, spec)
            self.connection_info.changed = True
            spec.comments.append(VSPOneServerMSG.HOST_GROUP_ADDED_SUCCESS.value)
        except Exception as e:
            logger.writeError(
                VSPOneServerMSG.ERROR_ADDING_HOST_GROUP.value.format(error=e)
            )
            spec.errors.append(
                VSPOneServerMSG.ERROR_ADDING_HOST_GROUP.value.format(error=e)
            )

    @log_entry_exit
    @check_server_exists
    def add_path_to_server(self, spec, server_object=None):
        """
        Add path to server
        """
        if not self._validate_hba_for_protocol(spec, server_object):
            return

        if spec.paths is None or len(spec.paths) == 0:
            raise ValueError(VSPOneServerMSG.PATHS_LIST_REQUIRED.value)
        for path in spec.paths:
            try:
                response = self.gateway.add_path_to_server(spec.server_id, path)
                self.connection_info.changed = True
                spec.comments.append(
                    VSPOneServerMSG.PATH_ADDED_SUCCESS.value.format(
                        port_ids=path.port_ids
                    )
                )
            except Exception as e:
                logger.writeError(
                    VSPOneServerMSG.ERROR_VALIDATING_EXISTING_PATHS.value.format(
                        error=e
                    )
                )
                spec.errors.append(
                    VSPOneServerMSG.ERROR_VALIDATING_EXISTING_PATHS.value.format(
                        error=e
                    )
                )
                return None

        return response

    @log_entry_exit
    @check_server_exists
    def remove_path_from_server(self, spec: ServerFactsSpec, server_object=None):
        """
        Remove path from server
        """
        if not self._validate_hba_for_protocol(spec, server_object):
            return

        if spec.paths is None or len(spec.paths) == 0:
            raise ValueError(VSPOneServerMSG.PATHS_LIST_REQUIRED.value)
        for path in spec.paths:
            try:
                for port_id in path.port_ids:
                    self.gateway.remove_path_from_server(
                        spec.server_id, port_id, path.iscsi_name, path.hba_wwn
                    )
                    spec.comments.append(
                        VSPOneServerMSG.PATH_REMOVED_SUCCESS.value.format(
                            port_id=port_id
                        )
                    )
                    self.connection_info.changed = True
            except Exception as e:
                logger.writeError(
                    VSPOneServerMSG.ERROR_REMOVING_PATH.value.format(error=e)
                )
                spec.errors.append(
                    VSPOneServerMSG.ERROR_REMOVING_PATH.value.format(error=e)
                )
        return

    @log_entry_exit
    def change_server_settings(self, server_id, spec):
        """
        Change server settings
        """
        response = self.gateway.change_server_settings(server_id, spec)
        return response

    @log_entry_exit
    def get_servers(self, query: str = None):
        """
        Get servers
        """
        response = self.gateway.get_servers(query)
        return response

    @log_entry_exit
    def get_server_by_id(self, server_id: int):
        """
        Get server
        """
        response = self.gateway.get_server_by_id(server_id)
        return response

    @log_entry_exit
    def get_server_by_id_with_details(self, server_id: int):
        """
        Get server
        """
        response = self.gateway.get_server_by_id_with_details(server_id)
        return response

    @log_entry_exit
    def get_server_by_nick_name(self, nick_name: str):
        """
        Get server by nick name
        """
        pattern = r"^[\w,./:@\\]([\w,\-./:@\\ ]*[\w,\-./:@\\])?$"

        if not re.match(pattern, nick_name):
            raise ValueError(VSPOneServerMSG.NAME_ERROR.value)

        try:
            response = self.gateway.get_all_servers_with_filter(nick_name=nick_name)
            if len(response.data) > 0:
                return response.data[0]
        except Exception as ex:
            logger.writeError(f"Error getting server with nick name {nick_name}: {ex}")
            return None
        return None

    @log_entry_exit
    @check_server_exists
    def sync_server_nick_name(self, spec: ServerFactsSpec, server_object=None):
        """
        Sync server nick name
        """
        response = self.gateway.sync_server_nick_name(spec.server_id)
        self.connection_info.changed = True
        spec.comments.append(VSPOneServerMSG.SERVER_NICKNAME_SYNCED_SUCCESS.value)
        return response

    @log_entry_exit
    @check_server_exists
    def add_wwn_of_hba(self, spec: CreateServerSpec, server_object=None):
        """
        Add wwn of hba to server spec
        """
        if not spec.hbas or len(spec.hbas) == 0:
            raise ValueError(VSPOneServerMSG.HBA_LIST_REQUIRED.value)

        if not self._validate_hba_for_protocol(spec, server_object):
            return

        if isinstance(server_object, VspOneServerResponse):

            hba_wwns = [
                hba.hbaWwn for hba in server_object.paths if hba.hbaWwn is not None
            ]
            if not hba_wwns:
                hba_wwns = [
                    hba.iscsiName
                    for hba in server_object.paths
                    if hba.iscsiName is not None
                ]
            for hba in spec.hbas:
                if (hba.hba_wwn in hba_wwns) or (hba.iscsi_name in hba_wwns):
                    spec.hbas.remove(hba)

            if len(spec.hbas) == 0:
                logger.writeInfo("No new HBAs to add after filtering.")
                spec.comments.append(VSPOneServerMSG.NO_NEW_HBAS_TO_ADD.value)
                return None
        response = self.gateway.add_wwn_of_hba(spec)
        self.connection_info.changed = True
        spec.comments.append(VSPOneServerMSG.WWN_HBA_ADDED_SUCCESS.value)
        return response

    @log_entry_exit
    @check_server_exists
    def remove_wwn_of_hba(self, spec: CreateServerSpec, server_object=None):
        """
        Remove wwn of hba from server spec
        """
        if not spec.hbas or len(spec.hbas) == 0:
            raise ValueError(VSPOneServerMSG.HBA_LIST_REQUIRED.value)

        if not self._validate_hba_for_protocol(spec, server_object):
            return

        try:
            hbas = [hba.hbaWwn or hba.iscsiName for hba in server_object.paths]
            if not hbas:
                return None
            for hba in spec.hbas:
                if (hba.hba_wwn or hba.iscsi_name) in hbas:
                    wwn_or_iscsi = hba.hba_wwn if hba.hba_wwn else hba.iscsi_name
                    self.gateway.remove_wwn_of_hba(spec.server_id, wwn_or_iscsi)

                    spec.comments.append(
                        VSPOneServerMSG.WWN_HBA_REMOVED_SUCCESS.value.format(
                            wwn_or_iscsi=wwn_or_iscsi
                        )
                    )
                    self.connection_info.changed = True
        except Exception as e:
            logger.writeError(
                VSPOneServerMSG.ERROR_REMOVING_WWN_HBA.value.format(error=e)
            )
            spec.errors.append(
                VSPOneServerMSG.ERROR_REMOVING_WWN_HBA.value.format(error=e)
            )
        return

    @log_entry_exit
    @check_server_exists
    def change_iscsi_target_settings(self, spec: CreateServerSpec, server_object=None):
        """
        Change iscsi target settings
        """
        if spec.iscsi_target_settings is None:
            raise ValueError(VSPOneServerMSG.ISCSI_TARGET_PORT_ID_REQUIRED.value)

        for target in spec.iscsi_target_settings:
            if target.port_id is None or target.target_iscsi_name is None:
                raise ValueError(VSPOneServerMSG.ISCSI_TARGET_BOTH_REQUIRED.value)
            try:
                unused = self.gateway.change_iscsi_target_settings(
                    spec.server_id, target.port_id, target.target_iscsi_name
                )
                self.connection_info.changed = True
                spec.comments.append(
                    VSPOneServerMSG.ISCSI_TARGET_CHANGED_SUCCESS.value.format(
                        port_id=target.port_id
                    )
                )
            except Exception as e:
                logger.writeError(
                    VSPOneServerMSG.ERROR_CHANGING_ISCSI_TARGET.value.format(
                        port_id=target.port_id, error=e
                    )
                )
                spec.errors.append(
                    VSPOneServerMSG.ERROR_CHANGING_ISCSI_TARGET.value.format(
                        port_id=target.port_id, error=e
                    )
                )
        return

    @log_entry_exit
    def get_server_hbas(self, spec):
        """
        Get HBAs for a server
        """
        if spec.server_id is None and spec.nick_name is None:
            raise ValueError(VSPOneServerMSG.SERVER_ID_NAME_REQUIRED.value)

        if spec.server_id is None and spec.nick_name is not None:
            existing_server = self.get_server_by_nick_name(spec.nick_name)
            if existing_server:
                spec.server_id = existing_server.id
            else:
                raise ValueError(
                    VSPOneServerMSG.SERVER_WITH_NICKNAME_NOT_FOUND.value.format(
                        nickname=spec.nick_name
                    )
                )
        if spec.hba_wwn is not None or spec.iscsi_name is not None:
            existing_hba = self.gateway.get_hba_by_wwn(
                spec.server_id,
                spec.hba_wwn if spec.hba_wwn is not None else spec.iscsi_name,
            )
            if existing_hba:
                return existing_hba.camel_to_snake_dict()
            else:
                return "HBA not found."
        else:
            hbas = self.gateway.get_hbas_by_server_id(spec.server_id)
            return hbas.data_to_snake_case_list() if hbas else []

    def _validate_hba_for_protocol(self, spec: CreateServerSpec, server_object=None):
        """
        Validate HBA based on server protocol
        """

        if isinstance(server_object, VspOneServerResponse):
            if server_object.protocol.upper() == ISCSI:
                # Check if all HBAs have iscsi_name when HBAs are provided
                if spec.hbas and all(hba.iscsi_name is None for hba in spec.hbas):
                    spec.errors.append(
                        VSPOneServerMSG.ISCSI_NAME_REQUIRED_FOR_ISCSI.value
                    )
                    return False
                # Check if all paths have iscsi_name when paths are provided
                if spec.paths and any(path.iscsi_name is None for path in spec.paths):
                    spec.errors.append(
                        VSPOneServerMSG.ISCSI_NAME_REQUIRED_FOR_ISCSI.value
                    )
                    return False
            elif server_object.protocol.upper() == FC:
                # Check if all HBAs have hba_wwn when HBAs are provided
                if spec.hbas and any(hba.hba_wwn is None for hba in spec.hbas):
                    spec.errors.append(VSPOneServerMSG.HBA_WWN_REQUIRED_FOR_FC.value)
                    return False
                if spec.paths and all(path.hba_wwn is None for path in spec.paths):
                    spec.errors.append(VSPOneServerMSG.HBA_WWN_REQUIRED_FOR_FC.value)
                    return False
        return True
