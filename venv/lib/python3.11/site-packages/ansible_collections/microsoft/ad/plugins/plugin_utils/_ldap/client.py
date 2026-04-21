# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# FOR INTERNAL COLLECTION USE ONLY
# The interfaces in this file are meant for use within this collection
# and may not remain stable to outside uses. Changes may be made in ANY release, even a bugfix release.
# See also: https://github.com/ansible/community/issues/539#issuecomment-780839686
# Please open an issue if you have questions about this.

import dataclasses
import socket
import ssl
import threading
import typing as t

try:
    import sansldap
except Exception:
    pass  # Check is in __init__.py


MessageType = t.TypeVar("MessageType", bound="sansldap.LDAPMessage")


class Credential:
    """Credential for LDAP client.

    Base object used to implementation authentication for the LDAP client.
    """

    def authenticate(
        self,
        client: "SyncLDAPClient",
        *,
        tls_sock: t.Optional[ssl.SSLSocket] = None,
    ) -> None:
        raise NotImplementedError()


class MessageEncryptor:
    """Message encryptor for LDAP client.

    Base object used by the LDAP client to encrypt and decrypt messages.
    """

    def wrap(
        self,
        data: bytes,
    ) -> bytes:
        raise NotImplementedError()

    def unwrap(
        self,
        data: bytes,
    ) -> t.Tuple[bytes, int]:
        raise NotImplementedError()


class LDAPResultError(Exception):
    def __init__(
        self,
        msg: str,
        result: "sansldap.LDAPResult",
    ) -> None:
        super().__init__(msg)
        self.result = result

    def __str__(self) -> str:
        inner_msg = super().__str__()
        msg = f"Received LDAPResult error {inner_msg} - {self.result.result_code.name}"
        if self.result.matched_dn:
            msg += f" - Matched DN {self.result.matched_dn}"

        if self.result.diagnostics_message:
            msg += f" - {self.result.diagnostics_message}"

        return msg


class ResponseHandler(t.Generic[MessageType]):
    def __init__(
        self,
        message_id: int,
        message_types: t.Tuple[t.Type[MessageType], ...],
    ) -> None:
        self._message_id = message_id
        self._message_types = message_types
        self._condition = threading.Condition()
        self._exp: t.Optional[Exception] = None
        self._results: t.List[MessageType] = []

    def __iter__(self) -> t.Iterator[MessageType]:
        return self._iter_next()

    def append(
        self,
        value: t.Union[Exception, MessageType],
    ) -> None:
        with self._condition:
            if isinstance(value, Exception):
                self._exp = value
            elif isinstance(value, self._message_types) and value.message_id == self._message_id:
                self._results.append(value)
            else:
                return

            self._condition.notify_all()

    def _iter_next(self) -> t.Iterator[MessageType]:
        idx = 0
        while True:
            with self._condition:
                if self._exp:
                    raise Exception(f"Exception from receiving task: {self._exp}") from self._exp

                if idx < len(self._results):
                    value = self._results[idx]
                    idx += 1
                    yield value

                else:
                    self._condition.wait()


@dataclasses.dataclass(frozen=True)
class RootDSE:
    default_naming_context: str
    subschema_subentry: str
    supported_controls: t.List[str]


class SyncLDAPClient:
    def __init__(
        self,
        server: str,
        protocol: "sansldap.LDAPClient",
        sock: t.Union[socket.socket, ssl.SSLSocket],
    ) -> None:
        self.server = server

        self._protocol = protocol
        self._sock = sock
        self._response_handler: t.List[ResponseHandler] = []
        self._encryptor: t.Optional[MessageEncryptor] = None
        self._reader_task = threading.Thread(
            target=self._read_loop,
            name=f"LDAP({server})",
        )
        self._reader_task.start()
        self._root_dse: t.Optional[RootDSE] = None

    @property
    def root_dse(self) -> RootDSE:
        if not self._root_dse:
            default_naming_context = ""
            subschema_subentry = ""
            supported_controls: t.List[str] = []

            for res in self._search_request(
                base_object="",
                scope=sansldap.SearchScope.BASE,
                filter=sansldap.FilterPresent("objectClass"),
                attributes=[
                    "defaultNamingContext",
                    "subschemaSubentry",
                    "supportedControl",
                ],
            ):
                if not isinstance(res, sansldap.SearchResultEntry):
                    continue

                for attr in res.attributes:
                    if attr.name == "defaultNamingContext":
                        default_naming_context = attr.values[0].decode("utf-8")

                    elif attr.name == "subschemaSubentry":
                        subschema_subentry = attr.values[0].decode("utf-8")

                    elif attr.name == "supportedControl":
                        supported_controls = [v.decode("utf-8") for v in attr.values]

            self._root_dse = RootDSE(
                default_naming_context=default_naming_context,
                subschema_subentry=subschema_subentry,
                supported_controls=supported_controls,
            )

        return self._root_dse

    def __enter__(self) -> "SyncLDAPClient":
        return self

    def __exit__(self, *args: t.Any, **kwargs: t.Any) -> None:
        self.close()

    @classmethod
    def start_tls(
        cls,
        protocol: "sansldap.LDAPClient",
        sock: socket.socket,
    ) -> None:
        protocol.extended_request(sansldap.ExtendedOperations.LDAP_START_TLS)
        data = protocol.data_to_send()
        sock.sendall(data)

        done = False
        while not done:
            data = sock.recv(4096)
            for msg in protocol.receive(data):
                msg = t.cast(sansldap.ExtendedResponse, msg)
                if msg.result.result_code != sansldap.LDAPResultCode.SUCCESS:
                    raise LDAPResultError("StartTLS failed", msg.result)

                done = True
                break

    def bind(
        self,
        dn: str,
        credential: "sansldap.AuthenticationCredential",
        success_only: bool = True,
    ) -> t.Optional[bytes]:
        msg_id = self._protocol.bind(dn, credential)
        response = self._write_and_wait_one(msg_id, sansldap.BindResponse)

        valid_codes = [sansldap.LDAPResultCode.SUCCESS]
        if not success_only:
            valid_codes.append(sansldap.LDAPResultCode.SASL_BIND_IN_PROGRESS)

        if response.result.result_code not in valid_codes:
            raise LDAPResultError("bind failed", response.result)

        return response.server_sasl_creds

    def close(self) -> None:
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            # The socket has already been shutdown for some other reason
            pass
        self._sock.close()
        self._reader_task.join()

    def register_encryptor(
        self,
        encryptor: MessageEncryptor,
    ) -> None:
        self._encryptor = encryptor

    def search(
        self,
        filter: t.Union[str, "sansldap.LDAPFilter"],
        attributes: t.List[str],
        search_base: t.Optional[str] = None,
        search_scope: t.Optional["sansldap.SearchScope"] = None,
    ) -> t.Dict[str, t.Dict[str, t.List[bytes]]]:
        if search_base is None:
            search_base = self.root_dse.default_naming_context

        controls: t.List[sansldap.LDAPControl] = []
        pagination_size = 1024

        if sansldap.PagedResultControl.control_type in self.root_dse.supported_controls:
            controls.append(sansldap.PagedResultControl(False, pagination_size, b""))

        search_kwargs: t.Dict[str, t.Any] = {
            "base_object": search_base,
            "scope": search_scope,
            "filter": filter,
            "attributes": attributes,
        }
        res: t.Dict[str, t.Dict[str, t.List[bytes]]] = {}

        while True:
            for entry in self._search_request(
                controls=controls,
                **search_kwargs,
            ):
                if isinstance(entry, sansldap.SearchResultDone):
                    paginated_control = next(
                        iter(c for c in entry.controls if isinstance(c, sansldap.PagedResultControl)),
                        None,
                    )
                    if paginated_control and paginated_control.cookie:
                        controls = [sansldap.PagedResultControl(False, pagination_size, paginated_control.cookie)]
                    else:
                        controls = []

                elif isinstance(entry, sansldap.SearchResultEntry):
                    entry_res = res.setdefault(entry.object_name, {})
                    for attr in entry.attributes:
                        entry_attr = entry_res.setdefault(attr.name, [])
                        entry_attr.extend(attr.values)

                # SearchResultReference is ignored for now.

            if not controls:
                break

        return res

    def _search_request(
        self,
        base_object: t.Optional[str] = None,
        scope: t.Optional[t.Union[int, "sansldap.SearchScope"]] = None,
        dereferencing_policy: t.Optional[t.Union[int, "sansldap.DereferencingPolicy"]] = None,
        size_limit: int = 0,
        time_limit: int = 0,
        types_only: bool = False,
        filter: t.Optional[t.Union[str, "sansldap.LDAPFilter"]] = None,
        attributes: t.Optional[t.List[str]] = None,
        controls: t.Optional[t.List["sansldap.LDAPControl"]] = None,
    ) -> t.Iterator[
        t.Union["sansldap.SearchResultReference", "sansldap.SearchResultEntry", "sansldap.SearchResultDone"]
    ]:
        ldap_filter: t.Optional[sansldap.LDAPFilter] = None
        if isinstance(filter, sansldap.LDAPFilter):
            ldap_filter = filter
        elif filter:
            ldap_filter = sansldap.LDAPFilter.from_string(filter)

        deref = dereferencing_policy if dereferencing_policy is not None else sansldap.DereferencingPolicy.NEVER

        msg_id = self._protocol.search_request(
            base_object=base_object,
            scope=scope if scope is not None else sansldap.SearchScope.SUBTREE,
            dereferencing_policy=deref,
            size_limit=size_limit,
            time_limit=time_limit,
            types_only=types_only,
            filter=ldap_filter,
            attributes=attributes,
            controls=controls,
        )

        handler = self._register_response_handler(
            msg_id,
            sansldap.SearchResultEntry,
            sansldap.SearchResultReference,
            sansldap.SearchResultDone,
        )
        try:
            self._write_msg()
            for res in handler:
                yield res  # type: ignore[misc]

                if isinstance(res, sansldap.SearchResultDone):
                    self._valid_result(res.result, "search request failed")
                    break

        finally:
            self._unregister_response_handler(handler)

    def _read_loop(self) -> None:
        data_buffer = bytearray()
        while True:
            try:
                resp = self._sock.recv(4096)
                if not resp:
                    raise Exception("LDAP connection has been shutdown")

                data_buffer.extend(resp)

                while data_buffer:
                    if self._encryptor:
                        dec_data, enc_len = self._encryptor.unwrap(data_buffer)
                        if enc_len == 0:
                            break

                        data_buffer = data_buffer[enc_len:]
                    else:
                        dec_data = bytes(data_buffer)
                        data_buffer = bytearray()

                    for msg in self._protocol.receive(dec_data):
                        for handler in self._response_handler:
                            handler.append(msg)

            except sansldap.ProtocolError as e:
                if e.response:
                    self._sock.sendall(e.response)

                for handler in self._response_handler:
                    handler.append(e)
                break

            except Exception as e:
                for handler in self._response_handler:
                    handler.append(e)
                break

    def _register_response_handler(
        self,
        msg_id: int,
        *message_types: t.Type[MessageType],
    ) -> ResponseHandler[MessageType]:
        handler = ResponseHandler(
            msg_id,
            message_types,
        )
        self._response_handler.append(handler)

        return handler

    def _valid_result(
        self,
        result: "sansldap.LDAPResult",
        msg: str,
    ) -> None:
        if result.result_code != sansldap.LDAPResultCode.SUCCESS:
            raise LDAPResultError(msg, result)

    def _unregister_response_handler(
        self,
        handler: ResponseHandler,
    ) -> None:
        self._response_handler.remove(handler)

    def _write_and_wait_one(
        self,
        msg_id: int,
        message_type: t.Type[MessageType],
    ) -> MessageType:
        handler = self._register_response_handler(msg_id, message_type)
        try:
            self._write_msg()

            return handler.__iter__().__next__()

        finally:
            self._unregister_response_handler(handler)

    def _write_msg(self) -> None:
        data = self._protocol.data_to_send()
        if self._encryptor:
            data = self._encryptor.wrap(data)

        self._sock.sendall(data)
