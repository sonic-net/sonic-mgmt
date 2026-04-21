# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# FOR INTERNAL COLLECTION USE ONLY
# The interfaces in this file are meant for use within this collection
# and may not remain stable to outside uses. Changes may be made in ANY release, even a bugfix release.
# See also: https://github.com/ansible/community/issues/539#issuecomment-780839686
# Please open an issue if you have questions about this.

import base64
import typing as t

try:
    import dpapi_ng

    HAS_DPAPI_NG = True
    DPAPI_NG_IMP_ERR = None
except Exception as e:
    HAS_DPAPI_NG = False
    DPAPI_NG_IMP_ERR = e


class LAPSDecryptor:

    def __init__(
        self,
        server: t.Optional[str] = None,
        username: t.Optional[str] = None,
        password: t.Optional[str] = None,
        auth_protocol: t.Optional[str] = None,
        **kwargs: t.Any,
    ) -> None:
        self._server = server
        self._username = username
        self._password = password

        if not auth_protocol or auth_protocol not in ["kerberos", "negotiate", "ntlm"]:
            auth_protocol = "negotiate"
        self._auth_protocol = auth_protocol

        self._cache = None
        if HAS_DPAPI_NG:
            self._cache = dpapi_ng.KeyCache()

    def decrypt(
        self,
        blob: bytes,
    ) -> t.Dict[str, t.Any]:
        update_timestamp_upper = int.from_bytes(blob[:4], byteorder="little")
        update_timestamp_lower = int.from_bytes(blob[4:8], byteorder="little")
        update_timestamp = (update_timestamp_upper << 32) | update_timestamp_lower
        enc_buffer_size = int.from_bytes(blob[8:12], byteorder="little")
        flags = int.from_bytes(blob[12:16], byteorder="little")
        enc_buffer = blob[16:16 + enc_buffer_size]

        value = {
            'update_timestamp': update_timestamp,
            'flags': flags,
            'encrypted_value': base64.b64encode(enc_buffer).decode(),
        }

        if HAS_DPAPI_NG:
            try:
                raw_dec_value = dpapi_ng.ncrypt_unprotect_secret(
                    enc_buffer,
                    server=self._server,
                    username=self._username,
                    password=self._password,
                    auth_protocol=self._auth_protocol,
                    cache=self._cache,
                )
                value['value'] = raw_dec_value.decode("utf-16-le").rstrip("\00")
            except Exception as e:
                value['debug'] = f'Failed to decrypt value due to error - {type(e).__name__} {e}'

        else:
            value['debug'] = 'Cannot decrypt value as the Python library dpapi-ng is not installed'

        return value
