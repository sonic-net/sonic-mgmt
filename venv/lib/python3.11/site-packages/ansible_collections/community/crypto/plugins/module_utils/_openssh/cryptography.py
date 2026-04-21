# Copyright (c) 2021, Andrew Pantuso (@ajpantuso) <ajpantuso@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import os
import typing as t
from base64 import b64decode, b64encode
from getpass import getuser
from socket import gethostname


try:
    from cryptography import __version__ as CRYPTOGRAPHY_VERSION
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    HAS_OPENSSH_SUPPORT = True

    _ALGORITHM_PARAMETERS = {
        "rsa": {
            "default_size": 2048,
            "valid_sizes": range(1024, 16384),
            "signer_params": {
                "padding": padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                "algorithm": hashes.SHA256(),
            },
        },
        "dsa": {
            "default_size": 1024,
            "valid_sizes": [1024],
            "signer_params": {
                "algorithm": hashes.SHA256(),
            },
        },
        "ed25519": {
            "default_size": 256,
            "valid_sizes": [256],
            "signer_params": {},
        },
        "ecdsa": {
            "default_size": 256,
            "valid_sizes": [256, 384, 521],
            "signer_params": {
                "signature_algorithm": ec.ECDSA(hashes.SHA256()),
            },
            "curves": {
                256: ec.SECP256R1(),
                384: ec.SECP384R1(),
                521: ec.SECP521R1(),
            },
        },
    }
except ImportError:
    HAS_OPENSSH_SUPPORT = False
    CRYPTOGRAPHY_VERSION = "0.0"
    _ALGORITHM_PARAMETERS = {}

from ansible_collections.community.crypto.plugins.module_utils._crypto.cryptography_support import (
    is_potential_certificate_issuer_private_key,
)


if t.TYPE_CHECKING:
    KeyFormat = t.Literal["SSH", "PKCS8", "PKCS1"]  # pragma: no cover
    KeySerializationFormat = t.Literal["PEM", "DER", "SSH"]  # pragma: no cover
    KeyType = t.Literal["rsa", "dsa", "ed25519", "ecdsa"]  # pragma: no cover

    PrivateKeyTypes = t.Union[  # noqa: UP007
        rsa.RSAPrivateKey,
        dsa.DSAPrivateKey,
        ec.EllipticCurvePrivateKey,
        Ed25519PrivateKey,
    ]  # pragma: no cover
    PublicKeyTypes = t.Union[  # noqa: UP007
        rsa.RSAPublicKey, dsa.DSAPublicKey, ec.EllipticCurvePublicKey, Ed25519PublicKey
    ]  # pragma: no cover

    from cryptography.hazmat.primitives.asymmetric.types import (
        PublicKeyTypes as AllPublicKeyTypes,  # pragma: no cover
    )


_TEXT_ENCODING = "UTF-8"


class OpenSSHError(Exception):
    pass


class InvalidAlgorithmError(OpenSSHError):
    pass


class InvalidCommentError(OpenSSHError):
    pass


class InvalidDataError(OpenSSHError):
    pass


class InvalidPrivateKeyFileError(OpenSSHError):
    pass


class InvalidPublicKeyFileError(OpenSSHError):
    pass


class InvalidKeyFormatError(OpenSSHError):
    pass


class InvalidKeySizeError(OpenSSHError):
    pass


class InvalidKeyTypeError(OpenSSHError):
    pass


class InvalidPassphraseError(OpenSSHError):
    pass


class InvalidSignatureError(OpenSSHError):
    pass


_AsymmetricKeypair = t.TypeVar("_AsymmetricKeypair", bound="AsymmetricKeypair")


class AsymmetricKeypair:
    """Container for newly generated asymmetric key pairs or those loaded from existing files"""

    @classmethod
    def generate(
        cls: type[_AsymmetricKeypair],
        *,
        keytype: KeyType = "rsa",
        size: int | None = None,
        passphrase: bytes | None = None,
    ) -> _AsymmetricKeypair:
        """Returns an Asymmetric_Keypair object generated with the supplied parameters
        or defaults to an unencrypted RSA-2048 key

        :keytype: One of rsa, dsa, ecdsa, ed25519
        :size: The key length for newly generated keys
        :passphrase: Secret of type Bytes used to encrypt the private key being generated
        """

        if keytype not in _ALGORITHM_PARAMETERS:
            raise InvalidKeyTypeError(
                f"{keytype} is not a valid keytype. Valid keytypes are {', '.join(_ALGORITHM_PARAMETERS)}"
            )

        if not size:
            size = _ALGORITHM_PARAMETERS[keytype]["default_size"]  # type: ignore
        else:
            if size not in _ALGORITHM_PARAMETERS[keytype]["valid_sizes"]:  # type: ignore
                raise InvalidKeySizeError(
                    f"{size} is not a valid key size for {keytype} keys"
                )
        size = t.cast(int, size)

        privatekey: PrivateKeyTypes
        if passphrase:
            encryption_algorithm = get_encryption_algorithm(passphrase)
        else:
            encryption_algorithm = serialization.NoEncryption()

        if keytype == "rsa":
            privatekey = rsa.generate_private_key(
                # Public exponent should always be 65537 to prevent issues
                # if improper padding is used during signing
                public_exponent=65537,
                key_size=size,
            )
        elif keytype == "dsa":
            privatekey = dsa.generate_private_key(
                key_size=size,
            )
        elif keytype == "ed25519":
            privatekey = Ed25519PrivateKey.generate()
        elif keytype == "ecdsa":
            privatekey = ec.generate_private_key(
                _ALGORITHM_PARAMETERS["ecdsa"]["curves"][size],  # type: ignore
            )

        publickey = privatekey.public_key()

        return cls(
            keytype=keytype,
            size=size,
            privatekey=privatekey,
            publickey=publickey,
            encryption_algorithm=encryption_algorithm,
        )

    @classmethod
    def load(
        cls: type[_AsymmetricKeypair],
        *,
        path: str | os.PathLike,
        passphrase: bytes | None = None,
        private_key_format: KeySerializationFormat = "PEM",
        public_key_format: KeySerializationFormat = "PEM",
        no_public_key: bool = False,
    ) -> _AsymmetricKeypair:
        """Returns an Asymmetric_Keypair object loaded from the supplied file path

        :path: A path to an existing private key to be loaded
        :passphrase: Secret of type bytes used to decrypt the private key being loaded
        :private_key_format: Format of private key to be loaded
        :public_key_format: Format of public key to be loaded
        :no_public_key: Set 'True' to only load a private key and automatically populate the matching public key
        """

        if passphrase:
            encryption_algorithm = get_encryption_algorithm(passphrase)
        else:
            encryption_algorithm = serialization.NoEncryption()

        privatekey = load_privatekey(
            path=path, passphrase=passphrase, key_format=private_key_format
        )
        publickey: AllPublicKeyTypes
        if no_public_key:
            publickey = privatekey.public_key()
        else:
            # TODO: Maybe we should check whether the public key actually fits the private key?
            publickey = load_publickey(
                path=str(path) + ".pub", key_format=public_key_format
            )

        # Ed25519 keys are always of size 256 and do not have a key_size attribute
        if isinstance(privatekey, Ed25519PrivateKey):
            size: int = _ALGORITHM_PARAMETERS["ed25519"]["default_size"]  # type: ignore
        else:
            size = privatekey.key_size

        keytype: KeyType
        if isinstance(privatekey, rsa.RSAPrivateKey):
            keytype = "rsa"
            if not isinstance(publickey, rsa.RSAPublicKey):
                raise InvalidKeyTypeError(
                    f"Private key is an RSA key, but public key is of type '{type(publickey)}'"
                )
        elif isinstance(privatekey, dsa.DSAPrivateKey):
            keytype = "dsa"
            if not isinstance(publickey, dsa.DSAPublicKey):
                raise InvalidKeyTypeError(
                    f"Private key is a DSA key, but public key is of type '{type(publickey)}'"
                )
        elif isinstance(privatekey, ec.EllipticCurvePrivateKey):
            keytype = "ecdsa"
            if not isinstance(publickey, ec.EllipticCurvePublicKey):
                raise InvalidKeyTypeError(
                    f"Private key is an Elliptic Curve key, but public key is of type '{type(publickey)}'"
                )
        elif isinstance(privatekey, Ed25519PrivateKey):
            keytype = "ed25519"
            if not isinstance(publickey, Ed25519PublicKey):
                raise InvalidKeyTypeError(
                    f"Private key is an Ed25519 key, but public key is of type '{type(publickey)}'"
                )
        else:
            raise InvalidKeyTypeError(f"Key type '{type(privatekey)}' is not supported")

        return cls(
            keytype=keytype,
            size=size,
            privatekey=privatekey,
            publickey=publickey,
            encryption_algorithm=encryption_algorithm,
        )

    def __init__(
        self,
        *,
        keytype: KeyType,
        size: int,
        privatekey: PrivateKeyTypes,
        publickey: PublicKeyTypes,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> None:
        """
        :keytype: One of rsa, dsa, ecdsa, ed25519
        :size: The key length for the private key of this key pair
        :privatekey: Private key object of this key pair
        :publickey: Public key object of this key pair
        :encryption_algorithm: Hashed secret used to encrypt the private key of this key pair
        """

        self.__size = size
        self.__keytype = keytype
        self.__privatekey = privatekey
        self.__publickey = publickey
        self.__encryption_algorithm = encryption_algorithm

        try:
            self.verify(signature=self.sign(b"message"), data=b"message")
        except InvalidSignatureError as e:
            raise InvalidPublicKeyFileError(
                "The private key and public key of this keypair do not match"
            ) from e

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AsymmetricKeypair):
            return NotImplemented

        return compare_publickeys(
            self.public_key, other.public_key
        ) and compare_encryption_algorithms(
            self.encryption_algorithm, other.encryption_algorithm
        )

    def __ne__(self, other: object) -> bool:
        return not self == other

    @property
    def private_key(self) -> PrivateKeyTypes:
        """Returns the private key of this key pair"""

        return self.__privatekey

    @property
    def public_key(self) -> PublicKeyTypes:
        """Returns the public key of this key pair"""

        return self.__publickey

    @property
    def size(self) -> int:
        """Returns the size of the private key of this key pair"""

        return self.__size

    @property
    def key_type(self) -> KeyType:
        """Returns the key type of this key pair"""

        return self.__keytype

    @property
    def encryption_algorithm(self) -> serialization.KeySerializationEncryption:
        """Returns the key encryption algorithm of this key pair"""

        return self.__encryption_algorithm

    def sign(self, data: bytes) -> bytes:
        """Returns signature of data signed with the private key of this key pair

        :data: byteslike data to sign
        """

        try:
            return self.__privatekey.sign(
                data,
                **_ALGORITHM_PARAMETERS[self.__keytype]["signer_params"],  # type: ignore
            )
        except TypeError as e:
            raise InvalidDataError(e) from e

    def verify(self, *, signature: bytes, data: bytes) -> None:
        """Verifies that the signature associated with the provided data was signed
        by the private key of this key pair.

        :signature: signature to verify
        :data: byteslike data signed by the provided signature
        """
        try:
            self.__publickey.verify(
                signature,
                data,
                **_ALGORITHM_PARAMETERS[self.__keytype]["signer_params"],  # type: ignore
            )
        except InvalidSignature as e:
            raise InvalidSignatureError from e

    def update_passphrase(self, passphrase: bytes | None = None) -> None:
        """Updates the encryption algorithm of this key pair

        :passphrase: Byte secret used to encrypt this key pair
        """

        if passphrase:
            self.__encryption_algorithm = get_encryption_algorithm(passphrase)
        else:
            self.__encryption_algorithm = serialization.NoEncryption()


_OpensshKeypair = t.TypeVar("_OpensshKeypair", bound="OpensshKeypair")


class OpensshKeypair:
    """Container for OpenSSH encoded asymmetric key pairs"""

    @classmethod
    def generate(
        cls: type[_OpensshKeypair],
        *,
        keytype: KeyType = "rsa",
        size: int | None = None,
        passphrase: bytes | None = None,
        comment: str | None = None,
    ) -> _OpensshKeypair:
        """Returns an Openssh_Keypair object generated using the supplied parameters or defaults to a RSA-2048 key

        :keytype: One of rsa, dsa, ecdsa, ed25519
        :size: The key length for newly generated keys
        :passphrase: Secret of type Bytes used to encrypt the newly generated private key
        :comment: Comment for a newly generated OpenSSH public key
        """

        if comment is None:
            comment = f"{getuser()}@{gethostname()}"

        asym_keypair = AsymmetricKeypair.generate(
            keytype=keytype, size=size, passphrase=passphrase
        )
        openssh_privatekey = cls.encode_openssh_privatekey(
            asym_keypair=asym_keypair, key_format="SSH"
        )
        openssh_publickey = cls.encode_openssh_publickey(
            asym_keypair=asym_keypair, comment=comment
        )
        fingerprint = calculate_fingerprint(openssh_publickey)

        return cls(
            asym_keypair=asym_keypair,
            openssh_privatekey=openssh_privatekey,
            openssh_publickey=openssh_publickey,
            fingerprint=fingerprint,
            comment=comment,
        )

    @classmethod
    def load(
        cls: type[_OpensshKeypair],
        *,
        path: str | os.PathLike,
        passphrase: bytes | None = None,
        no_public_key: bool = False,
    ) -> _OpensshKeypair:
        """Returns an Openssh_Keypair object loaded from the supplied file path

        :path: A path to an existing private key to be loaded
        :passphrase: Secret used to decrypt the private key being loaded
        :no_public_key: Set 'True' to only load a private key and automatically populate the matching public key
        """

        if no_public_key:
            comment = ""
        else:
            comment = extract_comment(str(path) + ".pub")

        asym_keypair = AsymmetricKeypair.load(
            path=path,
            passphrase=passphrase,
            private_key_format="SSH",
            public_key_format="SSH",
            no_public_key=no_public_key,
        )
        openssh_privatekey = cls.encode_openssh_privatekey(
            asym_keypair=asym_keypair, key_format="SSH"
        )
        openssh_publickey = cls.encode_openssh_publickey(
            asym_keypair=asym_keypair, comment=comment
        )
        fingerprint = calculate_fingerprint(openssh_publickey)

        return cls(
            asym_keypair=asym_keypair,
            openssh_privatekey=openssh_privatekey,
            openssh_publickey=openssh_publickey,
            fingerprint=fingerprint,
            comment=comment,
        )

    @staticmethod
    def encode_openssh_privatekey(
        *, asym_keypair: AsymmetricKeypair, key_format: KeyFormat
    ) -> bytes:
        """Returns an OpenSSH encoded private key for a given keypair

        :asym_keypair: Asymmetric_Keypair from the private key is extracted
        :key_format: Format of the encoded private key.
        """

        if key_format == "SSH":
            privatekey_format = serialization.PrivateFormat.OpenSSH
        elif key_format == "PKCS8":
            privatekey_format = serialization.PrivateFormat.PKCS8
        elif key_format == "PKCS1":
            if asym_keypair.key_type == "ed25519":
                raise InvalidKeyFormatError(
                    "ed25519 keys cannot be represented in PKCS1 format"
                )
            privatekey_format = serialization.PrivateFormat.TraditionalOpenSSL
        else:
            raise InvalidKeyFormatError(
                "The accepted private key formats are SSH, PKCS8, and PKCS1"
            )

        encoded_privatekey = asym_keypair.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=privatekey_format,
            encryption_algorithm=asym_keypair.encryption_algorithm,
        )

        return encoded_privatekey

    @staticmethod
    def encode_openssh_publickey(
        *, asym_keypair: AsymmetricKeypair, comment: str
    ) -> bytes:
        """Returns an OpenSSH encoded public key for a given keypair

        :asym_keypair: Asymmetric_Keypair from the public key is extracted
        :comment: Comment to apply to the end of the returned OpenSSH encoded public key
        """
        encoded_publickey = asym_keypair.public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )

        validate_comment(comment)

        encoded_publickey += (
            (b" " + comment.encode(encoding=_TEXT_ENCODING)) if comment else b""
        )

        return encoded_publickey

    def __init__(
        self,
        *,
        asym_keypair: AsymmetricKeypair,
        openssh_privatekey: bytes,
        openssh_publickey: bytes,
        fingerprint: str,
        comment: str | None,
    ) -> None:
        """
        :asym_keypair: An Asymmetric_Keypair object from which the OpenSSH encoded keypair is derived
        :openssh_privatekey: An OpenSSH encoded private key
        :openssh_privatekey: An OpenSSH encoded public key
        :fingerprint: The fingerprint of the OpenSSH encoded public key of this keypair
        :comment: Comment applied to the OpenSSH public key of this keypair
        """

        self.__asym_keypair = asym_keypair
        self.__openssh_privatekey = openssh_privatekey
        self.__openssh_publickey = openssh_publickey
        self.__fingerprint = fingerprint
        self.__comment = comment

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, OpensshKeypair):
            return NotImplemented

        return (
            self.asymmetric_keypair == other.asymmetric_keypair
            and self.comment == other.comment
        )

    @property
    def asymmetric_keypair(self) -> AsymmetricKeypair:
        """Returns the underlying asymmetric key pair of this OpenSSH encoded key pair"""

        return self.__asym_keypair

    @property
    def private_key(self) -> bytes:
        """Returns the OpenSSH formatted private key of this key pair"""

        return self.__openssh_privatekey

    @property
    def public_key(self) -> bytes:
        """Returns the OpenSSH formatted public key of this key pair"""

        return self.__openssh_publickey

    @property
    def size(self) -> int:
        """Returns the size of the private key of this key pair"""

        return self.__asym_keypair.size

    @property
    def key_type(self) -> KeyType:
        """Returns the key type of this key pair"""

        return self.__asym_keypair.key_type

    @property
    def fingerprint(self) -> str:
        """Returns the fingerprint (SHA256 Hash) of the public key of this key pair"""

        return self.__fingerprint

    @property
    def comment(self) -> str | None:
        """Returns the comment applied to the OpenSSH formatted public key of this key pair"""

        return self.__comment

    @comment.setter
    def comment(self, comment: str) -> bytes:
        """Updates the comment applied to the OpenSSH formatted public key of this key pair

        :comment: Text to update the OpenSSH public key comment
        """

        validate_comment(comment)

        self.__comment = comment
        encoded_comment = (
            f" {self.__comment}".encode(encoding=_TEXT_ENCODING)
            if self.__comment
            else b""
        )
        self.__openssh_publickey = (
            b" ".join(self.__openssh_publickey.split(b" ", 2)[:2]) + encoded_comment
        )
        return self.__openssh_publickey

    def update_passphrase(self, passphrase: bytes | None) -> None:
        """Updates the passphrase used to encrypt the private key of this keypair

        :passphrase: Text secret used for encryption
        """

        self.__asym_keypair.update_passphrase(passphrase)
        self.__openssh_privatekey = OpensshKeypair.encode_openssh_privatekey(
            asym_keypair=self.__asym_keypair, key_format="SSH"
        )


def load_privatekey(
    *,
    path: str | os.PathLike,
    passphrase: bytes | None,
    key_format: KeySerializationFormat,
) -> PrivateKeyTypes:
    privatekey_loaders = {
        "PEM": serialization.load_pem_private_key,
        "DER": serialization.load_der_private_key,
        "SSH": serialization.load_ssh_private_key,
    }

    try:
        privatekey_loader = privatekey_loaders[key_format]
    except KeyError as e:
        raise InvalidKeyFormatError(
            f"{key_format} is not a valid key format ({','.join(privatekey_loaders)})"
        ) from e

    if not os.path.exists(path):
        raise InvalidPrivateKeyFileError(f"No file was found at {path}")

    try:
        with open(path, "rb") as f:
            content = f.read()

        try:
            privatekey = privatekey_loader(
                data=content,
                password=passphrase,
            )
        except ValueError as exc:
            # Revert to PEM if key could not be loaded in SSH format
            if key_format == "SSH":
                privatekey = privatekey_loaders["PEM"](
                    data=content,
                    password=passphrase,
                )
            else:
                raise InvalidPrivateKeyFileError(exc) from exc
    except ValueError as e:
        raise InvalidPrivateKeyFileError(e) from e
    except TypeError as e:
        raise InvalidPassphraseError(e) from e
    except UnsupportedAlgorithm as e:
        raise InvalidAlgorithmError(e) from e

    if not is_potential_certificate_issuer_private_key(privatekey) or isinstance(
        privatekey, Ed448PrivateKey
    ):
        raise InvalidPrivateKeyFileError(
            f"{privatekey} is not a supported private key type"
        )
    return privatekey


def load_publickey(
    *, path: str | os.PathLike, key_format: KeySerializationFormat
) -> AllPublicKeyTypes:
    publickey_loaders = {
        "PEM": serialization.load_pem_public_key,
        "DER": serialization.load_der_public_key,
        "SSH": serialization.load_ssh_public_key,
    }

    try:
        publickey_loader = publickey_loaders[key_format]
    except KeyError as e:
        raise InvalidKeyFormatError(
            f"{key_format} is not a valid key format ({','.join(publickey_loaders)})"
        ) from e

    if not os.path.exists(path):
        raise InvalidPublicKeyFileError(f"No file was found at {path}")

    try:
        with open(path, "rb") as f:
            content = f.read()

            publickey = publickey_loader(
                data=content,
            )
    except ValueError as e:
        raise InvalidPublicKeyFileError(e) from e
    except UnsupportedAlgorithm as e:
        raise InvalidAlgorithmError(e) from e

    return publickey


def compare_publickeys(pk1: PublicKeyTypes, pk2: PublicKeyTypes) -> bool:
    a = isinstance(pk1, Ed25519PublicKey)
    b = isinstance(pk2, Ed25519PublicKey)
    if a or b:
        if not a or not b:
            return False
        a_bytes = pk1.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        b_bytes = pk2.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return a_bytes == b_bytes
    return pk1.public_numbers() == pk2.public_numbers()  # type: ignore


def compare_encryption_algorithms(
    ea1: serialization.KeySerializationEncryption,
    ea2: serialization.KeySerializationEncryption,
) -> bool:
    if isinstance(ea1, serialization.NoEncryption) and isinstance(
        ea2, serialization.NoEncryption
    ):
        return True
    if isinstance(ea1, serialization.BestAvailableEncryption) and isinstance(
        ea2, serialization.BestAvailableEncryption
    ):
        return ea1.password == ea2.password
    return False


def get_encryption_algorithm(
    passphrase: bytes,
) -> serialization.KeySerializationEncryption:
    try:
        return serialization.BestAvailableEncryption(passphrase)
    except ValueError as e:
        raise InvalidPassphraseError(e) from e


def validate_comment(comment: str) -> None:
    if not hasattr(comment, "encode"):
        raise InvalidCommentError(f"{comment} cannot be encoded to text")


def extract_comment(path: str | os.PathLike) -> str:
    if not os.path.exists(path):
        raise InvalidPublicKeyFileError(f"No file was found at {path}")

    try:
        with open(path, "rb") as f:
            fields = f.read().split(b" ", 2)
            if len(fields) == 3:
                comment = fields[2].decode(_TEXT_ENCODING)
            else:
                comment = ""
    except (IOError, OSError) as e:
        raise InvalidPublicKeyFileError(e) from e

    return comment


def calculate_fingerprint(openssh_publickey: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256())
    decoded_pubkey = b64decode(openssh_publickey.split(b" ")[1])
    digest.update(decoded_pubkey)

    value = b64encode(digest.finalize()).decode(encoding=_TEXT_ENCODING).rstrip("=")
    return f"SHA256:{value}"


__all__ = (
    "HAS_OPENSSH_SUPPORT",
    "CRYPTOGRAPHY_VERSION",
    "OpenSSHError",
    "InvalidAlgorithmError",
    "InvalidCommentError",
    "InvalidDataError",
    "InvalidPrivateKeyFileError",
    "InvalidPublicKeyFileError",
    "InvalidKeyFormatError",
    "InvalidKeySizeError",
    "InvalidKeyTypeError",
    "InvalidPassphraseError",
    "InvalidSignatureError",
    "AsymmetricKeypair",
    "OpensshKeypair",
    "load_privatekey",
    "load_publickey",
    "compare_publickeys",
    "compare_encryption_algorithms",
    "get_encryption_algorithm",
    "validate_comment",
    "extract_comment",
    "calculate_fingerprint",
)
