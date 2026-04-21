# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from ._token_providers import (
    BasicTokenProvider,
    CallbackTokenProvider,
    MsiTokenProvider,
    AzCliTokenProvider,
    UserPassTokenProvider,
    DeviceLoginTokenProvider,
    InteractiveLoginTokenProvider,
    ApplicationKeyTokenProvider,
    ApplicationCertificateTokenProvider,
    TokenConstants,
    AzureIdentityTokenCredentialProvider,
)
from .exceptions import KustoAuthenticationError, KustoClientError

if TYPE_CHECKING:
    from . import KustoConnectionStringBuilder


class _AadHelper:
    kusto_uri = None  # type: str
    authority_uri = None  # type: str
    token_provider = None  # type: TokenProviderBase

    def __init__(self, kcsb: "KustoConnectionStringBuilder", is_async: bool):
        parsed_url = urlparse(kcsb.data_source)
        self.kusto_uri = f"{parsed_url.scheme}://{parsed_url.hostname}"
        if parsed_url.port is not None:
            self.kusto_uri += f":{parsed_url.port}"

        self.username = None

        if kcsb.interactive_login:
            self.token_provider = InteractiveLoginTokenProvider(self.kusto_uri, kcsb.authority_id, kcsb.login_hint, kcsb.domain_hint, is_async=is_async)
        elif all([kcsb.aad_user_id, kcsb.password]):
            self.token_provider = UserPassTokenProvider(self.kusto_uri, kcsb.authority_id, kcsb.aad_user_id, kcsb.password, is_async=is_async)
        elif all([kcsb.application_client_id, kcsb.application_key]):
            self.token_provider = ApplicationKeyTokenProvider(
                self.kusto_uri, kcsb.authority_id, kcsb.application_client_id, kcsb.application_key, is_async=is_async
            )
        elif all([kcsb.application_client_id, kcsb.application_certificate, kcsb.application_certificate_thumbprint]):
            # kcsb.application_public_certificate can be None if SNI is not used
            self.token_provider = ApplicationCertificateTokenProvider(
                self.kusto_uri,
                kcsb.application_client_id,
                kcsb.authority_id,
                kcsb.application_certificate,
                kcsb.application_certificate_thumbprint,
                kcsb.application_public_certificate,
                is_async=is_async,
            )
        elif kcsb.msi_authentication:
            self.token_provider = MsiTokenProvider(self.kusto_uri, kcsb.msi_parameters, is_async=is_async)
        elif kcsb.user_token:
            self.token_provider = BasicTokenProvider(kcsb.user_token, is_async=is_async)
        elif kcsb.application_token:
            self.token_provider = BasicTokenProvider(kcsb.application_token, is_async=is_async)
        elif kcsb.az_cli_login:
            self.token_provider = AzCliTokenProvider(self.kusto_uri, is_async=is_async)
        elif kcsb.token_provider or kcsb.async_token_provider:
            self.token_provider = CallbackTokenProvider(token_callback=kcsb.token_provider, async_token_callback=kcsb.async_token_provider, is_async=is_async)
        elif kcsb.token_credential_login:
            self.token_provider = AzureIdentityTokenCredentialProvider(
                self.kusto_uri,
                is_async=is_async,
                credential=kcsb.azure_credential,
                credential_from_login_endpoint=kcsb.azure_credential_from_login_endpoint,
            )
        elif kcsb.device_login:
            self.token_provider = DeviceLoginTokenProvider(self.kusto_uri, kcsb.authority_id, kcsb.device_callback, is_async=is_async)
        else:
            self.token_provider = InteractiveLoginTokenProvider(self.kusto_uri, kcsb.authority_id, kcsb.login_hint, kcsb.domain_hint, is_async=is_async)

    def acquire_authorization_header(self):
        try:
            return _get_header_from_dict(self.token_provider.get_token())
        except Exception as error:
            kwargs = self.token_provider.context()
            kwargs["kusto_uri"] = self.kusto_uri
            raise KustoAuthenticationError(self.token_provider.name(), error, **kwargs)

    async def acquire_authorization_header_async(self):
        try:
            return _get_header_from_dict(await self.token_provider.get_token_async())
        except Exception as error:
            kwargs = await self.token_provider.context_async()
            kwargs["resource"] = self.kusto_uri
            raise KustoAuthenticationError(self.token_provider.name(), error, **kwargs)

    def close(self):
        self.token_provider.close()

    async def close_async(self):
        await self.token_provider.close_async()


def _get_header_from_dict(token: dict):
    if TokenConstants.MSAL_ACCESS_TOKEN in token:
        return _get_header(token[TokenConstants.MSAL_TOKEN_TYPE], token[TokenConstants.MSAL_ACCESS_TOKEN])
    elif TokenConstants.AZ_ACCESS_TOKEN in token:
        return _get_header(token[TokenConstants.AZ_TOKEN_TYPE], token[TokenConstants.AZ_ACCESS_TOKEN])
    else:
        raise KustoClientError("Unable to determine the token type. Neither 'tokenType' nor 'token_type' property is present.")


def _get_header(token_type: str, access_token: str) -> str:
    return "{0} {1}".format(token_type, access_token)


def _is_local_address(host):
    if host == "localhost" or host == "127.0.0.1" or host == "::1" or host == "[::1]":
        return True

    if host.startswith("127.") and 15 >= len(host) >= 9:
        for i in range(len(host)):
            c = host[i]
            if c != "." and (c < "0" or c > "9"):
                return False
            i += 1
        return True

    return False
