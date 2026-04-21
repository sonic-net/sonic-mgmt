# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License
import abc
import asyncio
import inspect
import time
from datetime import datetime
from threading import Lock
from typing import Callable, Coroutine, List, Optional, Any

import requests
from azure.core.exceptions import ClientAuthenticationError
from azure.core.tracing import SpanKind
from azure.core.tracing.decorator import distributed_trace
from azure.core.tracing.decorator_async import distributed_trace_async
from azure.identity import AzureCliCredential, ManagedIdentityCredential, DeviceCodeCredential
from msal import ConfidentialClientApplication, PublicClientApplication

from ._cloud_settings import CloudInfo, CloudSettings
from ._telemetry import MonitoredActivity
from .exceptions import KustoAioSyntaxError, KustoAsyncUsageError, KustoClientError

DeviceCallbackType = Callable[[str, str, datetime], None]
"""A callback enabling control of how authentication
        instructions are presented. Must accept arguments (``verification_uri``, ``user_code``, ``expires_on``):

        - ``verification_uri`` (str) the URL the user must visit
        - ``user_code`` (str) the code the user must enter there
        - ``expires_on`` (datetime.datetime) the UTC time at which the code will expire
        If this argument isn't provided, the credential will print instructions to stdout."""

try:
    from asgiref.sync import sync_to_async
except ImportError:

    def sync_to_async(f):
        raise KustoAioSyntaxError()


try:
    from azure.identity.aio import (
        ManagedIdentityCredential as AsyncManagedIdentityCredential,
        AzureCliCredential as AsyncAzureCliCredential,
        DefaultAzureCredential as AsyncDefaultAzureCredential,
    )

    from azure.core.credentials_async import AsyncTokenCredential
except ImportError:
    # These are here in case the user doesn't have the aio optional dependency installed, but still tries to use async.
    # They will give them a useful error message, and will appease linters.
    class AsyncManagedIdentityCredential:
        def __init__(self):
            raise KustoAioSyntaxError()

    class AsyncAzureCliCredential:
        def __init__(self):
            raise KustoAioSyntaxError()

    class AsyncDefaultAzureCredential:
        def __init__(self):
            raise KustoAioSyntaxError()

    class AsyncTokenCredential:
        def __init__(self):
            raise KustoAioSyntaxError()


# constant key names and values used throughout the code
class TokenConstants:
    BEARER_TYPE = "Bearer"
    MSAL_TOKEN_TYPE = "token_type"
    MSAL_ACCESS_TOKEN = "access_token"
    MSAL_ERROR = "error"
    MSAL_ERROR_DESCRIPTION = "error_description"
    MSAL_PRIVATE_CERT = "private_key"
    MSAL_THUMBPRINT = "thumbprint"
    MSAL_PUBLIC_CERT = "public_certificate"
    MSAL_DEVICE_MSG = "message"
    MSAL_DEVICE_URI = "verification_uri"
    MSAL_INTERACTIVE_PROMPT = "select_account"
    AZ_TOKEN_TYPE = "tokenType"
    AZ_ACCESS_TOKEN = "accessToken"


class TokenProviderBase(abc.ABC):
    """
    This base class abstracts token acquisition for all implementations.
    The class is build for Lazy initialization, so that the first call, take on instantiation of 'heavy' long-lived class members
    """

    _initialized: bool = False
    _resources_initialized: bool = False

    def __init__(self, is_async: bool = False):
        self._proxy_dict: Optional[str, str] = None
        self._session: Optional[requests.Session] = None
        self.is_async = is_async

        if is_async:
            self._async_lock = asyncio.Lock()
        else:
            self._lock = Lock()

    def close(self):
        pass

    async def close_async(self):
        pass

    def _init_once(self, init_only_resources=False):
        if self._initialized:
            return

        with self._lock:
            if self._initialized:
                return

            if not self._resources_initialized:
                self._init_resources()
                self._resources_initialized = True

            if init_only_resources:
                return

            self._init_impl()
            self._initialized = True

    async def _init_once_async(self, init_only_resources=False):
        if self._initialized:
            return

        async with self._async_lock:
            if self._initialized:
                return

            if not self._resources_initialized:
                await sync_to_async(self._init_resources)()
                self._resources_initialized = True

            if init_only_resources:
                return

            self._init_impl()
            self._initialized = True

    def _init_resources(self):
        pass

    def get_token(self):
        """Get a token silently from cache or authenticate if cached token is not found"""

        @distributed_trace(name_of_span=f"{self.name()}.get_token", tracing_attributes=self.context(), kind=SpanKind.CLIENT)
        def _get_token():
            if self.is_async:
                raise KustoAsyncUsageError("get_token", self.is_async)
            self._init_once()

            token = self._get_token_from_cache_impl()
            if token is None:
                with self._lock:
                    token = MonitoredActivity.invoke(self._get_token_impl, name_of_span=f"{self.name()}.get_token_impl", tracing_attributes=self.context())
            return self._valid_token_or_throw(token)

        return _get_token()

    def context(self) -> dict:
        if self.is_async:
            raise KustoAsyncUsageError("context", self.is_async)
        self._init_once(init_only_resources=True)
        return self._context_impl()

    async def context_async(self) -> dict:
        if not self.is_async:
            raise KustoAsyncUsageError("context_async", self.is_async)

        await self._init_once_async(init_only_resources=True)
        return self._context_impl()

    async def get_token_async(self):
        """Get a token asynchronously silently from cache or authenticate if cached token is not found"""

        context = await self.context_async()

        @distributed_trace_async(name_of_span=f"{self.name()}.get_token_async", tracing_attributes=context, kind=SpanKind.CLIENT)
        async def _get_token_async():
            if not self.is_async:
                raise KustoAsyncUsageError("get_token_async", self.is_async)

            await self._init_once_async()

            token = self._get_token_from_cache_impl()

            if token is None:
                async with self._async_lock:
                    token = await MonitoredActivity.invoke_async(
                        self._get_token_impl_async, name_of_span=f"{self.name()}.get_token_impl_async", tracing_attributes=context
                    )

            return self._valid_token_or_throw(token)

        return await _get_token_async()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close_async()

    @staticmethod
    @abc.abstractmethod
    def name() -> str:
        """return the provider class name"""
        pass

    @abc.abstractmethod
    def _context_impl(self) -> dict:
        """return a secret-free context for error reporting"""
        pass

    @abc.abstractmethod
    def _init_impl(self):
        """Implement any "heavy" first time initializations here"""
        pass

    @abc.abstractmethod
    def _get_token_impl(self) -> Optional[dict]:
        """implement actual token acquisition here"""
        pass

    async def _get_token_impl_async(self) -> Optional[dict]:
        """implement actual token acquisition here"""
        return await sync_to_async(self._get_token_impl)()

    @abc.abstractmethod
    def _get_token_from_cache_impl(self) -> Optional[dict]:
        """Implement cache checks here, return None if cache check fails"""
        pass

    @staticmethod
    def _valid_token_or_none(token: dict) -> Optional[dict]:
        if token is None or TokenConstants.MSAL_ERROR in token:
            return None
        return token

    def _valid_token_or_throw(self, token: dict, context: str = "") -> dict:
        if token is None:
            raise KustoClientError(self.name() + " - failed to obtain a token. " + context)

        if TokenConstants.MSAL_ERROR in token:
            message = self.name() + " - failed to obtain a token. " + context + "\n" + token[TokenConstants.MSAL_ERROR]
            if TokenConstants.MSAL_ERROR_DESCRIPTION in token:
                message = message + "\n" + token[TokenConstants.MSAL_ERROR_DESCRIPTION]

            raise KustoClientError(message)

        return token

    def set_proxy(self, proxy_url: str):
        self._proxy_dict = {"http": proxy_url, "https": proxy_url}

    def set_session(self, session: requests.Session):
        self._session = session


class CloudInfoTokenProvider(TokenProviderBase, abc.ABC):
    _cloud_info: Optional[CloudInfo]
    _scopes = List[str]
    _kusto_uri: str

    def __init__(self, kusto_uri: str, is_async: bool = False):
        super().__init__(is_async)
        self._kusto_uri = kusto_uri

    def _init_resources(self):
        if self._kusto_uri is not None:
            self._cloud_info = CloudSettings.get_cloud_info_for_cluster(self._kusto_uri, self._proxy_dict, self._session)
            resource_uri = self._cloud_info.kusto_service_resource_id
            if self._cloud_info.login_mfa_required:
                resource_uri = resource_uri.replace(".kusto.", ".kustomfa.")

            self._scopes = [resource_uri + "/.default"]


class BasicTokenProvider(TokenProviderBase):
    """Basic Token Provider keeps and returns a token received on construction"""

    def __init__(self, token: str, is_async: bool = False):
        super().__init__(is_async)
        self._token = token

    @staticmethod
    def name() -> str:
        return "BasicTokenProvider"

    def _context_impl(self) -> dict:
        return {"authority": self.name()}

    def _init_impl(self):
        pass

    def _get_token_impl(self) -> Optional[dict]:
        return None

    def _get_token_from_cache_impl(self) -> dict:
        return {TokenConstants.MSAL_TOKEN_TYPE: TokenConstants.BEARER_TYPE, TokenConstants.MSAL_ACCESS_TOKEN: self._token}


class CallbackTokenProvider(TokenProviderBase):
    """Callback Token Provider generates a token based on a callback function provided by the caller"""

    def __init__(
        self, token_callback: Optional[Callable[[], str]], async_token_callback: Optional[Callable[[], Coroutine[None, None, str]]], is_async: bool = False
    ):
        super().__init__(is_async)
        self._token_callback = token_callback
        self._async_token_callback = async_token_callback

    @staticmethod
    def name() -> str:
        return "CallbackTokenProvider"

    def _context_impl(self) -> dict:
        return {"authority": self.name()}

    def _init_impl(self):
        pass

    @staticmethod
    def _build_response(caller_token) -> dict:
        if not isinstance(caller_token, str):
            raise KustoClientError("Token provider returned something that is not a string [" + str(type(caller_token)) + "]")

        return {TokenConstants.MSAL_TOKEN_TYPE: TokenConstants.BEARER_TYPE, TokenConstants.MSAL_ACCESS_TOKEN: caller_token}

    def _get_token_impl(self) -> Optional[dict]:
        if self._token_callback is None:
            raise KustoClientError("token_callback is None, can't retrieve token")
        return self._build_response(self._token_callback())

    async def _get_token_impl_async(self) -> Optional[dict]:
        if self._async_token_callback is None:
            return await super()._get_token_impl_async()
        return self._build_response(await self._async_token_callback())

    def _get_token_from_cache_impl(self) -> Optional[dict]:
        return None


class MsiTokenProvider(CloudInfoTokenProvider):
    """
    MSI Token Provider obtains a token from the MSI endpoint
    The args parameter is a dictionary conforming with the ManagedIdentityCredential initializer API arguments
    """

    def __init__(self, kusto_uri: str, msi_args: dict = None, is_async: bool = False):
        super().__init__(kusto_uri, is_async)
        self._msi_args: dict = msi_args
        self._msi_auth_context: Optional[ManagedIdentityCredential] = None
        self._msi_auth_context_async: Optional[AsyncManagedIdentityCredential] = None

    @staticmethod
    def name() -> str:
        return "MsiTokenProvider"

    def _context_impl(self) -> dict:
        context = self._msi_args.copy()
        context["authority"] = self.name()
        return context

    def _init_impl(self):
        pass

    def _get_token_impl(self) -> Optional[dict]:
        try:
            if self._msi_auth_context is None:
                self._msi_auth_context = ManagedIdentityCredential(**self._msi_args)

            msi_token = self._msi_auth_context.get_token(self._scopes[0])
            return {TokenConstants.MSAL_TOKEN_TYPE: TokenConstants.BEARER_TYPE, TokenConstants.MSAL_ACCESS_TOKEN: msi_token.token}
        except ClientAuthenticationError as e:
            raise KustoClientError("Failed to initialize MSI ManagedIdentityCredential with [{0}]\n{1}".format(self._msi_args, e))
        except Exception as e:
            raise KustoClientError("Failed to obtain MSI token for '{0}' with [{1}]\n{2}".format(self._kusto_uri, self._msi_args, e))

    async def _get_token_impl_async(self) -> Optional[dict]:
        try:
            if self._msi_auth_context_async is None:
                self._msi_auth_context_async = AsyncManagedIdentityCredential(**self._msi_args)

            msi_token = await self._msi_auth_context_async.get_token(self._scopes[0])
            return {TokenConstants.MSAL_TOKEN_TYPE: TokenConstants.BEARER_TYPE, TokenConstants.MSAL_ACCESS_TOKEN: msi_token.token}
        except ClientAuthenticationError as e:
            raise KustoClientError("Failed to initialize MSI async ManagedIdentityCredential with [{0}]\n{1}".format(self._msi_args, e))
        except Exception as e:
            raise KustoClientError("Failed to obtain MSI token for '{0}' with [{1}]\n{2}".format(self._kusto_uri, self._msi_args, e))

    def _get_token_from_cache_impl(self) -> Optional[dict]:
        return None

    def close(self):
        if self._msi_auth_context is not None:
            self._msi_auth_context.close()
        if self._msi_auth_context_async is not None:
            raise KustoAsyncUsageError("Can't close async token provider with sync close", self.is_async)

    async def close_async(self):
        if self._msi_auth_context is not None:
            await sync_to_async(self._msi_auth_context.close())

        if self._msi_auth_context_async is not None:
            await self._msi_auth_context_async.close()


class AzCliTokenProvider(CloudInfoTokenProvider):
    """AzCli Token Provider obtains a refresh token from the AzCli cache and uses it to authenticate with MSAL"""

    def __init__(self, kusto_uri: str, is_async: bool = False):
        super().__init__(kusto_uri, is_async)
        self._az_auth_context = None
        self._az_auth_context_async = None
        self._az_token = None

    @staticmethod
    def name() -> str:
        return "AzCliTokenProvider"

    def _context_impl(self) -> dict:
        return {"authority:": self.name()}

    def _init_impl(self):
        pass

    def _get_token_impl(self) -> Optional[dict]:
        try:
            if self._az_auth_context is None:
                self._az_auth_context = AzureCliCredential()

            self._az_token = self._az_auth_context.get_token(self._scopes[0])
            return {TokenConstants.AZ_TOKEN_TYPE: TokenConstants.BEARER_TYPE, TokenConstants.AZ_ACCESS_TOKEN: self._az_token.token}
        except Exception as e:
            raise KustoClientError(
                "Failed to obtain Az Cli token for '{0}'.\nPlease be sure AzCli version 2.3.0 and above is intalled.\n{1}".format(self._kusto_uri, e)
            )

    async def _get_token_impl_async(self) -> Optional[dict]:
        try:
            if self._az_auth_context_async is None:
                self._az_auth_context_async = AsyncAzureCliCredential()

            self._az_token = await self._az_auth_context_async.get_token(self._scopes[0])
            return {TokenConstants.AZ_TOKEN_TYPE: TokenConstants.BEARER_TYPE, TokenConstants.AZ_ACCESS_TOKEN: self._az_token.token}
        except Exception as e:
            raise KustoClientError(
                "Failed to obtain Az Cli token for '{0}'.\nPlease be sure AzCli version 2.3.0 and above is installed.\n{1}".format(self._kusto_uri, e)
            )

    def _get_token_from_cache_impl(self) -> Optional[dict]:
        if self._az_token is not None:
            # A token is considered valid if it is due to expire in no less than 10 minutes
            cur_time = time.time()
            if (self._az_token.expires_on - 600) > cur_time:
                return {TokenConstants.MSAL_TOKEN_TYPE: TokenConstants.BEARER_TYPE, TokenConstants.MSAL_ACCESS_TOKEN: self._az_token.token}

        return None

    def close(self):
        if self._az_auth_context is not None:
            self._az_auth_context.close()
        if self._az_auth_context_async is not None:
            raise KustoAsyncUsageError("Can't close async token provider with sync close", self.is_async)

    async def close_async(self):
        if self._az_auth_context is not None:
            await sync_to_async(self._az_auth_context.close())

        if self._az_auth_context_async is not None:
            await self._az_auth_context_async.close()


class UserPassTokenProvider(CloudInfoTokenProvider):
    """Acquire a token from MSAL with username and password"""

    def __init__(self, kusto_uri: str, authority_id: str, username: str, password: str, is_async: bool = False):
        super().__init__(kusto_uri, is_async)
        self._msal_client = None
        self._auth = authority_id
        self._user = username
        self._pass = password

    @staticmethod
    def name() -> str:
        return "UserPassTokenProvider"

    def _context_impl(self) -> dict:
        return {"authority": self._cloud_info.authority_uri(self._auth), "client_id": self._cloud_info.kusto_client_app_id, "username": self._user}

    def _init_impl(self):
        self._msal_client = PublicClientApplication(
            client_id=self._cloud_info.kusto_client_app_id, authority=self._cloud_info.authority_uri(self._auth), proxies=self._proxy_dict
        )

    def _get_token_impl(self) -> Optional[dict]:
        token = self._msal_client.acquire_token_by_username_password(username=self._user, password=self._pass, scopes=self._scopes)
        return self._valid_token_or_throw(token)

    def _get_token_from_cache_impl(self) -> dict:
        account = None
        if self._user is not None:
            accounts = self._msal_client.get_accounts(self._user)
            if len(accounts) > 0:
                account = accounts[0]

        token = self._msal_client.acquire_token_silent(scopes=self._scopes, account=account)
        return self._valid_token_or_none(token)


class InteractiveLoginTokenProvider(CloudInfoTokenProvider):
    """Acquire a token from MSAL with Device Login flow"""

    def __init__(
        self,
        kusto_uri: str,
        authority_id: str,
        login_hint: Optional[str] = None,
        domain_hint: Optional[str] = None,
        is_async: bool = False,
    ):
        super().__init__(kusto_uri, is_async)
        self._msal_client = None
        self._auth = authority_id
        self._login_hint = login_hint
        self._domain_hint = domain_hint
        self._account = None

    @staticmethod
    def name() -> str:
        return "InteractiveLoginTokenProvider"

    def _context_impl(self) -> dict:
        return {"authority": self._cloud_info.authority_uri(self._auth), "client_id": self._cloud_info.kusto_client_app_id}

    def _init_impl(self):
        self._msal_client = PublicClientApplication(
            client_id=self._cloud_info.kusto_client_app_id, authority=self._cloud_info.authority_uri(self._auth), proxies=self._proxy_dict
        )

    def _get_token_impl(self) -> Optional[dict]:
        token = self._msal_client.acquire_token_interactive(
            scopes=self._scopes, prompt=TokenConstants.MSAL_INTERACTIVE_PROMPT, login_hint=self._login_hint, domain_hint=self._domain_hint
        )
        return self._valid_token_or_throw(token)

    def _get_token_from_cache_impl(self) -> dict:
        account = None
        accounts = self._msal_client.get_accounts(self._login_hint)
        if len(accounts) > 0:
            account = accounts[0]

        token = self._msal_client.acquire_token_silent(scopes=self._scopes, account=account)
        return self._valid_token_or_none(token)


class ApplicationKeyTokenProvider(CloudInfoTokenProvider):
    """Acquire a token from MSAL with application Id and Key"""

    def __init__(self, kusto_uri: str, authority_id: str, app_client_id: str, app_key: str, is_async: bool = False):
        super().__init__(kusto_uri, is_async)
        self._msal_client = None
        self._app_client_id = app_client_id
        self._app_key = app_key
        self._auth = authority_id

    @staticmethod
    def name() -> str:
        return "ApplicationKeyTokenProvider"

    def _context_impl(self) -> dict:
        return {"authority": self._cloud_info.authority_uri(self._auth), "client_id": self._app_client_id}

    def _init_impl(self):
        self._msal_client = ConfidentialClientApplication(
            client_id=self._app_client_id, client_credential=self._app_key, authority=self._cloud_info.authority_uri(self._auth), proxies=self._proxy_dict
        )

    def _get_token_impl(self) -> Optional[dict]:
        token = self._msal_client.acquire_token_for_client(scopes=self._scopes)
        return self._valid_token_or_throw(token)

    def _get_token_from_cache_impl(self) -> None:
        return None


class ApplicationCertificateTokenProvider(CloudInfoTokenProvider):
    """
    Acquire a token from MSAL using application certificate
    Passing the public certificate is optional and will result in Subject Name & Issuer Authentication
    """

    def __init__(
        self,
        kusto_uri: str,
        client_id: str,
        authority_id: str,
        private_cert: str,
        thumbprint: str,
        public_cert: str = None,
        is_async: bool = False,
    ):
        super().__init__(kusto_uri, is_async)
        self._msal_client = None
        self._auth = authority_id
        self._client_id = client_id
        self._cert_credentials = {TokenConstants.MSAL_PRIVATE_CERT: private_cert, TokenConstants.MSAL_THUMBPRINT: thumbprint}
        if public_cert is not None:
            self._cert_credentials[TokenConstants.MSAL_PUBLIC_CERT] = public_cert

    @staticmethod
    def name() -> str:
        return "ApplicationCertificateTokenProvider"

    def _context_impl(self) -> dict:
        return {
            "authority": self._cloud_info.authority_uri(self._auth),
            "client_id": self._client_id,
            "thumbprint": self._cert_credentials[TokenConstants.MSAL_THUMBPRINT],
        }

    def _init_impl(self):
        self._msal_client = ConfidentialClientApplication(
            client_id=self._client_id, client_credential=self._cert_credentials, authority=self._cloud_info.authority_uri(self._auth), proxies=self._proxy_dict
        )

    def _get_token_impl(self) -> Optional[dict]:
        token = self._msal_client.acquire_token_for_client(scopes=self._scopes)
        return self._valid_token_or_throw(token)

    def _get_token_from_cache_impl(self) -> None:
        return None


class AzureIdentityTokenCredentialProvider(CloudInfoTokenProvider):
    """Acquire a token using an Azure Identity credential"""

    def __init__(
        self,
        kusto_uri: str,
        is_async: bool = False,
        credential: Optional[Any] = None,
        credential_from_login_endpoint: Optional[Callable[[str], Any]] = None,
    ):
        super().__init__(kusto_uri, is_async)

        self.credential = credential
        self.credential_from_login_endpoint = credential_from_login_endpoint

        if self.credential is None and self.credential_from_login_endpoint is None:
            raise KustoClientError("Either a credential or a credential_from_login_endpoint must be provided")

    @staticmethod
    def name() -> str:
        return "AzureIdentityTokenProvider"

    def _context_impl(self) -> dict:
        return {"credential": self.credential}

    def _init_impl(self):
        if self.credential is None:
            self.credential = self.credential_from_login_endpoint(self._cloud_info.login_endpoint)

    def _get_token_impl(self) -> Optional[dict]:
        t = self.credential.get_token(self._scopes[0])
        return {TokenConstants.MSAL_TOKEN_TYPE: TokenConstants.BEARER_TYPE, TokenConstants.MSAL_ACCESS_TOKEN: t.token}

    async def _get_token_impl_async(self) -> Optional[dict]:
        # check if get_token is async
        if inspect.iscoroutinefunction(self.credential.get_token):
            t = await self.credential.get_token(self._scopes[0])
        else:
            t = await sync_to_async(self.credential.get_token)(self._scopes[0])
        return {TokenConstants.MSAL_TOKEN_TYPE: TokenConstants.BEARER_TYPE, TokenConstants.MSAL_ACCESS_TOKEN: t.token}

    def _get_token_from_cache_impl(self) -> Optional[dict]:
        return None

    def close(self):
        if self.credential is not None:
            if inspect.iscoroutinefunction(self.credential.close):
                raise KustoAsyncUsageError("Can't close async token provider with sync close", self.is_async)
            else:
                self.credential.close()
            self.credential = None
            self.credential_from_login_endpoint = None

    async def close_async(self):
        if self.credential is not None:
            if inspect.iscoroutinefunction(self.credential.close):
                await self.credential.close()
            else:
                await sync_to_async(self.credential.close)()
            self.credential = None
            self.credential_from_login_endpoint = None


class DeviceLoginTokenProvider(AzureIdentityTokenCredentialProvider):
    """Acquire a token from MSAL with Device Login flow"""

    def __init__(self, kusto_uri: str, authority_id: str, device_code_callback: DeviceCallbackType = None, is_async: bool = False):
        self._msal_client = None
        self._auth = authority_id
        self._account = None
        self._device_code_callback = device_code_callback

        def credential_from_login_endpoint(endpoint: str):
            cred = DeviceCodeCredential(
                authority=endpoint,
                tenant_id=self._auth,
                client_id=self._cloud_info.kusto_client_app_id,
                prompt_callback=self._device_code_callback,
            )

            return cred

        super().__init__(kusto_uri, is_async, credential_from_login_endpoint=credential_from_login_endpoint)

    @staticmethod
    def name() -> str:
        return "DeviceLoginTokenProvider"

    def _context_impl(self) -> dict:
        return {"authority": self._cloud_info.authority_uri(self._auth), "client_id": self._cloud_info.kusto_client_app_id}
