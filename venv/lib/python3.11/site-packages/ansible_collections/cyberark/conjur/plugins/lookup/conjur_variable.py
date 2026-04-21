# (c) 2020 CyberArk Software Ltd. All rights reserved.
# (c) 2018 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# pylint: disable=too-many-lines
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type  # pylint: disable=invalid-name

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
    name: conjur_variable
    version_added: "1.0.2"
    short_description: Fetch credentials from CyberArk Conjur.
    author:
      - CyberArk BizDev (@cyberark-bizdev)
    description:
      Retrieves credentials from Conjur using the controlling host's Conjur identity,
      environment variables, or extra-vars.
      Environment variables could be CONJUR_ACCOUNT, CONJUR_APPLIANCE_URL, CONJUR_CERT_FILE,
      CONJUR_CERT_CONTENT, CONJUR_AUTHN_LOGIN, CONJUR_AUTHN_API_KEY, CONJUR_AUTHN_TOKEN_FILE,
      CONJUR_AUTHN_TYPE, CONJUR_AUTHN_SERVICE_ID, AZURE_CLIENT_ID
      Extra-vars could be conjur_account, conjur_appliance_url, conjur_cert_file, conjur_cert_content,
      conjur_authn_login, conjur_authn_api_key, conjur_authn_token_file,
      conjur_authn_type, conjur_authn_service_id, azure_client_id
      Conjur info - U(https://www.conjur.org/).
    requirements:
      - 'The controlling host running Ansible has a Conjur identity.
        (More: U(https://docs.conjur.org/latest/en/Content/Get%20Started/key_concepts/machine_identity.html))'
    options:
      _terms:
        description: Variable path
        required: true
      validate_certs:
        description: Flag to control SSL certificate validation
        type: boolean
        default: true
      as_file:
        description: >
          Store lookup result in a temporary file and returns the file path. Thus allowing it to be consumed as an ansible file parameter
          (eg ansible_ssh_private_key_file).
        type: boolean
        default: false
      identity_file:
        description: Path to the Conjur identity file. The identity file follows the netrc file format convention.
        type: path
        default: /etc/conjur.identity
        required: false
        ini:
          - section: conjur,
            key: identity_file_path
        env:
          - name: CONJUR_IDENTITY_FILE
      config_file:
        description: Path to the Conjur configuration file. The configuration file is a YAML file.
        type: path
        default: /etc/conjur.conf
        required: false
        ini:
          - section: conjur,
            key: config_file_path
        env:
          - name: CONJUR_CONFIG_FILE
      conjur_appliance_url:
        description: Conjur appliance url
        type: string
        required: false
        ini:
          - section: conjur,
            key: appliance_url
        vars:
          - name: conjur_appliance_url
        env:
          - name: CONJUR_APPLIANCE_URL
      conjur_authn_login:
        description: Conjur authn login
        type: string
        required: false
        ini:
          - section: conjur,
            key: authn_login
        vars:
          - name: conjur_authn_login
        env:
          - name: CONJUR_AUTHN_LOGIN
      conjur_account:
        description: Conjur account
        type: string
        required: false
        ini:
          - section: conjur,
            key: account
        vars:
          - name: conjur_account
        env:
          - name: CONJUR_ACCOUNT
      conjur_authn_api_key:
        description: Conjur authn api key
        type: string
        required: false
        ini:
          - section: conjur,
            key: authn_api_key
        vars:
          - name: conjur_authn_api_key
        env:
          - name: CONJUR_AUTHN_API_KEY
      conjur_cert_file:
        description: Path to the Conjur cert file
        type: path
        required: false
        ini:
          - section: conjur,
            key: cert_file
        vars:
          - name: conjur_cert_file
        env:
          - name: CONJUR_CERT_FILE
      conjur_cert_content:
        description: Content of the Conjur cert
        type: string
        required: false
        ini:
          - section: conjur,
            key: cert_content
        vars:
          - name: conjur_cert_content
        env:
          - name: CONJUR_CERT_CONTENT
      conjur_authn_token_file:
        description: Path to the access token file
        type: path
        required: false
        ini:
          - section: conjur,
            key: authn_token_file
        vars:
          - name: conjur_authn_token_file
        env:
          - name: CONJUR_AUTHN_TOKEN_FILE
      conjur_authn_type:
        description: Type of Conjur authenticator
        type: string
        required: False
        ini:
          - section: conjur,
            key: authn_type
        vars:
          - name: conjur_authn_type
        env:
          - name: CONJUR_AUTHN_TYPE
      conjur_authn_service_id:
        description: Service ID for cloud-based authenticators
        type: string
        required: False
        ini:
          - section: conjur,
            key: authn_service_id
        vars:
          - name: conjur_authn_service_id
        env:
          - name: CONJUR_AUTHN_SERVICE_ID
      azure_client_id:
        description: Client id for azure user-assigned managed identity
        type: string
        required: False
        ini:
          - section: azure,
            key: client_id
        vars:
          - name: azure_client_id
        env:
          - name: AZURE_CLIENT_ID
"""

EXAMPLES = """
---
- hosts: localhost
  collections:
    - cyberark.conjur
  tasks:
    - name: Lookup variable in Conjur
      debug:
        msg: "{{ lookup('cyberark.conjur.conjur_variable', '/path/to/secret') }}"
"""

RETURN = """
  _raw:
    description:
      - Value stored in Conjur.
"""

import os
import socket
import traceback
import ssl
import re
import shutil
from base64 import b64encode
from netrc import netrc
from time import sleep
from stat import S_IRUSR, S_IWUSR
from tempfile import gettempdir, NamedTemporaryFile
import datetime
import hashlib
import hmac
import json
import urllib.parse
import yaml
import ansible.module_utils.six.moves.urllib.error as urllib_error
from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.module_utils.six.moves.urllib.parse import quote
from ansible.module_utils.urls import open_url
from ansible.utils.display import Display
try:
    from cryptography.x509 import load_pem_x509_certificate
    from cryptography.hazmat.backends import default_backend
except ImportError:
    cryptography_import_error = traceback.format_exc()
else:
    cryptography_import_error = None

display = Display()
temp_cert_file = None
telemetry_header = None


# ************* REQUEST VALUES *************
AWS_METADATA_URL = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
AWS_AVAILABILITY_ZONE = "http://169.254.169.254/latest/meta-data/placement/availability-zone"
AWS_TOKEN_URL = "http://169.254.169.254/latest/api/token"
METHOD = 'GET'
SERVICE = 'sts'
HOST = 'sts.amazonaws.com'
ENDPOINT = 'https://sts.amazonaws.com'
REQUEST_PARAMETERS = 'Action=GetCallerIdentity&Version=2011-06-15'

AZURE_METADATA_URL = "http://169.254.169.254/metadata/identity/oauth2/token"
GCP_METADATA_URL = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity"


class ConjurIAMAuthnException(Exception):
    """
    Exception raised when Conjur IAM authentication fails with a 401 Unauthorized error.
    """
    def __init__(self):
        Exception.__init__(
            self,
            "Conjur IAM authentication failed with 401 - Unauthorized. "
            "Check conjur logs for more information"
        )


class IAMRoleNotAvailableException(Exception):
    """
    Raised when the IAM Role is not available or incorrectly configured.
    """
    def __init__(self):
        Exception.__init__(
            self,
            "Most likely the ec2 instance is configured with no or an incorrect iam role"
        )


class InvalidAwsAccountIdException(Exception):
    """
    Raised when the AWS Account ID is invalid
    """
    def __init__(self):
        Exception.__init__(
            self,
            "The AWS Account ID specified in the CONJUR_AUTHN_LOGIN is invalid and "
            "must be a 12 digit number"
        )


def _valid_aws_account_number(host_id):
    """
    Checks if the given host_id contains a valid 12-digit AWS Account ID.
    """
    parts = host_id.split("/")
    account_id = parts[len(parts) - 2]
    if len(account_id) == 12:
        return True
    return False


def _sign(key, msg):
    """
    Signs the given message using the provided key and HMAC with SHA-256.
    """
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def _get_signature_key(key, date_stamp, region_name, service_name):
    """
    Generates the AWS V4 signing key using the provided key,
    date, region, and service name.
    """
    k_date = _sign(('AWS4' + key).encode('utf-8'), date_stamp)
    k_region = _sign(k_date, region_name)
    k_service = _sign(k_region, service_name)
    k_signing = _sign(k_service, 'aws4_request')
    return k_signing


def _get_aws_region():
    """
    Get the AWS Region.
    """
    return "us-east-1"


def _get_iam_role_name():
    """
    Retrieves the IAM Role Name associated with the current environment.
    """
    token = _get_metadata_token()
    headers = {}
    if token:
        headers = {'X-aws-ec2-metadata-token': token}
    res = open_url(
        AWS_METADATA_URL,
        method='GET',
        validate_certs=False,
        ca_path=None,
        headers=headers
    )
    res_body = res.read().decode('utf-8')
    return res_body


def _get_metadata_token():
    """Request a session token for IMDSv2"""
    headers = {'X-aws-ec2-metadata-token-ttl-seconds': '900'}
    token = None
    try:
        response = open_url(
            AWS_TOKEN_URL,
            method='PUT',
            validate_certs=False,
            ca_path=None,
            headers=headers
        )
        response_body = response.read().decode('utf-8')

        if response.getcode() == 200:
            return response_body
        return None
    except Exception as error:  # pylint: disable=broad-except
        display.warning(f"IMDSv2 token retrieval failed: {str(error)}. Falling back to IMDSv1.")
        return None
    finally:
        if token:
            token = None


def _get_iam_role_metadata(role_name, token=None):
    """
    Retrieves metadata for the IAM role associated with the current environment.
    """

    headers = {}
    if token:
        headers = {'X-aws-ec2-metadata-token': token}

    try:
        res = open_url(
            AWS_METADATA_URL + role_name,
            method='GET',
            headers=headers,
            validate_certs=False
        )
        if res.getcode() == 404:
            raise AnsibleError(f"Error retrieving IAM role metadata: {str(res.getcode())}")

        if res.getcode() != 200:
            raise AnsibleError(f"Error retrieving IAM role metadata: {str(res.getcode())}")

        res_body = res.read().decode('utf-8')
        json_dict = json.loads(res_body)

        access_key_id = json_dict["AccessKeyId"]
        secret_access_key = json_dict["SecretAccessKey"]
        token = json_dict["Token"]

        return access_key_id, secret_access_key, token

    except Exception as error:
        raise AnsibleError(f"Error retrieving IAM role metadata: Exception occurred - {str(error)}") from error


def _create_canonical_request(amzdate, token, signed_headers, payload_hash):
    """
    Creates the canonical request string for signing the AWS request.
    """
    canonical_uri = '/'
    canonical_querystring = REQUEST_PARAMETERS
    canonical_headers = 'host:' + HOST + '\n' + 'x-amz-content-sha256:' + payload_hash + '\n' + \
        'x-amz-date:' + amzdate + '\n' + 'x-amz-security-token:' + token + '\n'

    canonical_request = METHOD + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + \
        canonical_headers + '\n' + signed_headers + '\n' + payload_hash

    return canonical_request


# pylint: disable=too-many-arguments,too-many-locals
def _create_conjur_iam_api_key(iam_role_name=None, access_key=None, secret_key=None, token=None):
    """
    Creates an IAM API key for Conjur authentication using the provided IAM role and credentials.
    """
    if iam_role_name is None:
        iam_role_name = _get_iam_role_name()

    metadata_token = _get_metadata_token()

    if access_key is None and secret_key is None and token is None:
        access_key, secret_key, token = _get_iam_role_metadata(iam_role_name, metadata_token)

    region = _get_aws_region()

    if access_key is None or secret_key is None:
        raise AnsibleError('No access key is available.')

    date = datetime.datetime.now(datetime.timezone.utc)
    amzdate = date.strftime('%Y%m%dT%H%M%SZ')
    datestamp = date.strftime('%Y%m%d')

    signed_headers = 'host;x-amz-content-sha256;x-amz-date;x-amz-security-token'
    payload_hash = hashlib.sha256(('').encode('utf-8')).hexdigest()
    canonical_request = _create_canonical_request(amzdate, token, signed_headers, payload_hash)

    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = datestamp + '/' + region + '/' + SERVICE + '/' + 'aws4_request'
    string_to_sign = algorithm + '\n' + amzdate + '\n' + credential_scope + \
        '\n' + hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

    signing_key = _get_signature_key(secret_key, datestamp, region, SERVICE)

    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

    authorization_header = (
        algorithm + ' ' +
        'Credential=' + access_key + '/' + credential_scope + ', ' +
        'SignedHeaders=' + signed_headers + ', ' +
        'Signature=' + signature
    )

    headers = {
        'host': HOST,
        'x-amz-date': amzdate,
        'x-amz-security-token': token,
        'x-amz-content-sha256': payload_hash,
        'authorization': authorization_header
    }

    access_key = None
    secret_key = None
    token = None
    signing_key = None
    string_to_sign = None
    canonical_request = None

    return f'{headers}'.replace("'", '"')


def _fetch_conjur_iam_session_token(
    appliance_url, account, service_id, host_id, cert_file, validate_certs,
    iam_role_name=None, access_key=None, secret_key=None, token=None
):
    """
    Retrieves the Conjur IAM session token for the provided service and IAM role credentials.
    """

    if not _valid_aws_account_number(host_id):
        raise InvalidAwsAccountIdException()

    # Get the telemetry header
    encoded_telemetry = _telemetry_header()

    headers = {
        'x-cybr-telemetry': encoded_telemetry
    }

    appliance_url = appliance_url.rstrip("/")
    url = (
        f"{appliance_url}/authn-iam/{service_id}/{account}/"
        f"{urllib.parse.quote(host_id, safe='')}/authenticate"
    )

    iam_api_key = _create_conjur_iam_api_key(iam_role_name, access_key, secret_key, token)

    try:
        res = open_url(
            url,
            data=iam_api_key,
            method='POST',
            validate_certs=validate_certs,
            ca_path=cert_file,
            headers=headers
        )
        res_body = res.read()
        if res.getcode() == 401:
            raise ConjurIAMAuthnException()
        if res.getcode() != 200:
            raise AnsibleError(f'Failed to authenticate - (got {str(res.getcode())} response)')

        return res_body
    finally:
        iam_api_key = None


def _validate_pem_certificate(cert_content):
    # Normalize line endings
    if '\r\n' in cert_content:
        cert_content = cert_content.replace('\r\n', '\n').strip()
    elif '\r' in cert_content:
        cert_content = cert_content.replace('\r', '\n').strip()
    cert_content = re.sub(r'^[ \t]+', '', cert_content, flags=re.M)
    cert_content = re.sub(r'[ \t]+$', '', cert_content, flags=re.M)
    cert_content = re.sub(r'\n+', '\n', cert_content)

    if not re.match(r"^-----BEGIN CERTIFICATE-----.+-----END CERTIFICATE-----$", cert_content, re.DOTALL):
        raise AnsibleError("Invalid Certificate format.")

    try:
        load_pem_x509_certificate(cert_content.encode(), default_backend())
        return cert_content
    except ValueError as err:
        raise AnsibleError(
            f"Invalid certificate content provided: {str(err)}. "
            "Please check the certificate format."
        ) from err
    except ssl.SSLError as err:
        raise AnsibleError(
            f"SSL error while validating the certificate: {str(err)}. "
            "The certificate may be corrupted or invalid."
        ) from err
    except Exception as err:
        raise AnsibleError(
            f"An error occurred while validating the certificate: {str(err)}. "
            "Please verify the certificate format and try again."
        ) from err


def _get_valid_certificate(cert_content, cert_file):
    if cert_content:
        try:
            display.vvv("Validating provided certificate content")
            cert_content = _validate_pem_certificate(cert_content)
            return cert_content
        except AnsibleError as err:
            display.warning(f"Invalid certificate content: {str(err)}. Attempting to use certificate file.")

    # If cert_content is invalid or missing, fall back to cert_file
    if cert_file:
        if not os.path.exists(cert_file):
            raise AnsibleError(f"Certificate file `{cert_file}` does not exist or cannot be found.")
        try:
            with open(cert_file, 'rb') as file:
                cert_file_content = file.read().decode('utf-8')
                cert_file_content = _validate_pem_certificate(cert_file_content)
                return cert_file_content
        except Exception as err:
            raise AnsibleError(f"Failed to load or validate certificate file `{cert_file}`: {str(err)}") from err

    # If both cert_content and cert_file are missing or invalid, raise an error
    raise AnsibleError("Both certificate content and certificate file are invalid or missing. Please provide a valid certificate.")


def _get_certificate_file(cert_content, cert_file):
    """
    Creates a CA bundle containing CAs from the system truststore appended with the
    provided certificate. The CA bundle is stored in a temporary file.

    The file must persist until the end of the process, so `delete=False` is used
    to prevent automatic deletion. We manually handle deletion at the end of the process
    to ensure proper resource management. A global variable tracks the file for cleanup.

    Pylint's warning about not using a `with` statement is disabled because the file
    needs to remain accessible beyond the function scope.

    Args:
        cert_content (str): Raw certificate content.
        cert_file (str): Path to an existing certificate file, if provided.

    Returns:
        str: Path to the certificate file to be used.
    """
    global temp_cert_file
    cert_content = _get_valid_certificate(cert_content, cert_file)

    if cert_content:
        try:
            temp_cert_file = NamedTemporaryFile(delete=False)  # pylint: disable=consider-using-with

            # Prepare a CA bundle including system CA certificates
            system_ca_bundle = ssl.get_default_verify_paths().cafile
            if system_ca_bundle and os.path.exists(system_ca_bundle):
                with open(system_ca_bundle, 'rb') as bundle:
                    shutil.copyfileobj(bundle, temp_cert_file)
            else:
                display.warning("System CA bundle not found, only the provided cert(s) will be used.")

            # Normalize and append custom cert(s)
            cert_bytes = cert_content.encode() if isinstance(cert_content, str) else cert_content
            temp_cert_file.write(b"\n" + cert_bytes.strip().replace(b"\r\n", b"\n") + b"\n")
            temp_cert_file.close()
            cert_file = temp_cert_file.name
        except Exception as err:
            raise AnsibleError(f"Failed to create temporary CA bundle: {str(err)}") from err

    return cert_file


# Load configuration and return as dictionary if file is present on file system
def _load_conf_from_file(conf_path):
    display.vvv(f'conf file: {conf_path}')

    if not os.path.exists(conf_path):
        return {}
        # raise AnsibleError('Conjur configuration file `{conf_path}` was not found on the controlling host')

    display.vvvv(f'Loading configuration from: {conf_path}')
    with open(conf_path, encoding="utf-8") as file:
        config = yaml.safe_load(file.read())
        return config


# Load identity and return as dictionary if file is present on file system
def _load_identity_from_file(identity_path, appliance_url):
    display.vvvv(f'identity file: {identity_path}')

    if not os.path.exists(identity_path):
        return {}
        # raise AnsibleError(f'Conjur identity file `{identity_path}` was not found on the controlling host')

    display.vvvv(f'Loading identity from: {identity_path} for {appliance_url}')

    conjur_authn_url = f'{appliance_url}/authn'
    identity = netrc(identity_path)

    if identity.authenticators(conjur_authn_url) is None:
        raise AnsibleError(f'The netrc file on the controlling host does not contain an entry for: {conjur_authn_url}')

    host_id, unused, api_key = identity.authenticators(conjur_authn_url)  # pylint: disable=unused-variable

    if not host_id or not api_key:
        return {}

    return {'id': host_id, 'api_key': api_key}


# Merge multiple dictionaries by using dict.update mechanism
def _merge_dictionaries(*arg):
    ret = {}
    for item in arg:
        ret.update(item)
    return ret


# The `quote` method's default value for `safe` is '/' so it doesn't encode slashes
# into "%2F" which is what the Conjur server expects. Thus, we need to use this
# method with no safe characters. We can't use the method `quote_plus` (which encodes
# slashes correctly) because it encodes spaces into the character '+' instead of "%20"
# as expected by the Conjur server
def _encode_str(input_str):
    return quote(input_str, safe='')


# Prepare the telemetry header
def _telemetry_header():
    global telemetry_header

    if telemetry_header is None:
        plugin_dir = os.path.dirname(__file__)
        collection_root = os.path.abspath(os.path.join(plugin_dir, '..', '..'))
        version_file_path = os.path.join(collection_root, 'VERSION')
        if os.path.isfile(version_file_path):
            with open(version_file_path, 'r', encoding='utf-8') as version_file:
                version = version_file.read().strip()
        else:
            version_file_path = os.path.join(collection_root, 'collections', 'ansible_collections', 'cyberark', 'conjur', 'VERSION')
            if os.path.isfile(version_file_path):
                with open(version_file_path, 'r', encoding='utf-8') as version_file:
                    version = version_file.read().strip()
            else:
                galaxy_file_path = os.path.join(collection_root, 'galaxy.yml')
                if os.path.isfile(galaxy_file_path):
                    try:
                        with open(galaxy_file_path, 'r', encoding='utf-8') as galaxy_file:
                            galaxy_data = yaml.safe_load(galaxy_file)
                            version = galaxy_data['version']
                    except (IOError, KeyError, yaml.YAMLError):
                        version = "unknown"
                else:
                    version = "unknown"

        # Prepare the telemetry value
        telemetry_val = f'in=Ansible Collections&it=cybr-secretsmanager&iv={version}&vn=Ansible'

        # Encode to base64
        telemetry_header = b64encode(telemetry_val.encode()).decode().rstrip("=")
    return telemetry_header


# Use credentials to retrieve temporary authorization token
def _fetch_conjur_token(conjur_url, account, username, api_key, validate_certs, cert_file):  # pylint: disable=too-many-arguments
    conjur_url = f'{conjur_url}/authn/{account}/{_encode_str(username)}/authenticate'
    display.vvvv(f'Authentication request to Conjur at: {conjur_url}, with user: {_encode_str(username)}')

    # Get the telemetry header
    encoded_telemetry = _telemetry_header()

    # Prepare headers
    headers = {
        'x-cybr-telemetry': encoded_telemetry
    }

    response = open_url(conjur_url,
                        data=api_key,
                        method='POST',
                        validate_certs=validate_certs,
                        ca_path=cert_file,
                        headers=headers)
    code = response.getcode()
    if code != 200:
        raise AnsibleError(f'Failed to authenticate as \'{username}\' (got {code} response)')

    return response.read()


def retry(retries, retry_interval):
    """
    Custom retry decorator

    Args:
        retries (int, optional): Number of retries. Defaults to 5.
        retry_interval (int, optional): Time to wait between intervals. Defaults to 10.
    """
    def parameters_wrapper(target):
        def decorator(*args, **kwargs):
            retry_count = 0
            while True:
                retry_count += 1
                try:
                    return_value = target(*args, **kwargs)
                    return return_value
                except urllib_error.HTTPError as err:
                    if retry_count >= retries:
                        raise err
                    display.v('Error encountered. Retrying..')
                except socket.timeout as err:
                    if retry_count >= retries:
                        raise err
                    display.v('Socket timeout encountered. Retrying..')
                sleep(retry_interval)
        return decorator
    return parameters_wrapper


@retry(retries=5, retry_interval=10)
def _repeat_open_url(url, headers=None, method=None, validate_certs=True, ca_path=None):
    return open_url(url,
                    headers=headers,
                    method=method,
                    validate_certs=validate_certs,
                    ca_path=ca_path)


# Retrieve Conjur variable using the temporary token
def _fetch_conjur_variable(conjur_variable, token, conjur_url, account, validate_certs, cert_file):  # pylint: disable=too-many-arguments
    token = b64encode(token)
    # Get the telemetry header
    encoded_telemetry = _telemetry_header()

    headers = {
        'Authorization': f'Token token="{token.decode("utf-8")}"',
        'x-cybr-telemetry': encoded_telemetry
    }

    url = f'{conjur_url}/secrets/{account}/variable/{_encode_str(conjur_variable)}'
    display.vvvv(f'Conjur Variable URL: {url}')

    response = _repeat_open_url(url,
                                headers=headers,
                                method='GET',
                                validate_certs=validate_certs,
                                ca_path=cert_file)

    if response.getcode() == 200:
        display.vvvv(f'Conjur variable {conjur_variable} was successfully retrieved')
        value = response.read().decode("utf-8")
        return [value]
    if response.getcode() == 401:
        raise AnsibleError('Conjur request has invalid authorization credentials')
    if response.getcode() == 403:
        raise AnsibleError(f'The controlling host\'s Conjur identity does not have authorization to retrieve {conjur_variable}')
    if response.getcode() == 404:
        raise AnsibleError(f'The variable {conjur_variable} does not exist')

    return {}


def _default_tmp_path():
    if os.access("/dev/shm", os.W_OK):
        return "/dev/shm"

    return gettempdir()


def _store_secret_in_file(value):
    """
    Writes a secret value to a secure temporary file and returns its path.

    The file is created in /dev/shm or /tmp (based on `_default_tmp_path()`),
    with user-only read/write permissions. `delete=False` ensures the file
    persists beyond this function, as it needs to be accessible later.

    Note: We avoid using a `with` statement here to prevent premature file
    closure or deletion, which would make the file unusable.

    Args:
        value (list): List containing the secret string.

    Returns:
        list: Path to the temporary file as a single-item list.
    """
    secrets_file = NamedTemporaryFile(mode='w', dir=_default_tmp_path(), delete=False)  # pylint: disable=consider-using-with
    os.chmod(secrets_file.name, S_IRUSR | S_IWUSR)
    secrets_file.write(value[0])
    return [secrets_file.name]


# Fetch token from aure vm, func, app and authn with conjur for access token
def _fetch_conjur_azure_token(
    appliance_url, account, service_id,
    host_id, cert_file, validate_certs, client_id=""
):
    try:
        params = {
            "api-version": "2018-02-01",
            "resource": "https://management.azure.com/"
        }

        if client_id:
            params["client_id"] = client_id

        headers = {
            "Metadata": "true"
        }
        url_with_params = f"{AZURE_METADATA_URL}?{urllib.parse.urlencode(params)}"
        response = open_url(
            url_with_params,
            method='GET',
            headers=headers,
            validate_certs=validate_certs,
            timeout=10
        )

        response_body = response.read().decode('utf-8')
        # Parse JSON response
        data = json.loads(response_body)

        if response.getcode() != 200:
            raise AnsibleError(f"Error retrieving token from azure: {str(response.getcode())}")

        appliance_url = appliance_url.rstrip("/")
        url = (
            f"{appliance_url}/authn-azure/{service_id}/{account}/"
            f"{urllib.parse.quote(host_id, safe='')}/authenticate"
        )

        token = f"jwt={data.get('access_token')}"

        # Get the telemetry header
        encoded_telemetry = _telemetry_header()

        # Prepare headers
        headers = {
            'x-cybr-telemetry': encoded_telemetry
        }
        response = open_url(
            url,
            method='POST',
            data=token.encode('utf-8'),
            headers=headers,
            validate_certs=validate_certs,
            ca_path=cert_file,
            timeout=10
        )
        if response.getcode() != 200:
            raise AnsibleError(f"Error authenticating with Conjur: HTTP {str(response.getcode())}")
        return response.read()

    except urllib.error.URLError as error:
        raise AnsibleError(f"Error fetching identity token: URL error occurred - {str(error)}") from error

    except RuntimeError as error:
        raise AnsibleError(f"Error fetching identity token: {str(error)}") from error

    except Exception as error:
        raise AnsibleError(f"Error fetching identity token: {str(error)}") from error
    finally:
        client_id = None
        token = None
        response_body = None


def _fetch_conjur_gcp_identity_token(
    appliance_url, account, host_id, cert_file, validate_certs
):
    try:
        params = {
            'audience': f'conjur/{account}/{host_id}',
            'format': 'full'
        }
        headers = {'Metadata-Flavor': 'Google'}

        url_with_params = f"{GCP_METADATA_URL}?{urllib.parse.urlencode(params)}"

        response = open_url(
            url_with_params,
            method='GET',
            headers=headers,
            validate_certs=validate_certs,
            timeout=10
        )

        if response.getcode() != 200:
            raise AnsibleError(f"Error retrieving token from gcp: {str(response.getcode())}")

        response_body = response.read().decode('utf-8')
        appliance_url = appliance_url.rstrip("/")
        url = f"{appliance_url}/authn-gcp/{account}/authenticate"

        token = f"jwt={response_body}"

        # Get the telemetry header
        encoded_telemetry = _telemetry_header()

        # Prepare headers
        headers = {
            'x-cybr-telemetry': encoded_telemetry
        }
        response = open_url(
            url,
            method='POST',
            data=token.encode('utf-8'),
            headers=headers,
            validate_certs=validate_certs,
            ca_path=cert_file,
            timeout=10
        )
        if response.getcode() != 200:
            raise AnsibleError(f"Error: Received status code {str(response.getcode())}")

        return response.read()
    except urllib.error.URLError as error:
        raise AnsibleError(f"Error fetching identity token: URL error occurred - {str(error)}") from error

    except RuntimeError as error:
        raise AnsibleError(f"Error fetching identity token: {str(error)}") from error

    except Exception as error:
        raise AnsibleError(f"Error fetching identity token: {str(error)}") from error
    finally:
        token = None
        response_body = None


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):  # pylint: disable=too-many-locals,missing-function-docstring,too-many-branches,too-many-statements
        if terms == []:
            raise AnsibleError("Invalid secret path: no secret path provided.")
        if not terms[0] or terms[0].isspace():
            raise AnsibleError("Invalid secret path: empty secret path not accepted.")

        # We should register the variables as LookupModule options.
        #
        # Doing this has some nice advantages if we're considering supporting
        # a set of Ansible variables that could sometimes replace environment
        # variables.
        #
        # Registering the variables as options forces them to adhere to the
        # behavior described in the DOCUMENTATION variable. An option can have
        # both a Ansible variable and environment variable source, which means
        # Ansible will do some juggling on our behalf.
        self.set_options(var_options=variables, direct=kwargs)

        appliance_url = self.get_var_value("conjur_appliance_url")
        account = self.get_var_value("conjur_account")
        authn_login = self.get_var_value("conjur_authn_login")
        authn_api_key = self.get_var_value("conjur_authn_api_key")
        cert_file = self.get_var_value("conjur_cert_file")
        cert_content = self.get_var_value("conjur_cert_content")
        authn_token_file = self.get_var_value("conjur_authn_token_file")
        authn_type = self.get_var_value("conjur_authn_type")
        service_id = self.get_var_value("conjur_authn_service_id")
        azure_client_id = self.get_var_value("azure_client_id")

        validate_certs = self.get_option('validate_certs')
        conf_file = self.get_option('config_file')
        as_file = self.get_option('as_file')

        if validate_certs is False:
            display.warning('Certificate validation has been disabled. Please enable with validate_certs option.')

        if 'http://' in str(appliance_url):
            raise AnsibleError(('[WARNING]: Conjur URL uses insecure connection. Please consider using HTTPS.'))

        if validate_certs is True:
            cert_file = _get_certificate_file(cert_content, cert_file)

        if authn_type in ("aws", "azure") and service_id is None:
            raise AnsibleError("[WARNING]: Please set the conjur_authn_service_id for AWS or Azure authenticator")

        if not account:
            display.vvv("No conjur account provided. Defaulting to 'conjur'.")
            account = "conjur"

        conf = _merge_dictionaries(
            _load_conf_from_file(conf_file),
            {
                "account": account,
                "appliance_url": appliance_url
            } if (appliance_url is not None)
            else {},
            {
                "cert_file": cert_file
            } if (cert_file is not None)
            else {},
            {
                "authn_token_file": authn_token_file
            } if authn_token_file is not None
            else {}
        )

        if 'appliance_url' not in conf:
            raise AnsibleError(
                """Configuration must define options `conjur_appliance_url`.
                This config can be set by any of the following methods, listed in order of priority:
                - Ansible variable `conjur_appliance_url`, set in the parent playbook or
                  passed via --extra-vars
                - Environment variable `CONJUR_APPLIANCE_URL`
                - A configuration file on the controlling host with the field `appliance_url`"""
            )

        if 'authn_token_file' not in conf:
            identity_file = self.get_option('identity_file')
            identity = _merge_dictionaries(
                _load_identity_from_file(identity_file, conf['appliance_url']),
                {
                    **({"id": authn_login} if authn_login is not None else {}),
                    **({"api_key": authn_api_key} if authn_api_key is not None else {})
                }
            )

            if 'id' not in identity:
                raise AnsibleError(
                    """Configuration must define options `conjur_authn_login`.
                    This config can be set by any of the following methods, listed in order of priority:
                    - Ansible variable `conjur_authn_login`, set either in the parent playbook or passed via --extra-vars
                    - Environment variable `CONJUR_AUTHN_LOGIN`
                    - An identity file with the field `login`"""
                )

        cert_file = None
        if 'cert_file' in conf:
            display.vvv(f"Using cert file path {conf['cert_file']}")
            cert_file = conf['cert_file']

        try:
            token = None
            if 'authn_token_file' not in conf:
                display.vvv(f"Using auth_type as {authn_type}")
                if authn_type == 'aws':
                    token = _fetch_conjur_iam_session_token(
                        appliance_url=conf['appliance_url'],
                        account=conf['account'],
                        host_id=identity['id'],
                        service_id=service_id,
                        validate_certs=validate_certs,
                        cert_file=cert_file
                    )
                elif authn_type == "azure":
                    token = _fetch_conjur_azure_token(
                        appliance_url=conf['appliance_url'],
                        account=conf['account'],
                        host_id=identity['id'],
                        service_id=service_id,
                        validate_certs=validate_certs,
                        cert_file=cert_file,
                        client_id=azure_client_id
                    )
                elif authn_type == "gcp":
                    token = _fetch_conjur_gcp_identity_token(
                        appliance_url=conf['appliance_url'],
                        account=conf['account'],
                        host_id=identity['id'],
                        validate_certs=validate_certs,
                        cert_file=cert_file,
                    )
                else:
                    token = _fetch_conjur_token(
                        conf['appliance_url'],
                        conf['account'],
                        identity['id'],
                        identity['api_key'],
                        validate_certs,
                        cert_file
                    )
            else:
                if not os.path.exists(conf['authn_token_file']):
                    raise AnsibleError(f"Conjur authn token file `{conf['authn_token_file']}` was not found on the host")
                with open(conf['authn_token_file'], 'rb') as file:
                    token = file.read()

            conjur_variable = _fetch_conjur_variable(
                terms[0],
                token,
                conf['appliance_url'],
                conf['account'],
                validate_certs,
                cert_file
            )
        finally:
            if isinstance(token, bytes):
                token = b"\x00" * len(token)
            else:
                token = None

            if temp_cert_file:
                try:
                    if os.path.exists(temp_cert_file.name):
                        os.unlink(temp_cert_file.name)
                except (OSError, PermissionError) as err:
                    raise AnsibleError(f"Failed to delete temporary certificate file `{temp_cert_file.name}`: {str(err)}") from err

        if as_file:
            return _store_secret_in_file(conjur_variable)

        return conjur_variable

    def get_var_value(self, key):
        try:
            variable_value = self.get_option(key)
        except KeyError as err:
            raise AnsibleError(f"{key} was not defined in configuration") from err

        return variable_value
