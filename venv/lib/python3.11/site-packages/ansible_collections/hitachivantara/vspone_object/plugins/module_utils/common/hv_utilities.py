import re
import json
import urllib.error
from .hv_log import (Log)

logger = Log()  # Assuming Log() is defined elsewhere


class DictUtilities:
    @staticmethod
    def snake_to_camel(snake_dict):
        def convert_key(key):
            components = key.split('_')
            return components[0] + ''.join(x.title() for x in components[1:])

        return {convert_key(k): v for k, v in snake_dict.items()}

    @staticmethod
    def delete_keys(data: dict, keys_to_remove: list) -> dict:
        """
        Removes specified keys from a dictionary.

        :param data: The original dictionary.
        :param keys_to_remove: A list of keys to remove.
        :return: A new dictionary with the specified keys removed.
        """
        if data is None:
            return {}
        return {k: v for k, v in data.items() if k not in keys_to_remove}

    @staticmethod
    def is_subset_dict(dict1, dict2):
        """
        Returns True if all key-value pairs in dict1 are present in dict2.
        Returns False if any key in dict1 is missing in dict2 or has a different value.
        """
        if dict is None or dict2 is None:
            return False
        for key, value in dict1.items():
            if key not in dict2 or dict2[key] != value:
                return False
        return True

    @staticmethod
    def is_same_dict(dict1, dict2):
        """
        Returns True if both dictionaries have the same keys and values.
        """
        if dict1 is None and dict2 is None:
            return True
        if dict1 is None or dict2 is None:
            return False
        if dict1.keys() != dict2.keys():
            return False
        for key in dict1.keys():
            if dict1[key] != dict2[key]:
                return False
        return True

    @staticmethod
    def camel_to_snake(name):
        """Convert camelCase or PascalCase to snake_case."""
        s1 = re.sub(r'(.)([A-Z][a-z]+)', r'\1_\2', name)
        return re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

    @staticmethod
    def convert_keys_to_snake_case(obj):
        """Recursively convert dictionary keys from camelCase to snake_case."""
        if isinstance(obj, dict):
            new_dict = {}
            for key, value in obj.items():
                new_key = DictUtilities.camel_to_snake(key)
                new_dict[new_key] = DictUtilities.convert_keys_to_snake_case(value)
            return new_dict
        elif isinstance(obj, list):
            return [DictUtilities.convert_keys_to_snake_case(item) for item in obj]
        else:
            return obj


class StringUtilities:
    @staticmethod
    def snake_to_camel(snake_str):
        """
        Converts a string from snake_case to camelCase.

        Parameters:
        snake_str (str): The input string in snake_case format.

        Returns:
        str: The converted string in camelCase format.
        """
        # Split the string into a list of words using '_' as the separator
        components = snake_str.split('_')

        # Capitalize each word except the first, then join them
        return components[0] + ''.join(x.title() for x in components[1:])

    @staticmethod
    def camel_to_snake(camel_str):
        """
        Converts a string from camelCase to snake_case.

        Parameters:
        snake_str (str): The input string in camelCase format.

        Returns:
        str: The converted string in snake_case format.
        """
        snake_str = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', camel_str)
        return snake_str.lower()


class SecurityUtilities:
    # Recursive function
    @staticmethod
    def mask_sensitive_data(data, fields_to_mask):
        """
        Recursively masks sensitive data in the provided input data. If the data is a
        string and contains sensitive fields, it replaces them with asterisks ('*******').

        Args:
            data (str, dict, list, or bytes): The data to be masked. This argument will be modified.
            fields_to_mask (list): A list of keys or strings to be masked.

        Returns:
            The input data with sensitive fields replaced with asterisks.
        """

        # If the data is a string and is a valid JSON string, parse it into a
        # dictionary
        if isinstance(data, str):
            try:
                data = json.loads(data)
                logger.writeDebug("Parsed JSON string into dictionary")
            except json.JSONDecodeError:
                logger.writeDebug(
                    "Data is not a valid JSON string, proceeding with raw string")

        # If the data is a dictionary
        if isinstance(data, dict):
            for key in data:
                if key in fields_to_mask:
                    data[key] = '*******'  # Mask the sensitive key
                else:
                    data[key] = SecurityUtilities.mask_sensitive_data(
                        data[key], fields_to_mask)

        # If the data is a list
        elif isinstance(data, list):
            for i, value in enumerate(data):
                data[i] = SecurityUtilities.mask_sensitive_data(
                    value, fields_to_mask)

        # If the data is a byte string, decode and mask it
        elif isinstance(data, bytes):
            decoded_value = data.decode('utf-8', errors='ignore')
            data = SecurityUtilities.mask_sensitive_data(
                decoded_value, fields_to_mask)

        # If the data is a string, mask if it's in fields_to_mask
        elif isinstance(data, str):
            if data in fields_to_mask:
                return '*******'  # Mask the sensitive string

        return data


class ErrorUtilities:
    @staticmethod
    def format_MAPI_http_error(httperr: urllib.error.HTTPError):
        """
        Formats a http error from MAPI to camelCase.

        Parameters:
        httperr (str): The input string in http_error format.

        Returns:
        str: format the error string.
        """

        # Read the response body from the error (if available)
        if httperr.fp:
            error_bytes = httperr.fp.read()
            try:
                error_str = error_bytes.decode('utf-8')
                error_json = json.loads(error_str)
            except Exception as json_err:
                raise ErrorResponseParsingException(
                    error_bytes, json_err) from httperr
            formatted_error = f"{error_json.get('code', 'Unknown')}: {error_json.get('message', 'No message')} ({error_json.get('details', 'No details')})"
            raise RuntimeError(formatted_error) from httperr
        else:
            raise httperr


class ErrorResponseParsingException(Exception):
    """
    Exception raised when an HTTP error response cannot be parsed as valid JSON.

    Attributes:
        raw_data (bytes): The raw response body that failed to parse.
        original_exception (Exception): The original exception raised during JSON parsing.
    """

    def __init__(self, raw_data, original_exception):
        logger.writeDebug(f"Failed to parse error response: {raw_data}")
        super().__init__(f"{raw_data.decode('utf-8')}")
        self.raw_data = raw_data
        self.original_exception = original_exception


class CertUtilities:
    @staticmethod
    def get_subject_dn_from_pem(pem_file_path):
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
        except ImportError as e:
            logger.writeDebug("The \'cryptography\' library is not installed.")
            logger.writeDebug("Please install it using: pip install cryptography")
            return f"Error reading certificate: {e}"
        try:
            with open(pem_file_path, "rb") as pem_file:
                pem_data = pem_file.read()

            cert = x509.load_pem_x509_certificate(pem_data, default_backend())
            subject_dn = cert.subject.rfc4514_string()
            subject_dn = subject_dn.replace(",", ", ")
            return subject_dn

        except Exception as e:
            return f"Error reading certificate: {e}"
