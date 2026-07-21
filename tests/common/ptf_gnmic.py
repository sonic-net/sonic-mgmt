"""
PTF-based gnmic client wrapper providing gNMI operations via the gnmic CLI.

This module provides a wrapper that invokes the gnmic binary on the PTF container
via ptfhost.shell(), hiding the CLI complexity behind clean, Pythonic interfaces.
"""
import json
import logging
from typing import Dict

logger = logging.getLogger(__name__)

# Connection-related keywords that indicate a connection failure rather than
# a generic gnmic command error.
_CONNECTION_KEYWORDS = (
    "connection refused",
    "no such host",
    "tls: ",
    "certificate",
    "handshake",
)


class PtfGnmicError(Exception):
    """Base exception for PtfGnmic operations."""
    pass


class GnmicConnectionError(PtfGnmicError):
    """Connection-related gnmic errors (target unreachable, TLS handshake failures)."""
    pass


class GnmicCallError(PtfGnmicError):
    """gnmic command execution errors (non-zero exit, malformed output)."""
    pass


class PtfGnmic:
    """
    PTF-based gnmic client wrapper.

    This class executes gnmic commands in the PTF container to interact with
    gNMI services on the DUT, providing process separation and a clean Python
    interface over the gnmic CLI.

    Usage follows the two-step initialization pattern established by PtfGrpc:
      1. Construct with target and mode: ``PtfGnmic(ptfhost, target)``
      2. Configure TLS certs: ``client.configure_tls_certificates(ca, cert, key)``
      3. Call methods: ``result = client.capabilities()``
    """

    def __init__(self, ptfhost, target, plaintext=False):
        """
        Initialize PtfGnmic client.

        Args:
            ptfhost: PTF host instance for command execution
            target: Target string in host:port format (e.g. "10.0.0.1:50052")
            plaintext: If True, use --insecure flag instead of TLS certificates
        """
        self.ptfhost = ptfhost
        self.target = str(target)
        self.plaintext = plaintext
        self.ca_cert = None
        self.client_cert = None
        self.client_key = None
        self._gnmic_path = "/usr/local/bin/gnmic"
        logger.info(f"Initialized PtfGnmic: target={self.target}, plaintext={self.plaintext}")

    def configure_tls_certificates(self, ca_cert: str, client_cert: str, client_key: str) -> None:
        """
        Configure TLS certificates for mutual authentication.

        Args:
            ca_cert: Path to CA certificate file on the PTF container
            client_cert: Path to client certificate file on the PTF container
            client_key: Path to client private key file on the PTF container
        """
        self.ca_cert = ca_cert
        self.client_cert = client_cert
        self.client_key = client_key
        self.plaintext = False
        logger.info(f"Configured TLS certificates: ca={ca_cert}, cert={client_cert}, key={client_key}")

    def capabilities(self) -> Dict:
        """
        Query gNMI capabilities from the target device.

        Executes ``gnmic capabilities --format json`` on the PTF container and
        returns the parsed JSON output.

        Returns:
            Dictionary containing gNMI capabilities:
            - supported-encodings: List of supported encoding strings
            - supported-models: List of model dicts (name, organization, version)
            - gnmi-version: gNMI protocol version string

        Raises:
            GnmicConnectionError: If connection to target fails (refused, TLS errors)
            GnmicCallError: If gnmic exits with non-zero code or returns invalid JSON
        """
        cmd = f"{self._gnmic_path} -a {self.target}"

        if self.plaintext:
            cmd += " --insecure"
        elif self.ca_cert and self.client_cert and self.client_key:
            cmd += f" --tls-ca {self.ca_cert} --tls-cert {self.client_cert} --tls-key {self.client_key}"

        cmd += " capabilities --format json"

        logger.debug(f"Executing gnmic command: {cmd}")
        result = self.ptfhost.shell(cmd, module_ignore_errors=True)

        rc = result["rc"]
        stdout = result.get("stdout", "").strip()
        stderr = result.get("stderr", "").strip()

        if rc != 0:
            # Check for connection-related error keywords
            stderr_lower = stderr.lower()
            if any(kw in stderr_lower for kw in _CONNECTION_KEYWORDS):
                raise GnmicConnectionError(
                    f"gnmic connection failed to {self.target}: {stderr}"
                )
            raise GnmicCallError(
                f"gnmic capabilities failed (rc={rc}): {stderr}"
            )

        # Parse JSON output
        try:
            return json.loads(stdout)
        except (json.JSONDecodeError, ValueError) as e:
            raise GnmicCallError(
                f"gnmic returned invalid JSON: {e}\nOutput: {stdout}"
            )

    def __str__(self):
        return f"PtfGnmic(target={self.target}, plaintext={self.plaintext})"

    def __repr__(self):
        return self.__str__()
