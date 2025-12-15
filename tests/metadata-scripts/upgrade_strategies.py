"""
Upgrade strategies for SONiC upgrade testing.

This module provides different strategies for performing SONiC upgrade operations,
supporting both traditional script-based approaches and modern gNOI-based methods.
"""
import logging
from abc import ABC, abstractmethod
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class UpgradeStrategy(ABC):
    """Abstract base class for upgrade strategies."""

    @abstractmethod
    def preload_firmware(self, duthost, localhost, image_url: str, image_name: str, md5sum: str) -> None:
        """
        Download and prepare firmware for installation.

        Args:
            duthost: The DUT host object
            localhost: The localhost object
            image_url: URL of the firmware image to download
            image_name: Name of the firmware file (no path)
            md5sum: Expected MD5 checksum of the firmware

        Raises:
            Exception: If preload fails
        """
        pass

    def get_strategy_name(self) -> str:
        """Return human-readable name of this strategy."""
        return self.__class__.__name__


class ScriptUpgradeStrategy(UpgradeStrategy):
    """
    Traditional script-based upgrade strategy.

    This strategy uses the preload_firmware script from sonic-metadata
    repository, maintaining backward compatibility with existing workflows.
    """

    def preload_firmware(self, duthost, localhost, image_url: str, image_name: str, md5sum: str) -> None:
        """Download firmware using traditional preload_firmware script."""
        logger.info(f"Using script-based upgrade strategy for {image_name}")

        # Ensure the preload_firmware script is executable
        duthost.command("chmod +x /tmp/anpscripts/preload_firmware")

        # Execute preload_firmware script with required parameters
        logger.info(f"Executing preload_firmware {image_name} {image_url} {md5sum}")
        result = duthost.command(
            f"/usr/bin/sudo /tmp/anpscripts/preload_firmware {image_name} {image_url} {md5sum}"
        )

        if result['rc'] != 0:
            raise Exception(f"preload_firmware script failed: {result['stderr']}")

        logger.info("Script-based upgrade strategy completed successfully")


class GnoiUpgradeStrategy(UpgradeStrategy):
    """
    gNOI-based upgrade strategy.

    This strategy uses gNOI File.TransferToRemote RPC to download firmware
    directly to the DUT, providing a modern alternative to script-based approaches.
    """

    def __init__(self, ptf_gnoi):
        """
        Initialize gNOI upgrade strategy.

        Args:
            ptf_gnoi: PtfGnoi instance for making gNOI calls
        """
        self.ptf_gnoi = ptf_gnoi

    def preload_firmware(self, duthost, localhost, image_url: str, image_name: str, md5sum: str) -> None:
        """Download firmware using gNOI TransferToRemote."""
        logger.info(f"Using gNOI-based upgrade strategy for {image_name}")

        # Determine protocol from URL
        parsed_url = urlparse(image_url)
        protocol_map = {
            'http': 'HTTP',
            'https': 'HTTPS',
            'sftp': 'SFTP',
            'scp': 'SCP'
        }

        protocol = protocol_map.get(parsed_url.scheme, 'HTTP')
        logger.info(f"Detected protocol: {protocol} from URL scheme: {parsed_url.scheme}")

        # Prepare local path for downloaded file
        local_path = f"/tmp/{image_name}"

        try:
            # Use gNOI to transfer the file
            logger.info(f"Starting gNOI TransferToRemote: {image_url} -> {local_path}")
            result = self.ptf_gnoi.file_transfer_to_remote(
                local_path=local_path,
                remote_url=image_url,
                protocol=protocol
            )

            logger.info(f"gNOI TransferToRemote completed. Response: {result}")

            # Verify the file was downloaded
            file_stat = duthost.stat(path=local_path)
            if not file_stat['stat']['exists']:
                raise Exception(f"File {local_path} not found after gNOI transfer")

            # Verify MD5 checksum
            logger.info("Verifying MD5 checksum of downloaded file")
            md5_result = duthost.command(f"md5sum {local_path}")
            if md5_result['rc'] != 0:
                raise Exception(f"Failed to calculate MD5: {md5_result['stderr']}")

            actual_md5 = md5_result['stdout'].split()[0]
            if actual_md5.lower() != md5sum.lower():
                raise Exception(
                    f"MD5 checksum mismatch. Expected: {md5sum}, Actual: {actual_md5}"
                )

            logger.info(f"MD5 checksum verified: {actual_md5}")

            # gNOI doesn't handle postupgrade binaries like the script does,
            # but this is handled separately in the upgrade process
            logger.info("gNOI-based upgrade strategy completed successfully")

        except Exception as e:
            logger.error(f"gNOI upgrade strategy failed: {e}")
            raise


def create_upgrade_strategy(strategy_type: str, ptf_gnoi=None) -> UpgradeStrategy:
    """
    Factory function to create upgrade strategies.

    Args:
        strategy_type: Type of strategy ('script' or 'gnoi')
        ptf_gnoi: PtfGnoi instance (required for gNOI strategy)

    Returns:
        UpgradeStrategy instance

    Raises:
        ValueError: If strategy_type is unknown
    """
    strategy_map = {
        'script': lambda: ScriptUpgradeStrategy(),
        'gnoi': lambda: GnoiUpgradeStrategy(ptf_gnoi)
    }

    if strategy_type not in strategy_map:
        raise ValueError(
            f"Unknown upgrade strategy: {strategy_type}. "
            f"Valid options are: {list(strategy_map.keys())}"
        )

    if strategy_type == 'gnoi' and ptf_gnoi is None:
        raise ValueError("gnoi strategy requires ptf_gnoi instance")

    return strategy_map[strategy_type]()
