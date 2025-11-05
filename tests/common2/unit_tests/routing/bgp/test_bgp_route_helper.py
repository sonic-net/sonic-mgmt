"""
Comprehensive unit tests for bgp_route_control.py module.
Tests the BGPRouteController class and convenience functions for ExaBGP HTTP API interactions.
"""

import os
import sys
from typing import Any, Dict
from unittest.mock import Mock, patch

import pytest
import requests

# Get the absolute path to the test file
test_file_dir = os.path.dirname(os.path.abspath(__file__))

# Calculate paths relative to the test file
repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(test_file_dir)))))
common2_root = os.path.dirname(os.path.dirname(os.path.dirname(test_file_dir)))

# Add paths to sys.path if not already there  # pylint: disable=wrong-spelling-in-comment
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)
if common2_root not in sys.path:
    sys.path.insert(0, common2_root)

# Also add current working directory for relative imports when running from tests/common2
cwd = os.getcwd()
if cwd.endswith("tests/common2") and cwd not in sys.path:
    sys.path.insert(0, cwd)

# Import the BGP module with fallback paths
_BGP_MODULE = None
try:
    # Try absolute import first (when running from repo root)
    from tests.common2.routing.bgp import bgp_route_control

    _BGP_MODULE = bgp_route_control
except ImportError:
    try:
        # Try relative import (when running from tests/common2)
        from routing.bgp import bgp_route_control  # type: ignore

        _BGP_MODULE = bgp_route_control
    except ImportError:
        # Last fallback - direct relative import
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        from routing.bgp import bgp_route_control  # type: ignore

        _BGP_MODULE = bgp_route_control

# Import specific functions from the module
BGPRouteController = _BGP_MODULE.BGPRouteController
announce_route = _BGP_MODULE.announce_route
announce_route_with_community = _BGP_MODULE.announce_route_with_community
install_route_from_exabgp = _BGP_MODULE.install_route_from_exabgp
update_routes = _BGP_MODULE.update_routes
withdraw_route = _BGP_MODULE.withdraw_route
withdraw_route_with_community = _BGP_MODULE.withdraw_route_with_community

# Determine the correct module path for mocking based on the successful import
BGP_MODULE_PATH = _BGP_MODULE.__name__


@pytest.mark.unit_test
class TestBGPRouteController:  # pylint: disable=too-many-public-methods
    """Test cases for BGPRouteController class."""

    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_announce_route_basic(self, mock_post: Mock) -> None:
        """Test basic route announcement."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        # Act
        BGPRouteController.announce_route(
            ptfip="192.168.1.1", neighbor="10.0.0.1", route="192.168.10.0/24", nexthop="10.0.0.2", port=5000
        )

        # Assert
        expected_command = "neighbor 10.0.0.1 announce route 192.168.10.0/24 next-hop 10.0.0.2"
        mock_post.assert_called_once_with("http://192.168.1.1:5000", data={"command": expected_command}, timeout=30)

    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_announce_route_with_community(self, mock_post: Mock) -> None:
        """Test route announcement with community."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        # Act
        BGPRouteController.announce_route(
            ptfip="192.168.1.1",
            neighbor="10.0.0.1",
            route="192.168.10.0/24",
            nexthop="10.0.0.2",
            port=5000,
            community="1010:1010",
        )

        # Assert
        expected_command = "neighbor 10.0.0.1 announce route 192.168.10.0/24 next-hop 10.0.0.2 community [1010:1010]"
        mock_post.assert_called_once_with("http://192.168.1.1:5000", data={"command": expected_command}, timeout=30)

    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_announce_route_with_local_preference(self, mock_post: Mock) -> None:
        """Test route announcement with local preference."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        # Act
        BGPRouteController.announce_route(
            ptfip="192.168.1.1",
            neighbor="10.0.0.1",
            route="192.168.10.0/24",
            nexthop="10.0.0.2",
            port=5000,
            local_preference=150,
        )

        # Assert
        expected_command = "neighbor 10.0.0.1 announce route 192.168.10.0/24 next-hop 10.0.0.2 local-preference 150"
        mock_post.assert_called_once_with("http://192.168.1.1:5000", data={"command": expected_command}, timeout=30)

    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_announce_route_with_all_attributes(self, mock_post: Mock) -> None:
        """Test route announcement with all optional attributes."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        # Act
        BGPRouteController.announce_route(
            ptfip="192.168.1.1",
            neighbor="10.0.0.1",
            route="192.168.10.0/24",
            nexthop="10.0.0.2",
            port=5000,
            community="1010:1010",
            local_preference=150,
        )

        # Assert
        expected_command = (
            "neighbor 10.0.0.1 announce route 192.168.10.0/24 "
            "next-hop 10.0.0.2 local-preference 150 community [1010:1010]"
        )
        mock_post.assert_called_once_with("http://192.168.1.1:5000", data={"command": expected_command}, timeout=30)

    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_withdraw_route_basic(self, mock_post: Mock) -> None:
        """Test basic route withdrawal."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        # Act
        BGPRouteController.withdraw_route(
            ptfip="192.168.1.1", neighbor="10.0.0.1", route="192.168.10.0/24", nexthop="10.0.0.2", port=5000
        )

        # Assert
        expected_command = "neighbor 10.0.0.1 withdraw route 192.168.10.0/24 next-hop 10.0.0.2"
        mock_post.assert_called_once_with("http://192.168.1.1:5000", data={"command": expected_command}, timeout=30)

    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_withdraw_route_with_attributes(self, mock_post: Mock) -> None:
        """Test route withdrawal with all attributes."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        # Act
        BGPRouteController.withdraw_route(
            ptfip="192.168.1.1",
            neighbor="10.0.0.1",
            route="192.168.10.0/24",
            nexthop="10.0.0.2",
            port=5000,
            community="1010:1010",
            local_preference=150,
        )

        # Assert
        expected_command = (
            "neighbor 10.0.0.1 withdraw route 192.168.10.0/24 next-hop 10.0.0.2 "
            "local-preference 150 community [1010:1010]"
        )
        mock_post.assert_called_once_with("http://192.168.1.1:5000", data={"command": expected_command}, timeout=30)

    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_http_error_handling_400(self, mock_post: Mock) -> None:
        """Test HTTP 400 error handling."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 400
        mock_post.return_value = mock_response

        # Act & Assert
        with pytest.raises(AssertionError, match="HTTP request failed with status 400"):
            BGPRouteController.announce_route(
                ptfip="192.168.1.1", neighbor="10.0.0.1", route="192.168.10.0/24", nexthop="10.0.0.2", port=5000
            )

    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_http_error_handling_500(self, mock_post: Mock) -> None:
        """Test HTTP 500 error handling."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 500
        mock_post.return_value = mock_response

        # Act & Assert
        with pytest.raises(AssertionError, match="HTTP request failed with status 500"):
            BGPRouteController.announce_route(
                ptfip="192.168.1.1", neighbor="10.0.0.1", route="192.168.10.0/24", nexthop="10.0.0.2", port=5000
            )

    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_connection_error_handling(self, mock_post: Mock) -> None:
        """Test connection error handling."""
        # Arrange
        mock_post.side_effect = requests.ConnectionError("Connection refused")

        # Act & Assert
        with pytest.raises(AssertionError, match="HTTP request to ExaBGP API failed: Connection refused"):
            BGPRouteController.announce_route(
                ptfip="192.168.1.1", neighbor="10.0.0.1", route="192.168.10.0/24", nexthop="10.0.0.2", port=5000
            )

    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_timeout_error_handling(self, mock_post: Mock) -> None:
        """Test timeout error handling."""
        # Arrange
        mock_post.side_effect = requests.Timeout("Request timed out")

        # Act & Assert
        with pytest.raises(AssertionError, match="HTTP request to ExaBGP API failed: Request timed out"):
            BGPRouteController.announce_route(
                ptfip="192.168.1.1", neighbor="10.0.0.1", route="192.168.10.0/24", nexthop="10.0.0.2", port=5000
            )

    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_announce_routes_bulk_with_self_nexthop(self, mock_post: Mock) -> None:
        """Test bulk route announcement with self nexthop."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        route_list = ["192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24"]

        # Act
        BGPRouteController.announce_routes_bulk(ptfip="192.168.1.1", route_list=route_list, port=5000, nexthop="self")

        # Assert
        expected_command = "announce attributes next-hop self nlri 192.168.1.0/24 192.168.2.0/24 192.168.3.0/24"
        mock_post.assert_called_once_with("http://192.168.1.1:5000", data={"command": expected_command}, timeout=90)

    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_announce_routes_bulk_with_custom_nexthop(self, mock_post: Mock) -> None:
        """Test bulk route announcement with custom nexthop."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        route_list = ["192.168.1.0/24", "192.168.2.0/24"]

        # Act
        BGPRouteController.announce_routes_bulk(
            ptfip="192.168.1.1", route_list=route_list, port=5000, nexthop="10.0.0.2"
        )

        # Assert
        expected_command = "announce attributes next-hop 10.0.0.2 nlri 192.168.1.0/24 192.168.2.0/24"
        mock_post.assert_called_once_with("http://192.168.1.1:5000", data={"command": expected_command}, timeout=90)

    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_withdraw_routes_bulk(self, mock_post: Mock) -> None:
        """Test bulk route withdrawal."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        route_list = ["192.168.1.0/24", "192.168.2.0/24"]

        # Act
        BGPRouteController.withdraw_routes_bulk(ptfip="192.168.1.1", route_list=route_list, port=5000)

        # Assert
        expected_command = "withdraw attributes next-hop self nlri 192.168.1.0/24 192.168.2.0/24"
        mock_post.assert_called_once_with("http://192.168.1.1:5000", data={"command": expected_command}, timeout=90)

    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_bulk_operation_single_route(self, mock_post: Mock) -> None:
        """Test bulk operation with single route."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        route_list = ["192.168.1.0/24"]

        # Act
        BGPRouteController.announce_routes_bulk(ptfip="192.168.1.1", route_list=route_list, port=5000)

        # Assert
        expected_command = "announce attributes next-hop self nlri 192.168.1.0/24"
        mock_post.assert_called_once_with("http://192.168.1.1:5000", data={"command": expected_command}, timeout=90)

    @patch(f"{BGP_MODULE_PATH}.logger")
    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_bulk_operation_empty_route_list(self, mock_post: Mock, mock_logger: Mock) -> None:
        """Test bulk operation with empty route list."""
        # Act
        BGPRouteController.announce_routes_bulk(ptfip="192.168.1.1", route_list=[], port=5000)

        # Assert
        mock_logger.warning.assert_called_once_with("No routes provided for %s operation", "announce")
        mock_post.assert_not_called()

    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_bulk_operation_http_error(self, mock_post: Mock) -> None:
        """Test bulk operation HTTP error handling."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 404
        mock_post.return_value = mock_response
        route_list = ["192.168.1.0/24"]

        # Act & Assert
        with pytest.raises(AssertionError, match="HTTP request failed with status 404"):
            BGPRouteController.announce_routes_bulk(ptfip="192.168.1.1", route_list=route_list, port=5000)

    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_update_route_with_attributes_announce(self, mock_post: Mock) -> None:
        """Test route update with attributes for announcement."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        route_dict = {
            "prefix": "192.168.10.0/24",
            "nexthop": "10.0.0.2",
            "community": "1010:1010",
            "local_preference": 150,
        }

        # Act
        BGPRouteController.update_route_with_attributes(
            action="announce", ptfip="192.168.1.1", port=5000, route_dict=route_dict
        )

        # Assert
        expected_msg = "announce route 192.168.10.0/24 next-hop 10.0.0.2 community 1010:1010 local-preference 150"
        mock_post.assert_called_once_with("http://192.168.1.1:5000", data={"commands": expected_msg}, timeout=30)

    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_update_route_with_attributes_withdraw(self, mock_post: Mock) -> None:
        """Test route update with attributes for withdrawal."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        route_dict = {"prefix": "192.168.10.0/24", "nexthop": "10.0.0.2"}

        # Act
        BGPRouteController.update_route_with_attributes(
            action="withdraw", ptfip="192.168.1.1", port=5000, route_dict=route_dict
        )

        # Assert
        expected_msg = "withdraw route 192.168.10.0/24 next-hop 10.0.0.2"
        mock_post.assert_called_once_with("http://192.168.1.1:5000", data={"commands": expected_msg}, timeout=30)

    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_update_route_with_community_only(self, mock_post: Mock) -> None:
        """Test route update with community only."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        route_dict = {"prefix": "192.168.10.0/24", "nexthop": "10.0.0.2", "community": "2020:2020"}

        # Act
        BGPRouteController.update_route_with_attributes(
            action="announce", ptfip="192.168.1.1", port=5000, route_dict=route_dict
        )

        # Assert
        expected_msg = "announce route 192.168.10.0/24 next-hop 10.0.0.2 community 2020:2020"
        mock_post.assert_called_once_with("http://192.168.1.1:5000", data={"commands": expected_msg}, timeout=30)

    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_update_route_with_local_preference_only(self, mock_post: Mock) -> None:
        """Test route update with local preference only."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        route_dict = {"prefix": "192.168.10.0/24", "nexthop": "10.0.0.2", "local_preference": 200}

        # Act
        BGPRouteController.update_route_with_attributes(
            action="announce", ptfip="192.168.1.1", port=5000, route_dict=route_dict
        )

        # Assert
        expected_msg = "announce route 192.168.10.0/24 next-hop 10.0.0.2 local-preference 200"
        mock_post.assert_called_once_with("http://192.168.1.1:5000", data={"commands": expected_msg}, timeout=30)

    def test_update_route_invalid_action(self) -> None:
        """Test update route with invalid action."""
        # Arrange
        route_dict = {"prefix": "192.168.10.0/24", "nexthop": "10.0.0.2"}

        # Act & Assert
        with pytest.raises(ValueError, match="Unsupported route update operation: invalid"):
            BGPRouteController.update_route_with_attributes(
                action="invalid", ptfip="192.168.1.1", port=5000, route_dict=route_dict
            )

    def test_update_route_missing_prefix(self) -> None:
        """Test update route with missing prefix."""
        # Arrange
        route_dict = {"nexthop": "10.0.0.2"}

        # Act & Assert
        with pytest.raises(ValueError, match="route_dict must contain 'prefix' and 'nexthop' keys"):
            BGPRouteController.update_route_with_attributes(
                action="announce", ptfip="192.168.1.1", port=5000, route_dict=route_dict
            )

    def test_update_route_missing_nexthop(self) -> None:
        """Test update route with missing nexthop."""
        # Arrange
        route_dict = {"prefix": "192.168.10.0/24"}

        # Act & Assert
        with pytest.raises(ValueError, match="route_dict must contain 'prefix' and 'nexthop' keys"):
            BGPRouteController.update_route_with_attributes(
                action="announce", ptfip="192.168.1.1", port=5000, route_dict=route_dict
            )

    def test_update_route_empty_route_dict(self) -> None:
        """Test update route with empty route dictionary."""
        # Arrange
        route_dict: Dict[str, Any] = {}

        # Act & Assert
        with pytest.raises(ValueError, match="route_dict must contain 'prefix' and 'nexthop' keys"):
            BGPRouteController.update_route_with_attributes(
                action="announce", ptfip="192.168.1.1", port=5000, route_dict=route_dict
            )


@pytest.mark.unit_test
class TestConvenienceFunctions:
    """Test cases for convenience functions."""

    @patch(f"{BGP_MODULE_PATH}.BGPRouteController.announce_route")
    def test_announce_route_convenience_basic(self, mock_announce: Mock) -> None:
        """Test announce_route convenience function without community."""
        # Act
        announce_route("192.168.1.1", "10.0.0.1", "192.168.10.0/24", "10.0.0.2", 5000)

        # Assert
        mock_announce.assert_called_once_with("192.168.1.1", "10.0.0.1", "192.168.10.0/24", "10.0.0.2", 5000, None)

    @patch(f"{BGP_MODULE_PATH}.BGPRouteController.announce_route")
    def test_announce_route_convenience_with_community(self, mock_announce: Mock) -> None:
        """Test announce_route convenience function with community."""
        # Act
        announce_route("192.168.1.1", "10.0.0.1", "192.168.10.0/24", "10.0.0.2", 5000, "1010:1010")

        # Assert
        mock_announce.assert_called_once_with(
            "192.168.1.1", "10.0.0.1", "192.168.10.0/24", "10.0.0.2", 5000, "1010:1010"
        )

    @patch(f"{BGP_MODULE_PATH}.BGPRouteController.withdraw_route")
    def test_withdraw_route_convenience_basic(self, mock_withdraw: Mock) -> None:
        """Test withdraw_route convenience function without community."""
        # Act
        withdraw_route("192.168.1.1", "10.0.0.1", "192.168.10.0/24", "10.0.0.2", 5000)

        # Assert
        mock_withdraw.assert_called_once_with("192.168.1.1", "10.0.0.1", "192.168.10.0/24", "10.0.0.2", 5000, None)

    @patch(f"{BGP_MODULE_PATH}.BGPRouteController.withdraw_route")
    def test_withdraw_route_convenience_with_community(self, mock_withdraw: Mock) -> None:
        """Test withdraw_route convenience function with community."""
        # Act
        withdraw_route("192.168.1.1", "10.0.0.1", "192.168.10.0/24", "10.0.0.2", 5000, "1010:1010")

        # Assert
        mock_withdraw.assert_called_once_with(
            "192.168.1.1", "10.0.0.1", "192.168.10.0/24", "10.0.0.2", 5000, "1010:1010"
        )

    @patch(f"{BGP_MODULE_PATH}.BGPRouteController.announce_route")
    def test_announce_route_with_community_convenience(self, mock_announce: Mock) -> None:
        """Test announce_route_with_community convenience function."""
        # Act
        announce_route_with_community("192.168.1.1", "10.0.0.1", "192.168.10.0/24", "10.0.0.2", 5000, "1010:1010")

        # Assert
        mock_announce.assert_called_once_with(
            "192.168.1.1", "10.0.0.1", "192.168.10.0/24", "10.0.0.2", 5000, "1010:1010", 10000
        )

    @patch(f"{BGP_MODULE_PATH}.BGPRouteController.withdraw_route")
    def test_withdraw_route_with_community_convenience(self, mock_withdraw: Mock) -> None:
        """Test withdraw_route_with_community convenience function."""
        # Act
        withdraw_route_with_community("192.168.1.1", "10.0.0.1", "192.168.10.0/24", "10.0.0.2", 5000, "1010:1010")

        # Assert
        mock_withdraw.assert_called_once_with(
            "192.168.1.1", "10.0.0.1", "192.168.10.0/24", "10.0.0.2", 5000, "1010:1010", 10000
        )

    @patch(f"{BGP_MODULE_PATH}.BGPRouteController.announce_routes_bulk")
    def test_install_route_from_exabgp_announce(self, mock_announce_bulk: Mock) -> None:
        """Test install_route_from_exabgp with announce operation."""
        # Arrange
        route_list = ["192.168.1.0/24", "192.168.2.0/24"]

        # Act
        install_route_from_exabgp("announce", "192.168.1.1", route_list, 5000)

        # Assert
        mock_announce_bulk.assert_called_once_with("192.168.1.1", route_list, 5000)

    @patch(f"{BGP_MODULE_PATH}.BGPRouteController.withdraw_routes_bulk")
    def test_install_route_from_exabgp_withdraw(self, mock_withdraw_bulk: Mock) -> None:
        """Test install_route_from_exabgp with withdraw operation."""
        # Arrange
        route_list = ["192.168.1.0/24", "192.168.2.0/24"]

        # Act
        install_route_from_exabgp("withdraw", "192.168.1.1", route_list, 5000)

        # Assert
        mock_withdraw_bulk.assert_called_once_with("192.168.1.1", route_list, 5000)

    def test_install_route_from_exabgp_invalid_operation(self) -> None:
        """Test install_route_from_exabgp with invalid operation."""
        # Arrange
        route_list = ["192.168.1.0/24"]

        # Act & Assert
        with pytest.raises(ValueError, match="Unsupported operation: invalid"):
            install_route_from_exabgp("invalid", "192.168.1.1", route_list, 5000)

    def test_install_route_from_exabgp_empty_route_list(self) -> None:
        """Test install_route_from_exabgp with empty route list."""
        # This should still work as the bulk function handles empty lists
        with patch(f"{BGP_MODULE_PATH}.BGPRouteController.announce_routes_bulk") as mock_announce_bulk:
            install_route_from_exabgp("announce", "192.168.1.1", [], 5000)
            mock_announce_bulk.assert_called_once_with("192.168.1.1", [], 5000)

    @patch(f"{BGP_MODULE_PATH}.BGPRouteController.update_route_with_attributes")
    def test_update_routes_convenience_announce(self, mock_update: Mock) -> None:
        """Test update_routes convenience function for announce."""
        # Arrange
        route_dict = {"prefix": "192.168.10.0/24", "nexthop": "10.0.0.2", "community": "1010:1010"}

        # Act
        update_routes("announce", "192.168.1.1", 5000, route_dict)

        # Assert
        mock_update.assert_called_once_with("announce", "192.168.1.1", 5000, route_dict)

    @patch(f"{BGP_MODULE_PATH}.BGPRouteController.update_route_with_attributes")
    def test_update_routes_convenience_withdraw(self, mock_update: Mock) -> None:
        """Test update_routes convenience function for withdraw."""
        # Arrange
        route_dict = {"prefix": "192.168.10.0/24", "nexthop": "10.0.0.2"}

        # Act
        update_routes("withdraw", "192.168.1.1", 5000, route_dict)

        # Assert
        mock_update.assert_called_once_with("withdraw", "192.168.1.1", 5000, route_dict)


@pytest.mark.unit_test
class TestLogging:
    """Test cases for logging functionality."""

    @patch(f"{BGP_MODULE_PATH}.logger")
    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_logging_on_successful_single_route_request(self, mock_post: Mock, mock_logger: Mock) -> None:
        """Test that successful single route requests are logged."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        # Act
        BGPRouteController.announce_route(
            ptfip="192.168.1.1", neighbor="10.0.0.1", route="192.168.10.0/24", nexthop="10.0.0.2", port=5000
        )

        # Assert
        expected_command = "neighbor 10.0.0.1 announce route 192.168.10.0/24 next-hop 10.0.0.2"
        mock_logger.info.assert_called_with(
            "BGP %s: URL=%s, Command=%s", "announce", "http://192.168.1.1:5000", expected_command
        )

    @patch(f"{BGP_MODULE_PATH}.logger")
    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_logging_on_bulk_operation(self, mock_post: Mock, mock_logger: Mock) -> None:
        """Test that bulk operations are logged."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        route_list = ["192.168.1.0/24", "192.168.2.0/24"]

        # Act
        BGPRouteController.announce_routes_bulk(ptfip="192.168.1.1", route_list=route_list, port=5000)

        # Assert
        mock_logger.info.assert_called_with(
            "BGP bulk %s: URL=%s, Routes count=%d", "announce", "http://192.168.1.1:5000", 2
        )

        expected_command = "announce attributes next-hop self nlri 192.168.1.0/24 192.168.2.0/24"
        mock_logger.debug.assert_called_with("BGP bulk command: %s", expected_command)

    @patch(f"{BGP_MODULE_PATH}.logger")
    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_logging_on_update_route_operation(self, mock_post: Mock, mock_logger: Mock) -> None:
        """Test that update route operations are logged."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        route_dict = {"prefix": "192.168.10.0/24", "nexthop": "10.0.0.2", "community": "1010:1010"}

        # Act
        BGPRouteController.update_route_with_attributes(
            action="announce", ptfip="192.168.1.1", port=5000, route_dict=route_dict
        )

        # Assert
        expected_data = {"commands": "announce route 192.168.10.0/24 next-hop 10.0.0.2 community 1010:1010"}
        mock_logger.info.assert_called_with(
            "BGP update route: URL=%s, Data=%s", "http://192.168.1.1:5000", expected_data
        )


@pytest.mark.unit_test
class TestEdgeCases:
    """Test cases for edge cases and boundary conditions."""

    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_ipv6_route_announcement(self, mock_post: Mock) -> None:
        """Test route announcement with IPv6 addresses."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        # Act
        BGPRouteController.announce_route(
            ptfip="2001:db8::1", neighbor="2001:db8::2", route="2001:db8:1::/64", nexthop="2001:db8::3", port=5000
        )

        # Assert
        expected_command = "neighbor 2001:db8::2 announce route 2001:db8:1::/64 next-hop 2001:db8::3"
        mock_post.assert_called_once_with("http://2001:db8::1:5000", data={"command": expected_command}, timeout=30)

    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_large_route_list_bulk_operation(self, mock_post: Mock) -> None:
        """Test bulk operation with large route list."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        # Create a large list of routes
        route_list = [f"192.168.{i}.0/24" for i in range(1, 101)]

        # Act
        BGPRouteController.announce_routes_bulk(ptfip="192.168.1.1", route_list=route_list, port=5000)

        # Assert
        expected_nlri = " ".join(route_list)
        expected_command = f"announce attributes next-hop self nlri {expected_nlri}"
        mock_post.assert_called_once_with("http://192.168.1.1:5000", data={"command": expected_command}, timeout=90)

    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_special_characters_in_community(self, mock_post: Mock) -> None:
        """Test route announcement with special characters in community."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        # Act
        BGPRouteController.announce_route(
            ptfip="192.168.1.1",
            neighbor="10.0.0.1",
            route="192.168.10.0/24",
            nexthop="10.0.0.2",
            port=5000,
            community="65000:123",
        )

        # Assert
        expected_command = "neighbor 10.0.0.1 announce route 192.168.10.0/24 next-hop 10.0.0.2 community [65000:123]"
        mock_post.assert_called_once_with("http://192.168.1.1:5000", data={"command": expected_command}, timeout=30)

    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_zero_local_preference(self, mock_post: Mock) -> None:
        """Test route announcement with zero local preference."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        # Act
        BGPRouteController.announce_route(
            ptfip="192.168.1.1",
            neighbor="10.0.0.1",
            route="192.168.10.0/24",
            nexthop="10.0.0.2",
            port=5000,
            local_preference=0,
        )

        # Assert
        expected_command = "neighbor 10.0.0.1 announce route 192.168.10.0/24 next-hop 10.0.0.2 local-preference 0"
        mock_post.assert_called_once_with("http://192.168.1.1:5000", data={"command": expected_command}, timeout=30)

    @patch(f"{BGP_MODULE_PATH}.requests.post")
    def test_high_port_number(self, mock_post: Mock) -> None:
        """Test with high port number."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        # Act
        BGPRouteController.announce_route(
            ptfip="192.168.1.1", neighbor="10.0.0.1", route="192.168.10.0/24", nexthop="10.0.0.2", port=65535
        )

        # Assert
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert "http://192.168.1.1:65535" in call_args[0]
