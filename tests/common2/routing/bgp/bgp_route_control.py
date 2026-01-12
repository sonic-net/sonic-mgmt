"""
Common BGP route announcement and withdrawal functions for ExaBGP.
This module provides a unified interface for controlling BGP routes across different test scenarios.
"""

import logging
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


class BGPRouteController:
    """
    A unified controller for BGP route announcements and withdrawals via ExaBGP HTTP API.
    """

    @staticmethod
    def announce_route(
        ptfip: str,
        neighbor: str,
        route: str,
        nexthop: str,
        port: int,
        community: Optional[str] = None,
        local_preference: Optional[int] = None,
    ) -> None:
        """
        Announce a single BGP route to a specific neighbor.

        Args:
            ptfip: PTF host IP address
            neighbor: BGP neighbor IP address
            route: Route prefix to announce (e.g., "10.1.1.0/24")
            nexthop: Next-hop IP address
            port: ExaBGP HTTP API port
            community: Optional BGP community string (e.g., "1010:1010")
            local_preference: Optional local preference value
        """
        BGPRouteController._change_route("announce", ptfip, neighbor, route, nexthop, port, community, local_preference)

    @staticmethod
    def withdraw_route(
        ptfip: str,
        neighbor: str,
        route: str,
        nexthop: str,
        port: int,
        community: Optional[str] = None,
        local_preference: Optional[int] = None,
    ) -> None:
        """
        Withdraw a single BGP route from a specific neighbor.

        Args:
            ptfip: PTF host IP address
            neighbor: BGP neighbor IP address
            route: Route prefix to withdraw (e.g., "10.1.1.0/24")
            nexthop: Next-hop IP address
            port: ExaBGP HTTP API port
            community: Optional BGP community string (e.g., "1010:1010")
            local_preference: Optional local preference value
        """
        BGPRouteController._change_route("withdraw", ptfip, neighbor, route, nexthop, port, community, local_preference)

    @staticmethod
    def _change_route(
        operation: str,
        ptfip: str,
        neighbor: str,
        route: str,
        nexthop: str,
        port: int,
        community: Optional[str] = None,
        local_preference: Optional[int] = None,
    ) -> None:
        """
        Internal method to handle route changes via ExaBGP HTTP API.
        """
        url = f"http://{ptfip}:{port}"

        # Build the command based on available parameters
        command = f"neighbor {neighbor} {operation} route {route} next-hop {nexthop}"

        if local_preference is not None:
            command += f" local-preference {local_preference}"

        if community is not None:
            command += f" community [{community}]"

        data = {"command": command}

        logger.info("BGP %s: URL=%s, Command=%s", operation, url, command)

        try:
            response = requests.post(url, data=data, timeout=30)
            if response.status_code != 200:
                raise AssertionError(f"HTTP request failed with status {response.status_code}")
        except requests.RequestException as e:
            raise AssertionError(f"HTTP request to ExaBGP API failed: {e}") from e

    @staticmethod
    def announce_routes_bulk(ptfip: str, route_list: List[str], port: int, nexthop: str = "self") -> None:
        """
        Announce multiple routes in bulk using ExaBGP's bulk format.

        Args:
            ptfip: PTF host IP address
            route_list: List of route prefixes to announce
            port: ExaBGP HTTP API port
            nexthop: Next-hop address ("self" for next-hop self)
        """
        BGPRouteController._install_routes_bulk("announce", ptfip, route_list, port, nexthop)

    @staticmethod
    def withdraw_routes_bulk(ptfip: str, route_list: List[str], port: int, nexthop: str = "self") -> None:
        """
        Withdraw multiple routes in bulk using ExaBGP's bulk format.

        Args:
            ptfip: PTF host IP address
            route_list: List of route prefixes to withdraw
            port: ExaBGP HTTP API port
            nexthop: Next-hop address ("self" for next-hop self)
        """
        BGPRouteController._install_routes_bulk("withdraw", ptfip, route_list, port, nexthop)

    @staticmethod
    def _install_routes_bulk(
        operation: str, ptfip: str, route_list: List[str], port: int, nexthop: str = "self"
    ) -> None:
        """
        Internal method to handle bulk route operations.
        """
        if not route_list:
            logger.warning("No routes provided for %s operation", operation)
            return

        url = f"http://{ptfip}:{port}"

        # Build bulk command for ExaBGP
        if nexthop == "self":
            command = f"{operation} attributes next-hop self nlri {' '.join(route_list)}"
        else:
            command = f"{operation} attributes next-hop {nexthop} nlri {' '.join(route_list)}"

        data = {"command": command}

        logger.info("BGP bulk %s: URL=%s, Routes count=%d", operation, url, len(route_list))
        logger.debug("BGP bulk command: %s", command)

        try:
            response = requests.post(url, data=data, timeout=90)
            if response.status_code != 200:
                raise AssertionError(
                    f"HTTP request failed with status {response.status_code}. URL: {url}. Data: {data}"
                )
        except requests.RequestException as e:
            raise AssertionError(f"HTTP request to ExaBGP API failed: {e}") from e

    @staticmethod
    def update_route_with_attributes(action: str, ptfip: str, port: int, route_dict: Dict[str, Any]) -> None:
        """
        Update a route with custom attributes using the bgp_helpers format.

        Args:
            action: "announce" or "withdraw"
            ptfip: PTF host IP address
            port: ExaBGP HTTP API port
            route_dict: Dictionary with route attributes like:
                       {"prefix": "10.1.1.0/24", "nexthop": "10.1.1.1", "community": "1010:1010"}
        """
        if action not in ["announce", "withdraw"]:
            raise ValueError(f"Unsupported route update operation: {action}")

        if "prefix" not in route_dict or "nexthop" not in route_dict:
            raise ValueError("route_dict must contain 'prefix' and 'nexthop' keys")

        # Build message in bgp_helpers format
        msg = f'{action} route {route_dict["prefix"]} next-hop {route_dict["nexthop"]}'

        if "community" in route_dict:
            msg += f' community {route_dict["community"]}'

        if "local_preference" in route_dict:
            msg += f' local-preference {route_dict["local_preference"]}'

        url = f"http://{ptfip}:{port}"
        data = {"commands": msg}

        logger.info("BGP update route: URL=%s, Data=%s", url, data)

        try:
            response = requests.post(url, data=data, timeout=30)
            if response.status_code != 200:
                raise AssertionError(f"HTTP request failed with status {response.status_code}")
        except requests.RequestException as e:
            raise AssertionError(f"HTTP request to ExaBGP API failed: {e}") from e


# Convenience functions for backward compatibility
def announce_route(
    ptfip: str, neighbor: str, route: str, nexthop: str, port: int, community: Optional[str] = None
) -> None:
    """
    Convenience function for announcing a single route (test_bgp_speaker format).
    """
    BGPRouteController.announce_route(ptfip, neighbor, route, nexthop, port, community)


def withdraw_route(
    ptfip: str, neighbor: str, route: str, nexthop: str, port: int, community: Optional[str] = None
) -> None:
    """
    Convenience function for withdrawing a single route (test_bgp_speaker format).
    """
    BGPRouteController.withdraw_route(ptfip, neighbor, route, nexthop, port, community)


def announce_route_with_community(
    ptfip: str, neighbor: str, route: str, nexthop: str, port: int, community: str
) -> None:
    """
    Convenience function for announcing a route with community (test_bgp_sentinel format).
    """
    BGPRouteController.announce_route(ptfip, neighbor, route, nexthop, port, community, 10000)


def withdraw_route_with_community(
    ptfip: str, neighbor: str, route: str, nexthop: str, port: int, community: str
) -> None:
    """
    Convenience function for withdrawing a route with community (test_bgp_sentinel format).
    """
    BGPRouteController.withdraw_route(ptfip, neighbor, route, nexthop, port, community, 10000)


def install_route_from_exabgp(operation: str, ptfip: str, route_list: List[str], port: int) -> None:
    """
    Convenience function for bulk route operations (test_bgp_suppress_fib format).
    """
    if operation == "announce":
        BGPRouteController.announce_routes_bulk(ptfip, route_list, port)
    elif operation == "withdraw":
        BGPRouteController.withdraw_routes_bulk(ptfip, route_list, port)
    else:
        raise ValueError(f"Unsupported operation: {operation}")


def update_routes(action: str, ptfip: str, port: int, route: Dict[str, Any]) -> None:
    """
    Convenience function for route updates with attributes (bgp_helpers format).
    """
    BGPRouteController.update_route_with_attributes(action, ptfip, port, route)
