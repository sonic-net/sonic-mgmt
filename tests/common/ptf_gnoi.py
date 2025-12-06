"""
PTF-based gNOI client wrapper providing high-level gNOI operations.

This module provides a user-friendly wrapper around PtfGrpc for gNOI
(gRPC Network Operations Interface) operations, hiding the low-level
gRPC complexity behind clean, Pythonic method interfaces.
"""
import logging
from datetime import datetime
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class PtfGnoi:
    """
    High-level gNOI client wrapper.
    
    This class provides clean, Pythonic interfaces for gNOI operations,
    wrapping the low-level PtfGrpc client and handling gNOI-specific
    data transformations and validations.
    """
    
    def __init__(self, grpc_client):
        """
        Initialize PtfGnoi wrapper.
        
        Args:
            grpc_client: PtfGrpc instance for low-level gRPC operations
        """
        self.grpc_client = grpc_client
        logger.info(f"Initialized PtfGnoi wrapper with {grpc_client}")
    
    def system_time(self) -> Dict:
        """
        Get the current system time from the device.
        
        Returns:
            Dictionary containing time information:
            - time: Nanoseconds since Unix epoch (string)
            - formatted_time: Human-readable timestamp (added by wrapper)
            
        Raises:
            GrpcConnectionError: If connection fails
            GrpcCallError: If the gRPC call fails
            GrpcTimeoutError: If the call times out
        """
        logger.debug("Getting system time via gNOI System.Time")
        
        # Make the low-level gRPC call
        response = self.grpc_client.call_unary("gnoi.system.System", "Time")
        
        # Add human-readable formatting
        if "time" in response:
            try:
                # Convert nanoseconds to seconds for Python datetime
                time_ns = int(response["time"])
                time_seconds = time_ns / 1_000_000_000
                formatted_time = datetime.fromtimestamp(time_seconds).isoformat()
                response["formatted_time"] = formatted_time
                logger.debug(f"System time: {response['time']} ns ({formatted_time})")
            except (ValueError, TypeError) as e:
                logger.warning(f"Failed to format time {response['time']}: {e}")
                # Don't fail the call, just skip formatting
        
        return response
    
    def __str__(self):
        return f"PtfGnoi(grpc_client={self.grpc_client})"
    
    def __repr__(self):
        return self.__str__()