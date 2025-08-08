#!/usr/bin/env python3
"""
Splunk Output Module for Packet Drop Monitor

This module handles Splunk HTTP Event Collector (HEC) integration for the packet drop monitoring tool.
It provides a clean interface for sending drop counter data and alerts to Splunk for indexing and analysis.

Author: Network Monitoring Team
Date: July 2025
"""

import json
import time
import ssl
from datetime import datetime
from typing import Dict, Any, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import urljoin


def _sanitize_for_json(obj):
    """
    Recursively convert datetime objects and other non-JSON-serializable objects to strings.
    
    Args:
        obj: Any object that might contain datetime objects
        
    Returns:
        JSON-serializable version of the object
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, dict):
        return {k: _sanitize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [_sanitize_for_json(item) for item in obj]
    elif isinstance(obj, (int, float, str, bool, type(None))):
        return obj
    else:
        # Convert any other object to string
        return str(obj)


class SplunkOutput:
    """
    Splunk HTTP Event Collector (HEC) output handler for packet drop monitoring data.
    
    Handles sending structured data to Splunk via HEC endpoint for real-time indexing,
    alerting, and dashboard visualization.
    """
    
    def __init__(self, hec_url: str, hec_token: str, index: str = "network_monitoring", 
                 source: str = "packet_drop_monitor", sourcetype: str = "network:drops",
                 verify_ssl: bool = True, timeout: int = 30):
        """
        Initialize Splunk HEC connection parameters.
        
        Args:
            hec_url (str): Splunk HEC endpoint URL (e.g., https://splunk.company.com:8088)
            hec_token (str): HEC authentication token
            index (str): Splunk index name for data storage
            source (str): Source identifier for events
            sourcetype (str): Sourcetype for data parsing in Splunk
            verify_ssl (bool): Whether to verify SSL certificates
            timeout (int): HTTP request timeout in seconds
        """
        self.hec_url = hec_url.rstrip('/')
        self.hec_token = hec_token
        self.index = index
        self.source = source
        self.sourcetype = sourcetype
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        
        # Construct the full HEC endpoint URL
        self.endpoint = urljoin(self.hec_url + '/', 'services/collector')
        
        # Set up SSL context if needed
        if not verify_ssl:
            self.ssl_context = ssl.create_default_context()
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
        else:
            self.ssl_context = None
    
    def _send_to_splunk(self, event_data: Dict[str, Any]) -> bool:
        """
        Send event data to Splunk HEC endpoint.
        
        Args:
            event_data (Dict): Event data formatted for HEC
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Sanitize event data to ensure all datetime objects are converted
            sanitized_event_data = _sanitize_for_json(event_data)
            
            # Prepare the HEC event payload
            hec_event = {
                "time": int(time.time()),
                "index": self.index,
                "source": self.source,
                "sourcetype": self.sourcetype,
                "event": sanitized_event_data
            }
            
            # Convert to JSON
            payload = json.dumps(hec_event)
            
            # Create HTTP request
            request = Request(
                self.endpoint,
                data=payload.encode('utf-8'),
                headers={
                    'Authorization': 'Splunk {}'.format(self.hec_token),
                    'Content-Type': 'application/json'
                }
            )
            
            # Send request
            if self.ssl_context:
                response = urlopen(request, timeout=self.timeout, context=self.ssl_context)
            else:
                response = urlopen(request, timeout=self.timeout)
            
            # Check response
            if response.getcode() == 200:
                return True
            else:
                print("WARNING: Splunk HEC returned status code {}".format(response.getcode()))
                return False
                
        except HTTPError as e:
            error_msg = "HTTP error sending to Splunk: {} - {}".format(e.code, e.reason)
            print("ERROR: {}".format(error_msg))
            try:
                error_details = e.read().decode('utf-8')
                print("ERROR DETAILS: {}".format(error_details))
            except:
                pass
            return False
        except URLError as e:
            print("ERROR: URL error sending to Splunk: {}".format(e.reason))
            return False
        except Exception as e:
            print("ERROR: Failed to send data to Splunk: {}".format(e))
            import traceback
            print("TRACEBACK: {}".format(traceback.format_exc()))
            return False
    
    def store_drop_data(self, device_name: str, analyzer_type: str, data: Dict[str, Any]) -> bool:
        """
        Send drop counter data to Splunk.
        
        Args:
            device_name (str): Name of the monitored device
            analyzer_type (str): Type of analyzer (interface, drop_reason, queue, etc.)
            data (Dict): Drop counter data to send
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Sanitize all data to ensure JSON compatibility
            sanitized_data = _sanitize_for_json(data)
            
            # Prepare event data for Splunk
            event_data = {
                "event_type": "drop_counter",
                "timestamp": datetime.now().isoformat(),
                "device_name": device_name,
                "analyzer_type": analyzer_type,
                "interface_name": sanitized_data.get('interface_name'),
                "drop_reason": sanitized_data.get('drop_reason'),
                "queue_name": sanitized_data.get('queue_name'),
                "pg_name": sanitized_data.get('pg_name'),
                "npu_name": sanitized_data.get('npu_name'),
                "counter_name": sanitized_data.get('counter_name'),
                "current_value": sanitized_data.get('current_value'),
                "previous_value": sanitized_data.get('previous_value'),
                "increment": sanitized_data.get('increment'),
                "rx_drops": sanitized_data.get('rx_drops'),
                "tx_drops": sanitized_data.get('tx_drops'),
                "rx_util": sanitized_data.get('rx_util'),
                "tx_util": sanitized_data.get('tx_util'),
                "port": sanitized_data.get('port'),
                "priority_group": sanitized_data.get('priority_group'),
                "txq": sanitized_data.get('txq'),
                # NPU-specific fields
                "asic_id": sanitized_data.get('asic_id'),
                "counter_type": sanitized_data.get('counter_type'),
                "slice_info": sanitized_data.get('slice_info'),
                "drop_count": sanitized_data.get('drop_count'),
                "run_id": sanitized_data.get('run_id'),
                # Core file specific fields
                "filename": sanitized_data.get('filename'),
                "file_size": sanitized_data.get('file_size'),
                "file_date": sanitized_data.get('file_date'),
                "alert_type": sanitized_data.get('alert_type'),
                # Event counter specific fields
                "event_counter_name": sanitized_data.get('event_counter_name'),
                # PFCWD-specific fields
                "interface": sanitized_data.get('interface'),
                "queue_number": sanitized_data.get('queue_number'),
                "status": sanitized_data.get('status'),
                "storm_detected": sanitized_data.get('storm_detected'),
                "storm_restored": sanitized_data.get('storm_restored'),
                "tx_ok": sanitized_data.get('tx_ok'),
                "rx_ok": sanitized_data.get('rx_ok'),
                "metadata": sanitized_data.get('metadata', {})
            }
            
            # Remove None values to keep events clean
            event_data = {k: v for k, v in event_data.items() if v is not None}            
            return self._send_to_splunk(event_data)
            
        except Exception as e:
            print("ERROR: Failed to prepare drop data for Splunk: {}".format(e))
            return False
    
    def store_alert(self, device_name: str, analyzer_type: str, alert_level: str, 
                   message: str, details: Optional[Dict] = None) -> bool:
        """
        Send alert to Splunk.
        
        Args:
            device_name (str): Name of the monitored device
            analyzer_type (str): Type of analyzer that generated the alert
            alert_level (str): Alert severity level (INFO, WARNING, ERROR)
            message (str): Alert message
            details (Dict, optional): Additional alert details
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Sanitize details to ensure JSON compatibility
            sanitized_details = _sanitize_for_json(details or {})
            
            # Prepare alert event data
            event_data = {
                "event_type": "alert",
                "timestamp": datetime.now().isoformat(),
                "device_name": device_name,
                "analyzer_type": analyzer_type,
                "alert_level": alert_level,
                "message": message,
                "details": sanitized_details
            }
            
            return self._send_to_splunk(event_data)
            
        except Exception as e:
            print("ERROR: Failed to prepare alert for Splunk: {}".format(e))
            return False
    
    def test_connection(self) -> bool:
        """
        Test connectivity to Splunk HEC endpoint.
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            # Send a test event
            test_event = {
                "event_type": "connection_test",
                "timestamp": datetime.now().isoformat(),
                "message": "Packet Drop Monitor - Connection Test",
                "test": True
            }
            
            success = self._send_to_splunk(test_event)
            if success:
                print("INFO: Splunk HEC connection test successful")
            else:
                print("ERROR: Splunk HEC connection test failed")
            
            return success
            
        except Exception as e:
            print("ERROR: Failed to test Splunk connection: {}".format(e))
            return False
    
    def close(self):
        """Close connection (placeholder for consistency with DBOutput)."""
        # HTTP connections are stateless, so nothing to close
        pass
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


# Convenience functions for compatibility with db_output.py interface
def send_to_splunk(hec_url: str, hec_token: str, device_name: str, analyzer_type: str, 
                  data: Dict[str, Any], **kwargs) -> bool:
    """Convenience function for sending drop data to Splunk."""
    with SplunkOutput(hec_url, hec_token, **kwargs) as splunk:
        return splunk.store_drop_data(device_name, analyzer_type, data)


def send_alert_to_splunk(hec_url: str, hec_token: str, device_name: str, analyzer_type: str, 
                        alert_level: str, message: str, details: Optional[Dict] = None, 
                        **kwargs) -> bool:
    """Convenience function for sending alerts to Splunk."""
    with SplunkOutput(hec_url, hec_token, **kwargs) as splunk:
        return splunk.store_alert(device_name, analyzer_type, alert_level, message, details)


def test_splunk_connection(hec_url: str, hec_token: str, **kwargs) -> bool:
    """Convenience function for testing Splunk connection."""
    with SplunkOutput(hec_url, hec_token, **kwargs) as splunk:
        return splunk.test_connection()


# Configuration helper for loading Splunk settings from YAML config
def load_splunk_config_from_yaml(config_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Extract Splunk configuration from YAML config data.
    
    Args:
        config_data (Dict): YAML configuration data
        
    Returns:
        Optional[Dict]: Splunk configuration or None if not found
    """
    try:
        splunk_config = config_data.get('splunk', {})
        
        if not splunk_config:
            return None
        
        # Validate required fields
        required_fields = ['hec_url', 'hec_token']
        for field in required_fields:
            if field not in splunk_config:
                print("ERROR: Missing required Splunk config field: {}".format(field))
                return None
        
        # Set defaults for optional fields
        splunk_config.setdefault('index', 'network_monitoring')
        splunk_config.setdefault('source', 'packet_drop_monitor')
        splunk_config.setdefault('sourcetype', 'network:drops')
        splunk_config.setdefault('verify_ssl', True)
        splunk_config.setdefault('timeout', 30)
        
        return splunk_config
        
    except Exception as e:
        print("ERROR: Failed to load Splunk config from YAML: {}".format(e))
        return None


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 3:
        print("Usage: python3 splunk_output.py <hec_url> <hec_token>")
        print("Example: python3 splunk_output.py https://splunk.company.com:8088 your-hec-token-here")
        sys.exit(1)
    
    hec_url = sys.argv[1]
    hec_token = sys.argv[2]
    
    print("Testing Splunk HEC connection...")
    
    # Test connection
    if test_splunk_connection(hec_url, hec_token, verify_ssl=False, index="main", sourcetype="_json"):
        print("✓ Connection test passed")
    else:
        print("✗ Connection test failed")
        sys.exit(1)
    
    print("Splunk output test completed!")