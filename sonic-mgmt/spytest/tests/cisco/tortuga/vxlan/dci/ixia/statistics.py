from ixnetwork_restpy import SessionAssistant
from ixnetwork_restpy.assistants.statistics.row import Row
from typing import List, Dict

def get_traffic_stats(sess_assistant: SessionAssistant) -> List[Dict[str, str]]:
    """
    Retrieve statistics for all traffic items in the Ixia session.
    
    This function collects statistics such as transmitted and received frames for each 
    traffic item configured in the Ixia traffic generator.
    
    Args:
        sess_assistant (SessionAssistant): The Ixia session object
        
    Returns:
        List[Dict[str, str]]: List of dictionaries containing traffic statistics for each item.
                              Each dict has 'traffic_item', 'tx_frames', and 'rx_frames' keys.
        
    Example:
        stats = get_traffic_stats(sess)
    """
    from spytest import st
    
    st.log("Retrieving IXIA traffic statistics...")
    stats: Row = sess_assistant.StatViewAssistant("Traffic Item Statistics").Rows
    
    traffic_stats = []
    for stat in stats:
        traffic_item = stat['Traffic Item']
        tx_frames = stat['Tx Frames']
        rx_frames = stat['Rx Frames']
        
        traffic_stats.append({
            'traffic_item': str(traffic_item),
            'tx_frames': str(tx_frames),
            'rx_frames': str(rx_frames)
        })
        
        st.log(f"Traffic Item: {traffic_item}, Tx Frames: {tx_frames}, Rx Frames: {rx_frames}")
    
    st.log(f"Successfully retrieved statistics for {len(traffic_stats)} traffic items")
    return traffic_stats


def validate_traffic_stats(sess_assistant: SessionAssistant) -> bool:
    """
    Validate traffic statistics to ensure no packet loss (Rx == Tx).
    
    Args:
        sess_assistant (SessionAssistant): The Ixia session object
        
    Returns:
        bool: True if all traffic items have Rx == Tx (no packet loss), False otherwise
        
    Example:
        success = validate_traffic_stats(sess)
    """
    from spytest import st
    
    st.log("Starting IXIA traffic statistics validation...")
    # Get traffic statistics
    traffic_stats = get_traffic_stats(sess_assistant)
    
    if not traffic_stats:
        st.error("No traffic statistics available for validation")
        return False
    
    all_passed = True
    st.log("=" * 80)
    st.log("IXIA Traffic Statistics Validation")
    st.log("=" * 80)
    
    for stat in traffic_stats:
        traffic_item = stat['traffic_item']
        tx_frames = int(stat['tx_frames'])
        rx_frames = int(stat['rx_frames'])
        
        st.log(f"Traffic Item: {traffic_item}")
        st.log(f"  Tx Frames: {tx_frames}")
        st.log(f"  Rx Frames: {rx_frames}")
        
        if rx_frames == tx_frames:
            st.log(f"  ✓ PASS: Rx matches Tx (no packet loss or duplication)")
        elif rx_frames < tx_frames:
            loss = tx_frames - rx_frames
            loss_percent = (loss / tx_frames * 100) if tx_frames > 0 else 0
            st.error(f"  ✗ FAIL: Packet loss detected! Lost {loss} frames ({loss_percent:.2f}%)")
            all_passed = False
        else:  # rx_frames > tx_frames
            extra = rx_frames - tx_frames
            extra_percent = (extra / tx_frames * 100) if tx_frames > 0 else 0
            st.error(f"  ✗ FAIL: Duplicate packets detected! Received {extra} extra frames ({extra_percent:.2f}% duplication)")
            all_passed = False
        
        st.log("-" * 80)
    
    if all_passed:
        st.log("✓ All traffic items passed validation (Rx == Tx)")
    else:
        st.error("✗ Traffic validation failed - packet loss or duplication detected in one or more traffic items")
    
    st.log("=" * 80)
    return all_passed


def get_all_traffic_items_stats(sess_assistant: SessionAssistant) -> List[Dict[str, str]]:
    """
    Retrieve statistics for all traffic items in the Ixia session.
    
    This is an alias for get_traffic_stats() for backward compatibility.
    
    Args:
        sess_assistant (SessionAssistant): The Ixia session object
        
    Returns:
        List[Dict[str, str]]: List of dictionaries containing traffic statistics for each item.
        
    Example:
        stats = get_all_traffic_items_stats(sess)
    """
    return get_traffic_stats(sess_assistant)