"""
This module contains utilities for parsing the primitive values out of the ASIC query results.
"""
import ctypes
from sairedis import pysairedis


def mac_address_str_from_swig_uint8_t_arr(swig_uint8_p) -> str:
    """
    Given a swig pointer to a uint8_t array, return the MAC address string representation

    :param swig_uint8_p: The swig pointer to the uint8_t array
    :return: The MAC address string representation
    """
    pointer = ctypes.cast(swig_uint8_p.__int__(), ctypes.POINTER(ctypes.c_uint8))
    octets = [pointer[i] for i in range(6)]
    fmtd_mac_address = ":".join([f"{octet:02X}" for octet in octets])
    return fmtd_mac_address


def extract_attr_value(attr_metadata, attr):
    """
    Extract the value from the attribute based on the attribute metadata

    :param attr_metadata: The attribute metadata
    :param attr: The attribute
    :return: The value of the attribute
    """

    if attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_BOOL:
        attr_value = attr.value.booldata
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_UINT8:
        attr_value = attr.value.u8
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_INT8:
        attr_value = attr.value.s8
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_UINT16:
        attr_value = attr.value.u16
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_INT16:
        attr_value = attr.value.s16
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_UINT32:
        attr_value = attr.value.u32
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_INT32:
        attr_value = attr.value.s32
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_UINT64:
        attr_value = attr.value.u64
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_INT64:
        attr_value = attr.value.s64
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_OBJECT_ID:
        attr_value = attr.value.oid
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_UINT32_LIST:
        attr_value = attr.value.u32list
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_MAC:
        attr_value = mac_address_str_from_swig_uint8_t_arr(attr.value.mac)
    # ***************************************************************************
    # NOTE: GPT generated attributes below, likely to be incomplete and/or
    #       need additional processing.
    # ***************************************************************************
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_IP_ADDRESS:
        attr_value = attr.value.ipaddr
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_LATCH_STATUS:
        attr_value = attr.value.latch
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_INT8_LIST:
        attr_value = attr.value.s8list
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_OBJECT_LIST:
        attr_value = attr.value.aclactiondataobjlist
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_SYSTEM_PORT_CONFIG_LIST:
        attr_value = attr.value.systemportconfiglist
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_UINT8_LIST:
        attr_value = attr.value.aclfielddatau8list
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_UINT32_LIST:
        attr_value = attr.value.u32list
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_NAT_ENTRY_DATA:
        attr_value = attr.value.natentrydata
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_INT32_LIST:
        attr_value = attr.value.s32list
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_FABRIC_PORT_REACHABILITY:
        attr_value = attr.value.fabricportreachability
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_TLV_LIST:
        attr_value = attr.value.tlvlist
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_UINT32:
        attr_value = attr.value.u32
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_UINT8_LIST:
        attr_value = attr.value.u8list
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_IPV4:
        attr_value = attr.value.aclfielddataipv4
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_UINT16_RANGE_LIST:
        attr_value = attr.value.u16rangelist
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_CHAIN_LIST:
        attr_value = attr.value.aclchainlist
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_MACSEC_SCI:
        attr_value = attr.value.aclfielddatamacsecsci
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_INT16:
        attr_value = attr.value.s16
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_UINT16:
        attr_value = attr.value.aclactiondatau16
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_IPV6:
        attr_value = attr.value.aclactiondataipv6
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_IPV4:
        attr_value = attr.value.ip4
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_UINT8:
        attr_value = attr.value.aclactiondatau8
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_PORT_SNR_LIST:
        attr_value = attr.value.portsnrlist
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_UINT16:
        attr_value = attr.value.u16
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_BOOL:
        attr_value = attr.value.booldata
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_IPV6:
        attr_value = attr.value.aclfielddataipv6
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_BOOL:
        attr_value = attr.value.aclactiondatabool
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_OBJECT_ID:
        attr_value = attr.value.oid
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_UINT8:
        attr_value = attr.value.aclfielddatau8
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_POINTER:
        attr_value = attr.value.ptr
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_TIMESPEC:
        attr_value = attr.value.timespec
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_UINT16_LIST:
        attr_value = attr.value.u16list
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_UINT8:
        attr_value = attr.value.u8
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_INT16:
        attr_value = attr.value.aclfielddatas16
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_PORT_ERR_STATUS_LIST:
        attr_value = attr.value.porterrstatuslist
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_JSON:
        attr_value = attr.value.json
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_UINT16:
        attr_value = attr.value.aclfielddatau16
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_IP_ADDRESS:
        attr_value = attr.value.aclactiondataipaddr
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_BOOL:
        attr_value = attr.value.aclfielddatabool
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_RESOURCE_LIST:
        attr_value = attr.value.aclresourcelist
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_IP_PREFIX_LIST:
        attr_value = attr.value.ipprefixlist
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_VLAN_LIST:
        attr_value = attr.value.vlanlist
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_INT8:
        attr_value = attr.value.aclactiondataint8
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_OBJECT_LIST:
        attr_value = attr.value.objlist
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_TWAMP_STATS_DATA:
        attr_value = attr.value.twampstatsdata
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_MACSEC_SALT:
        attr_value = attr.value.macsecsalt
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_IPV6:
        attr_value = attr.value.ipv6
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_MAC:
        attr_value = attr.value.aclfielddatamac
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_AUTH_KEY:
        attr_value = attr.value.authkey
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_UINT32:
        attr_value = attr.value.aclfielddatau32
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_MACSEC_SAK:
        attr_value = attr.value.macsecsak
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_INT64:
        attr_value = attr.value.s64
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_SYSTEM_PORT_CONFIG:
        attr_value = attr.value.systemportconfig
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_INT32_RANGE:
        attr_value = attr.value.s32range
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_OBJECT_ID:
        attr_value = attr.value.aclactiondataobjid
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_MACSEC_SCI:
        attr_value = attr.value.macsecsci
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_UINT64:
        attr_value = attr.value.u64
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_PRBS_RX_STATE:
        attr_value = attr.value.prbsrxstate
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_INT32:
        attr_value = attr.value.aclfielddatas32
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_INT32:
        attr_value = attr.value.aclactiondatas32
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_CHARDATA:
        attr_value = attr.value.chardata
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_SEGMENT_LIST:
        attr_value = attr.value.segmentlist
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_INT8:
        attr_value = attr.value.s8
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_PORT_FREQUENCY_OFFSET_PPM_LIST:
        attr_value = attr.value.portfreqoffsetppmlist
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_MACSEC_AUTH_KEY:
        attr_value = attr.value.macsecauthkey
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_MAP_LIST:
        attr_value = attr.value.maplist
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_OBJECT_ID:
        attr_value = attr.value.aclfielddataobjid
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_UINT64:
        attr_value = attr.value.aclfielddatau64
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_CAPABILITY:
        attr_value = attr.value.aclcapability
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_QOS_MAP_LIST:
        attr_value = attr.value.qosmaplist
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ENCRYPT_KEY:
        attr_value = attr.value.encryptkey
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_OBJECT_LIST:
        attr_value = attr.value.aclfielddataobjlist
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_IP_PREFIX:
        attr_value = attr.value.ipprefix
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_PORT_EYE_VALUES_LIST:
        attr_value = attr.value.porteyevalueslist
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_MACSEC_SSCI:
        attr_value = attr.value.macsecssci
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_UINT32:
        attr_value = attr.value.aclactiondatau32
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_FIELD_DATA_INT8:
        attr_value = attr.value.aclfielddataint8
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_INT16_LIST:
        attr_value = attr.value.s16list
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_PORT_LANE_LATCH_STATUS_LIST:
        attr_value = attr.value.portlanelatchstatuslist
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_INT32:
        attr_value = attr.value.s32
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_IPV4:
        attr_value = attr.value.aclactiondataipv4
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_MAC:
        attr_value = attr.value.aclactiondatamac
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_ACL_ACTION_DATA_INT16:
        attr_value = attr.value.aclactiondatas16
    elif attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_IP_ADDRESS_LIST:
        attr_value = attr.value.ipaddlist
    else:
        raise NotImplementedError(f"Unsupported attribute value type: {attr_metadata.attrvaluetype}")

    if attr_metadata.isenum:
        # Map to the string value if enum
        enum_metadata = attr_metadata.enummetadata
        attr_value = pysairedis.sai_metadata_get_enum_value_name(enum_metadata, attr_value)

    return attr_value
