from ..SubMng import PREPROCESSING, PROCESSING, POSTPROCESSING,\
    VALIDATION, CONFIG_CHECK, ENQUEUE, PROTOCOL, FUNCTION, DICTIONARY,\
    ALT, KEY, FILL, RECALCULATION, subscribe_protocol_transformation,\
    subscribe_timestamp_postprocess, subscribe_timestamp_process,\
    subscribe_timestamp_alt, subscribe_timestamp_mode

import scapy.layers.inet as inet
import scapy.layers.inet6 as inet6
import scapy.layers.dns as dns
import scapy.layers.l2 as l2
import scapy.utils

import scapy_extend.http as http

from ..transf import PacketProcessing as TMpp
from ..utils import tmdict_fillers as Filler

def timestamp_static_shift(packet, data, prev_timestamp_old, prev_timestamp_new, curr_timestamp_old, curr_timestamp_new):
    """
    Shift current packet timestamp by specified value. Ignored timestamp changes by postprocessing.
    Data must be a dictionary with field 'timestamp_shift' containing signed float
    Data[TMdef.GLOBAL][TMdef.ATTACK] must contain key timestamp_shift.

    :param packet: Ether scapy packet
    :param data: dict containing TMLib.TMdict dictionaries
    :param prev_timestamp_old: old (unchanged) timestamp of previous packet, float
    :param prev_timestamp_new: new (generated) timestamp of previous packet, float
    :param curr_timestamp_old: old (unchanged) timestamp of current packet, float
    :param curr_timestamp_new: new timestamp value to be changed
    :return: new timestamp of the packet, float 
    """
    return curr_timestamp_old + data[TMdef.GLOBAL][TMdef.ATTACK]['timestamp_shift']

"""
Single entry in subsribed_functions represents single tranformation.
Multiple processing, preprocessing & validation functions may be referenced
in single entry (including other entries).

An entry in subsribed_functions must have:
key - unique string name
value - these possible keys
    PROCESSING - contains list of dicionaries with keys PROTOCOL and FUNCTION
                representing protocol and function for rewrapper processing function
    PREPROCESSING - contains list of dictionaries with keys PROTOCOL and FUNCTION
                representing protocol and function for rewrapper preprocessing function
    VALIDATION - contains list of dictionaries witn keys DICTIONARY and FUNCTION
                representing TMdict dictionaries validation function and name of the dictionary
                in rewrapper
    ENQUEUE - contains list of entries from subsribed_functions
    FILL - list of functions that statistics, TMdicts and parsed config as dict on input and fill them with data
"""
subsribed_functions = { # dictionary of known transformation functions

#################
#### Ether
#################

'mac_change_default' : {
    PROCESSING : [
        {
        PROTOCOL : inet.Ether
        , FUNCTION : TMpp.mac_change_default
        }
    ]
    , FILL : [
        Filler.make_mac_map
    ]
}

#################
#### ARP
#################

, 'arp_change_default' : {
    PROCESSING : [
        {
        PROTOCOL : l2.ARP
        , FUNCTION : TMpp.arp_change_default
        }
    ]
    , FILL : [
        Filler.make_mac_map
        , Filler.make_ip_map
    ]
}

#################
#### IPv4
#################
, 'ip_src_change' : {
    PROCESSING : [
        {
        PROTOCOL : inet.IP
        , FUNCTION : TMpp.ip_src_change
        }
    ]
    , FILL : [
        Filler.make_ip_map
    ]
}

, 'ip_dst_change' : {
    PROCESSING : [
        {
        PROTOCOL : inet.IP
        , FUNCTION : TMpp.ip_dst_change
        }
    ]
    , FILL : [
        Filler.make_ip_map
    ]
}

, 'ip_auto_checksum' : {
    PROCESSING : [
        {
        PROTOCOL : inet.IP
        , FUNCTION : TMpp.ip_auto_checksum
        }
    ]
}

#################
#### IPv6
#################
, 'ipv6_src_change' : {
    PROCESSING : [
        {
        PROTOCOL : inet6.IPv6
        , FUNCTION : TMpp.ipv6_src_change
        }
    ]
    , FILL : [
        Filler.make_ip_map
    ]
}

, 'ipv6_dst_change' : {
    PROCESSING : [
        {
        PROTOCOL : inet6.IPv6
        , FUNCTION : TMpp.ipv6_dst_change
        }
    ]
    , FILL : [
        Filler.make_ip_map
    ]
}


#################
#### ICMPv4
#################
, 'icmp_ip_src_change' : {
    PROCESSING : [
        {
        PROTOCOL : inet.IPerror
        , FUNCTION : TMpp.ip_src_change
        }
    ]
    , FILL : [
        Filler.make_ip_map
    ]
}

, 'icmp_ip_dst_change' : {
    PROCESSING : [
        {
        PROTOCOL : inet.IPerror
        , FUNCTION : TMpp.ip_dst_change
        }
    ]
    , FILL : [
        Filler.make_ip_map
    ]
}

#################
#### DNS
#################
, 'dns_change_ips' : {
    PROCESSING : [
        {
        PROTOCOL : dns.DNS
        , FUNCTION : TMpp.dns_change_ips
        }
    ]
    , FILL : [
        Filler.make_ip_map
    ]
}

#################
#### HTTPv1
#################
, 'httpv1_regex_ip_swap' : {
    PROCESSING : [
        {
        PROTOCOL : http.HTTPv1 
        , FUNCTION : TMpp.httpv1_regex_ip_swap
        }
    ]
    , FILL : [
        Filler.make_ip_map
    ]
}
}


"""
Single entry in timestamp_function_dict represents single timestamp generation function

An entry in timestamp_function_dict must have:
key - unique string name
value - these possible keys
    FUNCTION - contains timestamp generator function 
    ALT - contains backup/alternative timestamp generation function. 
        If value is string, timestamp_alt_function_dict will be searched.
    VALIDATION - contains list of dictionaries witn keys DICTIONARY and FUNCTION
                representing TMdict dictionaries validation function and name of the dictionary
                in rewrapper
    FILL - list of functions that statistics, TMdicts and parsed config as dict on input and fill them with data
"""
timestamp_function_dict = { # dictionary of known timestamp generation functions
'timestamp_shift' : {
    FUNCTION : TMtg.timestamp_static_shift
}
}

subscribe_protocol_transformation(subsribed_functions)
subscribe_timestamp_process(timestamp_function_dict)
