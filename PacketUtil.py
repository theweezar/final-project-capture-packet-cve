from pyshark.packet.packet import Packet
from typing import Union
import SystemHelpers
import re

def discover_all_fields_that_match_value(packet: Packet, value):
    '''
        Builds a dictionary, with each layer name as a key, containing a list
        of each field, in that layer, that matches the value exactly

        Args:
            packet: a single packet, that will be inspected
            value: the value that all fields in the packet will be inspected for.

        Returns:
            a dictionary of lists
            or None, if any of the arguments are None
            example:
                {'http': ['http.request.uri']}
    '''
    if not packet or not value:
        return None

    matches = {}
    for current_layer in packet.layers:
        fields = current_layer.__dict__['_all_fields']
        layer_name = current_layer.__dict__['_layer_name']
        for field in fields:
            if value == fields[field]:
                if layer_name not in matches:
                    matches[layer_name] = []
                matches[layer_name].append(field)
    return matches


def discover_all_fields_that_contain_value(packet: Packet, value):
    '''
        Builds a dictionary, with each layer name as a key, containing a list
        of each field, in that layer, that contains the value

        It doesn't have to be an exact match, it only has to contain the value.
        i.e. '20' is contained in '13203'

        Args:
            packet: a single packet, that will be inspected
            value: the value that all fields in the packet will be inspected for.

        Returns:
            a dictionary of lists
            or None, if any of the arguments are None
            example:
                {'http': ['http.request.uri']}
    '''
    if not packet or not value:
        return None

    matches = {}
    for current_layer in packet.layers:
        fields = current_layer.__dict__['_all_fields']
        layer_name = current_layer.__dict__['_layer_name']
        for field in fields:
            if value in fields[field]:
                if layer_name not in matches:
                    matches[layer_name] = []
                matches[layer_name].append(field)
    return matches


def get_value_from_packet_for_layer_field(packet: Packet, layer, field):
    '''
        Gets the value from the packet for the specified 'layer' and 'field'

        Args:
            packet: The packet where you'll be retrieving the value from
            layer: The layer that contains the field
            field: The field that contains the value

        Returns:
            the value at packet[layer][key] or None
            or None, if any of the arguments are None
    '''
    if not packet or not layer or not field:
        return None
    for current_layer in packet.layers:
        if layer == current_layer.__dict__['_layer_name'] and \
           current_layer.__dict__['_all_fields']:
            return current_layer.__dict__['_all_fields'][field]
    return None


def get_all_field_names(packet: Packet, layer=None):
    '''
        Builds a unique list of field names, that exist in the packet,
        for the specified layer.

        If no layer is provided, all layers are considered.

        Args:
            packet: the pyshark packet object the fields will be gathered from
            layer: the string name of the layer that will be targeted

        Returns:
            a set containing all unique field names
            or None, if packet is None
    '''

    if not packet:
        return None

    field_names = set()
    for current_layer in packet.layers:
        if not layer or layer == current_layer.__dict__['_layer_name']:
            for field in current_layer.__dict__['_all_fields']:
                field_names.add(field)
    # print(*sorted(field_names), sep='\n')
    return field_names

def print_all_field_in_layers(packet: Packet):
    for layers in packet.layers:
        for field in layers.__dict__['_all_fields']:
            print('Layer:', layers.__dict__['_layer_name'], ', Field:', field, ':', layers.__dict__['_all_fields'][field])

def print_all_field_in_frame_info(packet: Packet):
    frame_info = packet.__dict__['frame_info']
    for frame in frame_info.__dict__:
        print(frame, ':', frame_info.__dict__[frame])

def get_tls_app_data(packet: Packet, decode = False):
    tls_app_data = None
    for current_layer in packet.layers:
        if current_layer.__dict__['_layer_name'] == 'tls':
            if 'tls.app_data' in current_layer.__dict__['_all_fields']:
                tls_app_data = str(current_layer.__dict__['_all_fields']['tls.app_data'])
                if tls_app_data is not None and decode is True:
                    tls_app_data = SystemHelpers.convert_hex_string_to_paragraph(tls_app_data)
    return tls_app_data

def get_udp_tcp_hex_payload(packet: Packet) -> Union[str, None]:
    payload = None
    
    for layers in packet.layers:
        if layers.__dict__['_layer_name'] == 'udp' and 'udp.payload' in layers.__dict__['_all_fields']:
            # payload = str(get_value_from_packet_for_layer_field(packet, 'udp', 'udp.payload'))
            payload = str(layers.__dict__['_all_fields']['udp.payload'])
        elif layers.__dict__['_layer_name'] == 'tcp' and 'tcp.payload' in layers.__dict__['_all_fields']:
            # payload = str(get_value_from_packet_for_layer_field(packet, 'tcp', 'tcp.payload'))
            payload = str(layers.__dict__['_all_fields']['tcp.payload'])
    
    return payload

def summary_data_in_packet(packet: Packet, is_decode_hex_payload: False) -> Union[dict, None]:
    """Summary necessary packet information into dict"""
    summary_dict = {}
    try:
        summary_dict['protocol'] = packet.transport_layer
        summary_dict['source_address'] = packet.ip.src
        summary_dict['source_port'] = packet[packet.transport_layer].srcport
        summary_dict['destination_address'] = packet.ip.dst
        summary_dict['destination_port'] = packet[packet.transport_layer].dstport
        summary_dict['packet_time'] = '{:%Y-%b-%d %H:%M:%S}'.format(packet.sniff_time)
        hex_payload = get_udp_tcp_hex_payload(packet)
        summary_dict['layer_hex_payload'] = hex_payload
        if hex_payload is not None and is_decode_hex_payload is True:
            summary_dict['layer_string_payload'] = SystemHelpers.convert_hex_payload_to_string(hex_payload)
        return summary_dict
    except:
        return None

def is_packet_payload_suspicious(packet_summary: dict):
    """
    Analyze payload with pattern /(<\?php)((\s+)?.*)/g. Return True if this packet is suspicious
    """
    if 'layer_string_payload' in packet_summary:
        pattern = '(<\?php)((\s+)?.*)'
        layer_string_payload = re.sub('\\s+', '', packet_summary['layer_string_payload'])
        search_result = re.search(pattern, layer_string_payload)
        if search_result is not None:
            return True

    return False

