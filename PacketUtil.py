from pyshark.packet.packet import Packet
from typing import Union
import SystemHelpers
import re

def get_value_from_packet_for_layer_field(packet: Packet, layer: str, field: str):
    '''
        Gets the value from the packet for the specified 'layer' and 'field'
    '''
    if not packet or not layer or not field:
        return None
    for current_layer in packet.layers:
        if layer == current_layer.__dict__['_layer_name'] and \
           current_layer.__dict__['_all_fields']:
            return current_layer.__dict__['_all_fields'][field]
    return None

def get_value_from_field(packet: Packet, field: str):
    '''
        Get value from field name
    '''
    for current_layer in packet.layers:
        if field in current_layer.__dict__['_all_fields']:
            return current_layer.__dict__['_all_fields'][field]
    return None

def get_all_field_names(packet: Packet, layer=None):
    '''
        Builds a unique list of field names, that exist in the packet,
        for the specified layer.
    '''
    if not packet:
        return None

    field_names = set()
    for current_layer in packet.layers:
        if not layer or layer == current_layer.__dict__['_layer_name']:
            for field in current_layer.__dict__['_all_fields']:
                field_names.add(field)
    return field_names

    # print(*sorted(field_names), sep='\n')

def print_all_field_in_layers(packet: Packet):
    '''
        Print all fields in every layers in the packet
    '''
    for layers in packet.layers:
        for field in layers.__dict__['_all_fields']:
            print('Layer:', layers.__dict__['_layer_name'], ', Field:', field, ':', layers.__dict__['_all_fields'][field])

def print_all_field_in_frame_info(packet: Packet):
    '''
        Print all fields in packet frame
    '''
    frame_info = packet.__dict__['frame_info']
    for frame in frame_info.__dict__:
        print(frame, ':', frame_info.__dict__[frame])

def get_tls_app_data(packet: Packet, decode = False):
    '''
        Get the TLS payload if it's in the packet
    '''
    tls_app_data = None
    for current_layer in packet.layers:
        if current_layer.__dict__['_layer_name'] == 'tls':
            if 'tls.app_data' in current_layer.__dict__['_all_fields']:
                tls_app_data = str(current_layer.__dict__['_all_fields']['tls.app_data'])
                if tls_app_data is not None and decode is True:
                    tls_app_data = SystemHelpers.convert_hex_string_to_paragraph(tls_app_data)
    return tls_app_data

def get_udp_tcp_hex_payload(packet: Packet) -> Union[str, None]:
    '''
        Get UDP or TCP payload of the packet
    '''
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
    '''
        Summary necessary packet information into a dictionary
    '''
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

def parse_csv_data_to_dict(dataset: list) -> dict:
    '''
        Parse dataset from CSV into dictionary
    '''
    summary_dict = {}
    try:
        summary_dict['protocol'] = dataset[0]
        summary_dict['source_address'] = dataset[1]
        summary_dict['source_port'] = dataset[2]
        summary_dict['destination_address'] = dataset[3]
        summary_dict['destination_port'] = dataset[4]
        summary_dict['packet_time'] = dataset[5]
        hex_payload = dataset[6]
        summary_dict['layer_hex_payload'] = hex_payload
        if hex_payload is not None and len(hex_payload) != 0:
            summary_dict['layer_string_payload'] = SystemHelpers.convert_hex_payload_to_string(hex_payload)
        return summary_dict
    except:
        return None

def is_packet_payload_suspicious(packet_summary: dict):
    '''
        Analyze payload with pattern /(<\?php)((\s+)?.*)/g. Return True if this packet is suspicious
    '''
    if packet_summary is not None:
        if 'layer_string_payload' in packet_summary:
            pattern_php = '(<\?php)((\s+)?.*)'
            pattern_content_type = 'Content-Type:image\/(jpeg|png)'
            layer_string_payload = re.sub('\\s+', '', packet_summary['layer_string_payload'])
            search_result_php = re.search(pattern_php, layer_string_payload)
            search_result_content_type = re.search(pattern_content_type, layer_string_payload)
            if search_result_php is not None and search_result_content_type is not None:
                return search_result_php

    return None

def get_file_name_from_payload(payload: str):
    '''
        Extract file name from packet's payload
    '''
    pattern_filename = '(filename=")(\w+\.jpg|\.png|\.jpeg)(")'
    regex_filename = re.compile(pattern_filename)
    split_array = regex_filename.split(payload)
    if len(split_array) == 5:
        return split_array[2]
    return None

def print_suspicious_packet_info(packet_summary: dict):
    '''
        Print information in terminal
    '''
    print('[', packet_summary['packet_time'], ']', '- Warning: Detect suspicious packet that has been injected')
    print('Protocol:', packet_summary['protocol'])
    print('Source IP:', packet_summary['source_address'] + ':' + packet_summary['source_port'])
    print('Destination IP:', packet_summary['destination_address'] + ':' + packet_summary['destination_port'])
    injected_filename = get_file_name_from_payload(packet_summary['layer_string_payload'])
    if injected_filename is not None:
        print('Injected file name:', injected_filename)
    print('Suspicious payload:', packet_summary['layer_string_payload'])
    