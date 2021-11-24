import SystemHelpers
import pyshark
import msvcrt
import PacketUtil
import csv
import sys

def main():
    output_file_name = "output"
    interfaces = SystemHelpers.get_interfaces()
    for i in range(len(interfaces)):
        print(str(i + 1) + '.', interfaces[i])

    selected = False
    selected_int = 0
    while selected is False:
        selected_int = input('Choose interfaces: ')
        selected = True if selected_int.isdigit() is True and int(selected_int) > 0 and int(selected_int) <= len(interfaces) else False

    capture = pyshark.LiveCapture(
        interface=interfaces[int(selected_int) - 1]
    )

    csv_file = open(f'{output_file_name}.csv', 'w+', encoding='utf-8')
    csv_writter = csv.writer(csv_file)
    header = ['Protocol', 'Source Address', 'Source Port', 'Destination Address', 'Destination Port', 'Packet Time', 'Payload Hex', 'Note']
    csv_writter.writerow(header)

    for packet in capture.sniff_continuously():
        if msvcrt.kbhit():
            char = msvcrt.getch().decode('utf-8')
            if char == 'q' or char == 'c':
                print('Exit...')
                break

        packet_summary = PacketUtil.summary_data_in_packet(packet, is_decode_hex_payload=True)
        
        if packet_summary is not None:
            print(packet_summary)
            
            if PacketUtil.is_packet_payload_suspicious(packet_summary) is True:
                PacketUtil.print_all_field_in_layers(packet)
                packet_summary['note'] = 'Suspicious'

            if 'layer_string_payload' in packet_summary:
                del packet_summary['layer_string_payload']

            csv_writter.writerow([packet_summary[key] for key in packet_summary])
    
    csv_file.close()
    pyshark.capture.capture.StopCapture()
    

if __name__ == '__main__':
    main()