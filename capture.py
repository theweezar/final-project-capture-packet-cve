from sys import argv
import SystemHelpers
import pyshark
import msvcrt
import PacketUtil
import csv

def read_csv_and_analysize(csv_file_name: str):
    with open(csv_file_name, 'r+', encoding='utf-8') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        csv_reader_list = list(csv_reader)
        if len(csv_reader_list) != 0:
            lastest_packet_summary = csv_reader_list[-2]
            packet_summary_dict = PacketUtil.parse_csv_data_to_dict(lastest_packet_summary)
            print(packet_summary_dict)
            if PacketUtil.is_packet_payload_suspicious(packet_summary_dict) is True:
                PacketUtil.print_suspicious_packet_info(packet_summary_dict)
            

def main():
    # CSV file name
    output_file_name = argv[1] if len(argv) == 2 else "output"

    # Select network interface
    interfaces = SystemHelpers.get_interfaces()
    for i in range(len(interfaces)):
        print(str(i + 1) + '.', interfaces[i])
    selected = False
    selected_int = 0
    while selected is False:
        selected_int = input('Choose interfaces: ')
        selected = True if selected_int.isdigit() is True and int(selected_int) > 0 and int(selected_int) <= len(interfaces) else False

    # Initial CSV file for read and write
    header = [
        'Protocol', 'Source Address', 'Source Port', 'Destination Address',
        'Destination Port', 'Packet Time', 'Payload Hex', 'Note'
    ]
    csv_file = open(f'{output_file_name}.csv', 'w+', encoding='utf-8')
    csv_writter = csv.writer(csv_file)
    csv_writter.writerow(header)

    # Initial live capture
    capture = pyshark.LiveCapture(
        interface=interfaces[int(selected_int) - 1]
    )

    # Capturing packet...
    for packet in capture.sniff_continuously():
        if msvcrt.kbhit():
            char = msvcrt.getch().decode('utf-8')
            if char == 'q' or char == 'c':
                print('Exit...')
                break

        packet_summary = PacketUtil.summary_data_in_packet(packet, is_decode_hex_payload=True)
        
        if packet_summary is not None:
            if 'layer_string_payload' in packet_summary:
                del packet_summary['layer_string_payload']

            csv_writter.writerow([packet_summary[key] for key in packet_summary])

            read_csv_and_analysize(output_file_name + '.csv')
    
    csv_file.close()
    pyshark.capture.capture.StopCapture()

if __name__ == '__main__':
    main()