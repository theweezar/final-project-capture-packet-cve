from sys import argv
import SystemHelpers
import pyshark
import msvcrt
import PacketUtil
import csv
import threading
import shutil
import time

thread_read_csv = False

def reset_csv_file(csv_file_name: str):
    '''
        Reset the csv file and write header into it first
    '''
    header = [
        'Protocol', 'Source Address', 'Source Port', 'Destination Address',
        'Destination Port', 'Packet Time', 'Payload Hex', 'Note'
    ]
    with open(csv_file_name, 'w+', encoding='utf-8') as csv_file:
        csv_writter = csv.writer(csv_file)
        csv_writter.writerow(header)

def thread_read_csv_and_analysize(csv_file_name: str, time_wait: float):
    '''
        This thread will be used to read the csv file and analysize it
        to find the suspicious packet that try to exploit the CVE-2019-8942
    '''
    print('Starting thread read data from csv and analysize that data...')
    while True:
        if msvcrt.kbhit():
            char = msvcrt.getch().decode('utf-8')
            if char == 'q' or char == 'c':
                print('Exit...')
                break
        
        # if time.time() - time_wait > 6:
        thread_read_csv = True
        shutil.copyfile(csv_file_name, 'temp.csv')
        thread_read_csv = False
        with open('temp.csv', 'r+', encoding='utf-8') as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            csv_reader_list = list(csv_reader)
            if len(csv_reader_list) != 0:
                for i in range(1, len(csv_reader_list) - 2):
                    packet_summary = PacketUtil.parse_csv_data_to_dict(csv_reader_list[i])
                    matched = PacketUtil.is_packet_payload_suspicious(packet_summary)
                    if matched is not None:
                        f, t = matched.span()
                        print('Suspicious payload start from:', packet_summary['layer_string_payload'][f:t])

def thread_capture_and_write_csv(interface: str, csv_file_name: str, is_read_csv: bool):
    '''
        This thread will be used to capture the packet and write it's summary info
        into the csv file
    '''
    print('Starting thread capture packet and write it in csv file...')
    # Initial live capture
    capture = pyshark.LiveCapture(
        interface=interface
    )
    # Capturing packet...
    for packet in capture.sniff_continuously():
        if msvcrt.kbhit():
            char = msvcrt.getch().decode('utf-8')
            if char == 'q' or char == 'c':
                print('Exit...')
                break

        packet_summary = PacketUtil.summary_data_in_packet(packet, is_decode_hex_payload=True)
        
        if packet_summary is not None and is_read_csv is not True:
            if 'layer_string_payload' in packet_summary:
                del packet_summary['layer_string_payload']
            with open(csv_file_name, 'a+', encoding='utf-8') as csv_file:
                csv_writter = csv.writer(csv_file)
                csv_writter.writerow([packet_summary[key] for key in packet_summary])
    
    pyshark.capture.capture.StopCapture()

def main():
    '''
        Main function
    '''
    # CSV file name
    output_file_name = argv[1] + '.csv' if len(argv) == 2 else "output.csv"

    # Select network interface
    interfaces = SystemHelpers.get_interfaces()
    for i in range(len(interfaces)):
        print(str(i + 1) + '.', interfaces[i])
    selected = False
    selected_int = 0
    while selected is False:
        selected_int = input('Choose interfaces: ')
        selected = True if selected_int.isdigit() is True and int(selected_int) > 0 and int(selected_int) <= len(interfaces) else False
    
    reset_csv_file(output_file_name)

    # Thread capture packet and write packet to csv
    t_capture_and_write_csv = threading.Thread(
        target=thread_capture_and_write_csv,
        args=[interfaces[int(selected_int) - 1], output_file_name, thread_read_csv]
    )

    # Thread read packet from csv and analysize it
    t_read_csv_and_analysize = threading.Thread(
        target=thread_read_csv_and_analysize,
        args=[output_file_name, time.time()]
    )

    t_capture_and_write_csv.start()
    t_read_csv_and_analysize.start()
    
    t_capture_and_write_csv.join()
    t_read_csv_and_analysize.join()
    

if __name__ == '__main__':
    main()