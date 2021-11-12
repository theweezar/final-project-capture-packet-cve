import SystemHelpers
import pyshark
import msvcrt
from PacketUtil import *

def main():
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

    for packet in capture.sniff_continuously():
        packet_analysis(packet)
        if msvcrt.kbhit():
            char = msvcrt.getch().decode('utf-8')
            if char == 'q' or char == 'c':
                print('Exit...')
                break

    pyshark.capture.capture.StopCapture()
    

if __name__ == '__main__':
    main()