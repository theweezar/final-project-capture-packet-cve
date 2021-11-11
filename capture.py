import SystemHelpers
import pyshark
import msvcrt
from os.path import exists
from pyshark.packet.packet import Packet

def parse_packet(packet: Packet):
    try:
        protocol = packet.transport_layer
        source_address = packet.ip.src
        source_port = packet[packet.transport_layer].srcport
        destination_address = packet.ip.dst
        destination_port = packet[packet.transport_layer].dstport 
        packet_time = '{:%Y-%b-%d %H:%M:%S}'.format(packet.sniff_time)
        return f"{protocol},{source_address},{source_port},{destination_address},{destination_port},{packet_time}"
    except:
        pass

def main():
    interfaces = SystemHelpers.get_interfaces()
    for i in range(len(interfaces)):
        print(str(i + 1) + ".", interfaces[i])

    selected = False
    selected_int = 0
    while selected is False:
        selected_int = input("Choose interfaces: ")
        selected = True if selected_int.isdigit() is True and int(selected_int) > 0 and int(selected_int) <= len(interfaces) else False

    capture = pyshark.LiveCapture(
        interface=interfaces[int(selected_int) - 1]
    )

    for packet in capture.sniff_continuously():
        print(parse_packet(packet))
        if msvcrt.kbhit():
            char = msvcrt.getch().decode("utf-8")
            if char == "q" or char == "c":
                print("Exit...")
                break

    pyshark.capture.capture.StopCapture()
    

if __name__ == "__main__":
    main()