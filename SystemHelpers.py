import psutil
import binascii
import codecs
import re

def calculate_time_execute(callback):
    start_time = time.time()
    if callback is not None and type(callback).__name__ == 'function':
        callback()
    else:
        raise TypeError('Callback is not function')
    print(f'\n--- {(time.time() - start_time)} seconds ---')


def get_interfaces():
    addrs = psutil.net_if_addrs()
    interfaces = [key for key in addrs.keys()]
    return interfaces

def convert_hex_payload_to_string(hex_str: str):
    """
    'backslashreplace'  - uses a backslash instead of the character that could not be encoded
    'ignore'    - ignores the characters that cannot be encoded
    'namereplace'   - replaces the character with a text explaining the character
    'strict'    - Default, raises an error on failure
    'replace'   - replaces the character with a questionmark
    'xmlcharrefreplace' - replaces the character with an xml character
    """
    data_bytes = binascii.unhexlify(hex_str.replace(':', ''))
    data_decode = None
    try:    
        data_decode = codecs.decode(data_bytes, encoding='unicode_escape', errors='replace')
        data_decode = re.sub('\\s+', '', data_decode)
    except:
        data_decode = 'Unable to decode hex data'
    return data_decode.strip()

if __name__ == '__main__':
    get_interfaces()