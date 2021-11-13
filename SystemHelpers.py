import time
import psutil
from Crypto.Util import number
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
    # os.system('netsh interface show interface')
    addrs = psutil.net_if_addrs()
    interfaces = [key for key in addrs.keys()]
    return interfaces

if __name__ == '__main__':
    get_interfaces()

def convert_hex_string_to_paragraph(hex_str: str):
    data_long = int(hex_str.replace(':', ''), 16)
    data_bytes = number.long_to_bytes(data_long)
    data_decode = None
    try:    
        data_decode = codecs.decode(data_bytes, encoding='unicode_escape', errors='replace')
        data_decode = re.sub('\\s+', '', data_decode)
    except:
        data_decode = 'Unable to decode hex data'
    return data_decode