import time
import os
import psutil

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