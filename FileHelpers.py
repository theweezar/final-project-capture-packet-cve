
def write(file_name: str, input_data: str):
    input_file = open(file_name, 'w+')
    input_file.write(input_data)
    input_file.close()

def append(file_name: str, input_data: str):
    input_file = open(file_name, 'a+')
    input_file.write(input_data)
    input_file.close()

def read(file_name: str):
    '''Read a file and return a result with a status number: 0: successfully, 1: failed'''
    output_string = ''
    status = 0
    try:
        output_file = open(file_name, 'r')
        output_string = output_file.read()
        output_file.close()
    except:
        status = 1
    return output_string, status

def write_bin(file_name: str, input_data: bytes):
    input_file = open(file_name, 'wb+')
    input_file.write(input_data)
    input_file.close()


def read_bin(file_name: str):
    '''Read a binary file and return a result with a status number: 0: successfully, 1: failed'''
    output_bin = b''
    status = 0
    try:
        output_file = open(file_name, 'rb')
        output_bin = output_file.read()
        output_file.close()
    except:
        status = 1
    return output_bin, status

if __name__ == '__main__':
    a = 0
    