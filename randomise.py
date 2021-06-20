import shutil
import socket
import getpass

def generate_128bit_key():
    '''
        Creates a 128 bit encryption key for this implementation. 
        This can me made more complex in the future by using randomness in the code.
    '''
    disk_size = shutil.disk_usage('/')
    disk_size = str(int(disk_size[0] / 11))
    user = getpass.getuser()[-4:]
    host = socket.gethostname()[4:]
    key = host + disk_size + host + user
    # print(key[:16])
    return key[:16]

def generate_192bit_key():
    '''
        Creates a 192 bit encryption key for this implementation.
        Beyond scope for now.
    '''
    pass

def generate_256bit_key():
    '''
        Creates a 256 bit encryption key for this implementation. 
        Beyond scope for now.
    '''
    pass