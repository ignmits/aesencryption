from lookup import S_BOX, R_CON, KEY_BYTE_SIZE, NUM_OF_ROUNDS, KEY_SIZE
from randomise import generate_128bit_key

def display(key):
    format(ord("c"), "x")
    for i in range(int(len(key)/4)):
        print(key[i+0], '\t', key[i+4], '\t',key[i+8], '\t',key[i+12], '\t')
    print('\n')

def rot_word(key_state):
    '''
        This is to rotate the last column of the key by 1 byte.
        i.e. 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 should be represented as
        ---------------------
        | 00 | 04 | 08 | 12 |
        ---------------------
        | 01 | 05 | 09 | 13 |
        ---------------------
        | 02 | 06 | 10 | 14 |
        ---------------------
        | 03 | 07 | 11 | 15 |
        ---------------------

        The last column is shifted by one row to return below

        ------
        | 13 |
        ------
        | 14 |
        ------
        | 15 |
        ------
        | 12 |
        ------
    '''

    rot_word_key = [None] * 4
    # print('Pre-ROT', key_state[12:16])
    rot_word_key[0] = key_state[13]
    rot_word_key[1] = key_state[14]
    rot_word_key[2] = key_state[15]
    rot_word_key[3] = key_state[12]
    # print('Post-ROT', rot_word_key)
    return rot_word_key

# def hexor(*args):
#     xor_val = int(args[0],16)
#     for _ in range(1, len(args)):
#         xor_val = xor_val ^ int(args[_],16)
#     return hex(xor_val)

sbox_val = lambda hex_val: S_BOX[int(hex_val, 16)]

def sub_byte(rot_word_key):
    '''
        Replace every byte of the input by the byte at that place in the nonlinear S-box
    '''
    # print('Pre-sub Byte', rot_word_key)
    sub_byte_key = [None] * 4

    sub_byte_key[0] = sbox_val(rot_word_key[0])
    sub_byte_key[1] = sbox_val(rot_word_key[1])
    sub_byte_key[2] = sbox_val(rot_word_key[2])
    sub_byte_key[3] = sbox_val(rot_word_key[3])
    # print('Post-sub Byte', rot_word_key)
    del rot_word_key
    return sub_byte_key

def xor_rcon_round(key_state, sub_byte_key, round):
    '''
        Adding more confusion to the encryption key.
        XOR given encryption key with the subByte and round constants from the lookup
    '''

    # print('Pre - XOR RCON')
    # display(key_state)

    key_state[0] = hex(int(key_state[0], 16) ^ int(sub_byte_key[0], 16) ^ int(R_CON[round], 16))
    key_state[1] = hex(int(key_state[1], 16) ^ int(sub_byte_key[1], 16) ^ int('0x00', 16))
    key_state[2] = hex(int(key_state[2], 16) ^ int(sub_byte_key[2], 16) ^ int('0x00', 16))
    key_state[3] = hex(int(key_state[3], 16) ^ int(sub_byte_key[3], 16) ^ int('0x00', 16))

    key_state[4] = hex(int(key_state[4], 16) ^ int(key_state[0], 16))
    key_state[5] = hex(int(key_state[5], 16) ^ int(key_state[1], 16))
    key_state[6] = hex(int(key_state[6], 16) ^ int(key_state[2], 16))
    key_state[7] = hex(int(key_state[7], 16) ^ int(key_state[3], 16))

    key_state[8] = hex(int(key_state[8], 16) ^ int(key_state[4], 16))
    key_state[9] = hex(int(key_state[9], 16) ^ int(key_state[5], 16))
    key_state[10] = hex(int(key_state[10], 16) ^ int(key_state[6], 16))
    key_state[11] = hex(int(key_state[11], 16) ^ int(key_state[7], 16))

    key_state[12] = hex(int(key_state[12], 16) ^ int(key_state[8], 16))
    key_state[13] = hex(int(key_state[13], 16) ^ int(key_state[9], 16))
    key_state[14] = hex(int(key_state[14], 16) ^ int(key_state[10], 16))
    key_state[15] = hex(int(key_state[15], 16) ^ int(key_state[11], 16))

    # print('Post - XOR RCON')
    # display(key_state)
    return key_state

def get_key_block(key, block_size):
    '''
        Convert key into a 16 byte block.
        This also adds padding if block size is smaller than 16 byte.
        Key size bigger than 16 byte will ignore trailing chars
    '''
    # Convert key in to hex
    key_block = [hex(ord(key)) for key in key]

    # Validate size and add padding
    if len(key_block) < block_size:
        size_diff = block_size - len(key_block)
        key_block += [hex(size_diff)] * size_diff
    elif len(key_block) > block_size:
        key_block = key_block[:block_size]

    return key_block

def key_expansion():
    '''
        This function creates and returns the key for encryption.
        The key will be of size 128 bit.
    '''
    # Create key
    if KEY_SIZE == 128:
        key = generate_128bit_key()
    elif KEY_SIZE == 192:
        # key = generate_192bit_key() # If someone gets enthusiastic in the future can implement this.
        pass
    elif KEY_SIZE == 256:
        # key = generate_256bit_key() # If someone gets enthusiastic in the future can implement this.
        pass

    # print('Key - ', 0)
    # Prepare key block
    key_state = get_key_block(key, KEY_BYTE_SIZE)

    # display(key_state)

    # At the end, this should produce a 176 byte key for 128 bit encryption.
    for round in range(NUM_OF_ROUNDS):
        # print('Key - ', round+1)
        rot_word_key = rot_word(key_state[round * KEY_BYTE_SIZE:KEY_BYTE_SIZE + (KEY_BYTE_SIZE * round)])
        sub_byte_key = sub_byte(rot_word_key)
        rcon_key = xor_rcon_round(key_state[round * KEY_BYTE_SIZE:KEY_BYTE_SIZE + (KEY_BYTE_SIZE * round)], sub_byte_key, round+1)
        key_state += rcon_key

    # print(key_state)
    return key_state