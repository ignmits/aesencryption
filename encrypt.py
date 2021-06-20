from lookup import (
        S_BOX, 
        MUL2, 
        MUL3, 
        AES_MSG_BLK_SIZE_BYTE, 
        NUM_OF_ROUNDS
    )
from key import key_expansion

mul1 = lambda hex_num : int(hex_num,16)
mul2 = lambda hex_num : int(MUL2[int(hex_num,16)], 16)
mul3 = lambda hex_num : int(MUL3[int(hex_num,16)], 16)

def mix_columns(shift_row_box):
    '''
        Mix matrix - 
        ---------------------
        | 02 | 03 | 01 | 01 |
        ---------------------
        | 01 | 02 | 03 | 01 |
        ---------------------
        | 01 | 01 | 02 | 03 |
        ---------------------
        | 03 | 01 | 01 | 02 |
        ---------------------
    '''
    mix_column_state = [None] * AES_MSG_BLK_SIZE_BYTE

    mix_column_state[0] = hex(mul2(shift_row_box[0]) ^ mul3(shift_row_box[1]) ^ mul1(shift_row_box[2]) ^ mul1(shift_row_box[3]))
    mix_column_state[1] = hex(mul1(shift_row_box[0]) ^ mul2(shift_row_box[1]) ^ mul3(shift_row_box[2]) ^ mul1(shift_row_box[3]))
    mix_column_state[2] = hex(mul1(shift_row_box[0]) ^ mul1(shift_row_box[1]) ^ mul2(shift_row_box[2]) ^ mul3(shift_row_box[3]))
    mix_column_state[3] = hex(mul3(shift_row_box[0]) ^ mul1(shift_row_box[1]) ^ mul1(shift_row_box[2]) ^ mul2(shift_row_box[3]))

    mix_column_state[4] = hex(mul2(shift_row_box[4]) ^ mul3(shift_row_box[5]) ^ mul1(shift_row_box[6]) ^ mul1(shift_row_box[7]))
    mix_column_state[5] = hex(mul1(shift_row_box[4]) ^ mul2(shift_row_box[5]) ^ mul3(shift_row_box[6]) ^ mul1(shift_row_box[7]))
    mix_column_state[6] = hex(mul1(shift_row_box[4]) ^ mul1(shift_row_box[5]) ^ mul2(shift_row_box[6]) ^ mul3(shift_row_box[7]))
    mix_column_state[7] = hex(mul3(shift_row_box[4]) ^ mul1(shift_row_box[5]) ^ mul1(shift_row_box[6]) ^ mul2(shift_row_box[7]))

    mix_column_state[8] = hex(mul2(shift_row_box[8]) ^ mul3(shift_row_box[9]) ^ mul1(shift_row_box[10]) ^ mul1(shift_row_box[11]))
    mix_column_state[9] = hex(mul1(shift_row_box[8]) ^ mul2(shift_row_box[9]) ^ mul3(shift_row_box[10]) ^ mul1(shift_row_box[11]))
    mix_column_state[10] = hex(mul1(shift_row_box[8]) ^ mul1(shift_row_box[9]) ^ mul2(shift_row_box[10]) ^ mul3(shift_row_box[11]))
    mix_column_state[11] = hex(mul3(shift_row_box[8]) ^ mul1(shift_row_box[9]) ^ mul1(shift_row_box[10]) ^ mul2(shift_row_box[11]))

    mix_column_state[12] = hex(mul2(shift_row_box[12]) ^ mul3(shift_row_box[13]) ^ mul1(shift_row_box[14]) ^ mul1(shift_row_box[15]))
    mix_column_state[13] = hex(mul1(shift_row_box[12]) ^ mul2(shift_row_box[13]) ^ mul3(shift_row_box[14]) ^ mul1(shift_row_box[15]))
    mix_column_state[14] = hex(mul1(shift_row_box[12]) ^ mul1(shift_row_box[13]) ^ mul2(shift_row_box[14]) ^ mul3(shift_row_box[15]))
    mix_column_state[15] = hex(mul3(shift_row_box[12]) ^ mul1(shift_row_box[13]) ^ mul1(shift_row_box[14]) ^ mul2(shift_row_box[15]))

    # print('Mix Column ', mix_column_state)

    return mix_column_state

def sub_bytes(state):
    '''
        SubBytes replaces each byte from the message block to the corresponding value in S-box.
        S-Box is a 256 byte char set.
    '''
    # Initialize new sub byte state box
    sub_bytes_state = [None] * AES_MSG_BLK_SIZE_BYTE

    # Replace values from the S-Box
    for _ in range(AES_MSG_BLK_SIZE_BYTE):
        sub_bytes_state[_] = S_BOX[int(state[_], 16)]

    # print('Sub-Key', sub_bytes_state)
    return sub_bytes_state

def shift_rows(msg_block: list) ->list:
    '''
        This method will shift rows.
        Each will be shifted in the order of 0,1,2,3
        The message is to be considered in the form of block trasposed.
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

        This is then shifted to give

        ---------------------
        | 00 | 04 | 08 | 12 | 
        ---------------------
        | 05 | 09 | 13 | 01 |         --> Shit row by one
        ---------------------
        | 10 | 14 | 02 | 06 |         --> Shift row by two
        ---------------------
        | 15 | 03 | 07 | 11 |         --> Shift row by three
        ---------------------

    '''
    # Initialize the new shifted row block
    shift_row_box = [None] * AES_MSG_BLK_SIZE_BYTE

    shift_row_box[0] = msg_block[0]
    shift_row_box[1] = msg_block[5]
    shift_row_box[2] = msg_block[10]
    shift_row_box[3] = msg_block[15]

    shift_row_box[4] = msg_block[4]
    shift_row_box[5] = msg_block[9]
    shift_row_box[6] = msg_block[14]
    shift_row_box[7] = msg_block[3]

    shift_row_box[8] = msg_block[8]
    shift_row_box[9] = msg_block[13]
    shift_row_box[10] = msg_block[2]
    shift_row_box[11] = msg_block[7]

    shift_row_box[12] = msg_block[12]
    shift_row_box[13] = msg_block[1]
    shift_row_box[14] = msg_block[6]
    shift_row_box[15] = msg_block[11]

    # print('Shift Rows', shift_row_box)
    return shift_row_box

def add_round_key(state, round_key):
    '''
        This performs XOR operation on the message block with message block with shifted rows also called as round round_key
    '''
    # print('Key - ', round_key[:16])
    for _ in range(AES_MSG_BLK_SIZE_BYTE):
        # XOR each element of message block with the corresponding element of the round key provided
        # ^ is the XOR operator
        state[_] = hex(int(state[_], 16) ^ int(round_key[_], 16))
    
    # print('After mix - ', state)
    return state

def cms_padding(message: str):
    '''
        Check the size of the message block, it should be 128 bit long - 16 chars.
        Here we are using Cryptographic Message Syntax to pad messages shorter than 128 bits.

        Post padding return message in the form of state - as 16 byte blocks
    '''
    # convert message and key into string if not one
    message = str(message)

    # Get message length
    msg_length = len(message)

    # Get unicodes of message using ord functions
    msg_block = [hex(ord(msg)) for msg in message]

    # Get padding length to add padding
    if msg_length % 16 != 0:
        pad_len = AES_MSG_BLK_SIZE_BYTE - msg_length % 16
        msg_block += [hex(pad_len)] * pad_len

    # print(msg_block)
    return msg_block

def rijndael_encryption(message_byte, key):
    cipher_byte_block = []

    for i in range(0, len(message_byte), AES_MSG_BLK_SIZE_BYTE):
        # AES encrypts message blocks of size 128 bits / 16 byte onyl.
        # This needs to broken down into multiples of 16 Byte blocks and encrypted individually
        state = message_byte[i:i+AES_MSG_BLK_SIZE_BYTE]

        # print('\nRound - ', 0,'\n-----------')
        # print('Input - ', state)

        # This is Round 0
        state = add_round_key(state, key)

        # This is Round 1 to Round 9

        for round in range(1, NUM_OF_ROUNDS):
            # print('\nRound - ', round)
            # print('-------------')
            # print('Input - ', state)
            state = sub_bytes(state)
            state = shift_rows(state)
            state = mix_columns(state)
            state = add_round_key(state, key[AES_MSG_BLK_SIZE_BYTE * round:])

        # This is the final round 10
        # print('\nFinal Round\n-------------')
        state = sub_bytes(state)
        state = shift_rows(state)
        state = add_round_key(state, key[-AES_MSG_BLK_SIZE_BYTE:])

        cipher_byte_block += state
    return cipher_byte_block

def encryptAES(message : str):

    # Generate random key and expand it for encryption
    key = key_expansion()

    message_block = cms_padding(message)

    cipher_block = rijndael_encryption(message_block, key)

    # Convert byte cipher block to text
    # Get rid of '0x' from the byte
    cipher_text = [cipher_block[2:] for cipher_block in cipher_block]

    # Add 0 for single char
    cipher_text = ['0'+cipher_text if len(cipher_text)==1 else cipher_text for cipher_text in cipher_text]

    # Create final text
    cipher_text = ''.join(cipher_text)
    
    # print('\nEndrypted Text - ', cipher_text) 
    return cipher_text