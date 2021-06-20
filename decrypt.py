from lookup import (
                        MUL9, 
                        MUL11, 
                        MUL13, 
                        MUL14, 
                        S_BOX_INVERSE, 
                        AES_MSG_BLK_SIZE_BYTE, 
                        NUM_OF_ROUNDS
                        )

from key import key_expansion

from encrypt import add_round_key

mul9 = lambda hex_num : int(MUL9[int(hex_num,16)], 16)      #09
mul11 = lambda hex_num : int(MUL11[int(hex_num,16)], 16)    #0B
mul13 = lambda hex_num : int(MUL13[int(hex_num,16)], 16)    #0D
mul14 = lambda hex_num : int(MUL14[int(hex_num,16)], 16)    #0E

def rev_mix_columns(shift_row_box):
    '''
        This is the inverse matrix for mix columns.
        Mix matrix - 
        ---------------------
        | 0E | 0B | 0D | 09 |
        ---------------------
        | 09 | 0E | 0B | 0D |
        ---------------------
        | 0D | 09 | 0E | 0B |
        ---------------------
        | 0B | 0D | 09 | 0E |
        ---------------------
        OR
        Mix matrix - 
        ---------------------
        | 14 | 11 | 13 | 09 |
        ---------------------
        | 09 | 14 | 11 | 13 |
        ---------------------
        | 13 | 09 | 14 | 11 |
        ---------------------
        | 11 | 13 | 09 | 14 |
        ---------------------
    '''
    mix_column_state = [None] * AES_MSG_BLK_SIZE_BYTE

    mix_column_state[0] = hex(mul14(shift_row_box[0]) ^ mul11(shift_row_box[1]) ^ mul13(shift_row_box[2]) ^ mul9(shift_row_box[3]))
    mix_column_state[1] = hex(mul9(shift_row_box[0]) ^ mul14(shift_row_box[1]) ^ mul11(shift_row_box[2]) ^ mul13(shift_row_box[3]))
    mix_column_state[2] = hex(mul13(shift_row_box[0]) ^ mul9(shift_row_box[1]) ^ mul14(shift_row_box[2]) ^ mul11(shift_row_box[3]))
    mix_column_state[3] = hex(mul11(shift_row_box[0]) ^ mul13(shift_row_box[1]) ^ mul9(shift_row_box[2]) ^ mul14(shift_row_box[3]))

    mix_column_state[4] = hex(mul14(shift_row_box[4]) ^ mul11(shift_row_box[5]) ^ mul13(shift_row_box[6]) ^ mul9(shift_row_box[7]))
    mix_column_state[5] = hex(mul9(shift_row_box[4]) ^ mul14(shift_row_box[5]) ^ mul11(shift_row_box[6]) ^ mul13(shift_row_box[7]))
    mix_column_state[6] = hex(mul13(shift_row_box[4]) ^ mul9(shift_row_box[5]) ^ mul14(shift_row_box[6]) ^ mul11(shift_row_box[7]))
    mix_column_state[7] = hex(mul11(shift_row_box[4]) ^ mul13(shift_row_box[5]) ^ mul9(shift_row_box[6]) ^ mul14(shift_row_box[7]))

    mix_column_state[8] = hex(mul14(shift_row_box[8]) ^ mul11(shift_row_box[9]) ^ mul13(shift_row_box[10]) ^ mul9(shift_row_box[11]))
    mix_column_state[9] = hex(mul9(shift_row_box[8]) ^ mul14(shift_row_box[9]) ^ mul11(shift_row_box[10]) ^ mul13(shift_row_box[11]))
    mix_column_state[10] = hex(mul13(shift_row_box[8]) ^ mul9(shift_row_box[9]) ^ mul14(shift_row_box[10]) ^ mul11(shift_row_box[11]))
    mix_column_state[11] = hex(mul11(shift_row_box[8]) ^ mul13(shift_row_box[9]) ^ mul9(shift_row_box[10]) ^ mul14(shift_row_box[11]))

    mix_column_state[12] = hex(mul14(shift_row_box[12]) ^ mul11(shift_row_box[13]) ^ mul13(shift_row_box[14]) ^ mul9(shift_row_box[15]))
    mix_column_state[13] = hex(mul9(shift_row_box[12]) ^ mul14(shift_row_box[13]) ^ mul11(shift_row_box[14]) ^ mul13(shift_row_box[15]))
    mix_column_state[14] = hex(mul13(shift_row_box[12]) ^ mul9(shift_row_box[13]) ^ mul14(shift_row_box[14]) ^ mul11(shift_row_box[15]))
    mix_column_state[15] = hex(mul11(shift_row_box[12]) ^ mul13(shift_row_box[13]) ^ mul9(shift_row_box[14]) ^ mul14(shift_row_box[15]))

    # print('Mix Column ', mix_column_state)

    return mix_column_state

def rev_sub_bytes(state):
    '''
        SubBytes replaces each byte from the message block to the corresponding value in S-box.
        S-Box is a 256 byte char set.
    '''
    # Initialize new sub byte state box
    sub_bytes_state = [None] * AES_MSG_BLK_SIZE_BYTE

    # Replace values from the S-Box
    for _ in range(AES_MSG_BLK_SIZE_BYTE):
        sub_bytes_state[_] = S_BOX_INVERSE[int(state[_], 16)]

    # print('Sub-Key', sub_bytes_state)
    return sub_bytes_state

def rev_shift_rows(msg_block: list) ->list:
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
        | 13 | 01 | 05 | 09 |         --> Shit row by one
        ---------------------
        | 10 | 14 | 02 | 06 |         --> Shift row by two
        ---------------------
        | 07 | 11 | 15 | 03 |         --> Shift row by three
        ---------------------

    '''
    # Initialize the new shifted row block
    shift_row_box = [None] * AES_MSG_BLK_SIZE_BYTE

    shift_row_box[0] = msg_block[0]
    shift_row_box[1] = msg_block[13]
    shift_row_box[2] = msg_block[10]
    shift_row_box[3] = msg_block[7]

    shift_row_box[4] = msg_block[4]
    shift_row_box[5] = msg_block[1]
    shift_row_box[6] = msg_block[14]
    shift_row_box[7] = msg_block[11]

    shift_row_box[8] = msg_block[8]
    shift_row_box[9] = msg_block[5]
    shift_row_box[10] = msg_block[2]
    shift_row_box[11] = msg_block[15]

    shift_row_box[12] = msg_block[12]
    shift_row_box[13] = msg_block[9]
    shift_row_box[14] = msg_block[6]
    shift_row_box[15] = msg_block[3]

    # print('Shift Rows', shift_row_box)

    return shift_row_box

def rijndael_decryption(cipher_block, key):
    plain_text_block = []

    for i in range(0, len(cipher_block), AES_MSG_BLK_SIZE_BYTE):
        state = cipher_block[i:i+AES_MSG_BLK_SIZE_BYTE]

        # print('\nRound - ', 10,'\n-----------')
        # print('Input - ', state)

        state = add_round_key(state, key[-AES_MSG_BLK_SIZE_BYTE:])
        state = rev_shift_rows(state)
        state = rev_sub_bytes(state)

        for round in range(NUM_OF_ROUNDS-1, 0, -1):
            # print('\nRound - ', round)
            # print('-------------')
            # print('Input - ', state)
            state = add_round_key(state, key[AES_MSG_BLK_SIZE_BYTE * round:])
            state = rev_mix_columns(state)
            state = rev_shift_rows(state)
            state = rev_sub_bytes(state)
            
        # The final round
        # print('\nFinal Round\n-------------')
        state = add_round_key(state, key)

        plain_text_block += state
    
    return plain_text_block


def decryptAES(cipher_text : str):

    # Initialise Cipher Block
    cipher_block = []

    # Convert cipher text to byte block by creating a list of hex values
    for _  in range(0, len(cipher_text), 2):
        cipher_block += ['0x'+cipher_text[_:_+2]]

    # Get key for decryption. This should be the same key used for encryption
    key = key_expansion()

    plain_text_block = rijndael_decryption(cipher_block, key)
    
    try:
        # Get padding length if it was added
        end_byte = int(plain_text_block[-1], 16)
        if  16 > end_byte > 0:
            plain_text_block = plain_text_block[:-end_byte]

        # Get Text
        # Get rid of '0x'
        plain_text = [plain_text_block[2:] for plain_text_block in plain_text_block]

        # Add 0 for single char
        plain_text = ['0'+plain_text if len(plain_text)==1 else plain_text for plain_text in plain_text]
        plain_text = ''.join(plain_text)

        # Convert to Text
        plain_text = bytes.fromhex(plain_text).decode('utf-8')
    except:
        print('Failed to Decrypt Text.')
        plain_text = None

    return plain_text