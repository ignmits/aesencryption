from decrypt import decryptAES
from encrypt import encryptAES

__name__ == '__init__'

input_message = input('Enter message to encrypt : ')

ciphertext = encryptAES(input_message)

print('Input Message - ',ciphertext)

plain_text = decryptAES(ciphertext)

print('Plain Text -',plain_text)

if plain_text == input_message:
    print('AES Encryption working.')