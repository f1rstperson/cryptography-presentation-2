from typing import List
from random import randint
import math

CBC_BLOCK_SIZE = 64
CBC_INITIALIZATION_VECTOR = 0b10101110100100111110001001110001
# CBC_INITIALIZATION_VECTOR = randint(0, CBC_BLOCK_SIZE)

if 2**CBC_BLOCK_SIZE < CBC_INITIALIZATION_VECTOR:
    raise Exception("CBC_BLOCK_SIZE < CBC_INITIALIZATION_VECTOR")

def text_to_ascii(text: str) -> int:
    """
    Return an ascii representation of `text`. Example:
    ord('A') = 65 = 0b1000001, ord('B') = 66 = 0b1000010
    text_to_ascii('AB') = 0b1000001 padded and concatenated with 0b1000010
                        = 0b100000101000010 = 16706
    """
    return int(''.join("{:08b}".format(ord(c)) for c in text), 2)

def ascii_to_text(ascii: int) -> str:
    """
    text_to_ascii(ascii_to_text('any_text')) = 'any_text'
    """
    ascii_str = ("{:0" + str(math.ceil(ascii.bit_length() / 8) * 8) + "b}").format(ascii)
    text = [
        chr(int(ascii_str[i:i + 8], 2)) for i in range(0, len(ascii_str), 8)
    ]
    return ''.join(text)

def very_secure_encryption(plain: int, key) -> int:
    """
    A very secure encrption algorithm.
    """
    return plain + key % 2**CBC_BLOCK_SIZE

def very_secure_decryption(cipher: int, key) -> int:
    """
    very_secure_encryption(very_secure_decryption(any_int, mykey), mykey) = any_int
    """
    return cipher - key % 2**CBC_BLOCK_SIZE

def _cbc_split(unsplit: int) -> List[int]:
    """
    Split `unsplit` into blocks of size < CBC_BLOCK_SIZE
    """
    unsplit_str = (
        "{:0" + str(math.ceil(
            unsplit.bit_length() / CBC_BLOCK_SIZE
        ) * CBC_BLOCK_SIZE) + "b}"
    ).format(unsplit)
    return [
        int(unsplit_str[i:i + CBC_BLOCK_SIZE], 2) for i in range(0, len(unsplit_str), CBC_BLOCK_SIZE)
    ]

def cbc_encrypt_string(plain: str, key: int) -> List[int]:
    """
    Encrypt a string with CBC and return the list of encrypted blocks.
    """
    return cbc_encrypt(_cbc_split(text_to_ascii(plain)), key)

def cbc_decrypt_string(cipher: List[int], key: int) -> List[int]:
    """
    Decrypt a list of CBC encrypted blocks into a string.
    """
    return "".join([ascii_to_text(p) for p in cbc_decrypt(cipher, key)])

def cbc_encrypt(plain: List[int], key: int) -> List[int]:
    """
    Encrypt blocks specified in `plain` and return the encrypted blocks. Uses
    the CBC mode of operation - see
    https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
    """
    initialization_vector = CBC_INITIALIZATION_VECTOR
    cipher = [ very_secure_encryption(plain[0] ^ initialization_vector, key) ]
    for i in range(1, len(plain)):
        if plain[i] > 2**CBC_BLOCK_SIZE:
            raise Exception("invalid block size [%d]: (%d)" % (i, plain[i]))
        cipher.append(very_secure_encryption(plain[i] ^ cipher[i - 1], key))
    return cipher

def cbc_decrypt(cipher: List[int], key: int) -> List[int]:
    """
    Decrypt blocks specified in `plain` and return the decrypted blocks. Uses
    the CBC mode of operation - see
    https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
    """
    initialization_vector = CBC_INITIALIZATION_VECTOR
    plain = [ very_secure_decryption(cipher[0], key) ^ initialization_vector ]
    for i in range(1, len(cipher)):
        if cipher[i] > 2**CBC_BLOCK_SIZE:
            raise Exception("invalid block size [%d]: (%d)" % (i, cipher[i]))
        plain.append(very_secure_decryption(cipher[i], key) ^ cipher[i - 1])
    return plain

# print(bin(text_to_ascii("BB")))
# print(ascii_to_text(text_to_ascii("jaja i bims")))
# print(cbc_encrypt_string("hi i bims jajajja nenene", 13))
print(cbc_decrypt_string(cbc_encrypt_string("AAhi i    BB bims jajajja nenene", 13), 13))