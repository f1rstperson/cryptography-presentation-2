from cbc import *

# Allow for anonymous object creation
Object = lambda **kwargs: type("Object", (), kwargs)

class CBCGadget:
    position: int
    plain_1: int
    cipher_0: int
    cipher_1: int

def replace_plaintext(
        cipher: List[int], new_plaintext: str,
        gadget: CBCGadget,
) -> None:
    """
    Every step in cbc looks like

                     plain[i] = cipher[i] ^ decrypt(cipher[i + 1])           (1)

    Taking the inverse of XOR, we can therefore assert that

                     decrypt(cipher[i + 1]) = plain[i] ^ cipher[i].          (2)

    XORing any value with itself returns 0. Therefore

                  0 = decrypt(cipher[i + 1]) ^ (plain[i] ^ cipher[i]).       (3)

    XORing 0 with any value returns that value. Therefore

                     new_plaintext = decrypt(cipher[i + 1])
                                     ^ (plain[i] ^ cipher[i])                (4)
                                     ^ new_plaintext.

    Combining (1) and (4) (and knowing that XOR is commutative), we can now
    manipulate cipher[i] to be `(plain[i] ^ cipher[i]) ^ new_plaintext`.
    """

    cipher[gadget.position] = gadget.plain_1 ^ gadget.cipher_0 ^ new_plaintext
    return cipher



"""
This file demonstrates the maleability of the CBC mode of operation in its most
simple form.
"""

KEY = 187
print("")

# ----------------------------------------------------------------------
# sender
# ----------------------------------------------------------------------
plain = [0b010111100101, 0b110010100010, 0b000000000000]

cipher = cbc_encrypt(plain, KEY)

# ----------------------------------------------------------------------
# attacker
# known: plain[1], cipher
# ----------------------------------------------------------------------

plain_1_goal          = 0b101010101010

print("cipher before modification: " + str(bin(cipher[1])))

# cipher[1] = cipher[1] ^ plain[1] ^ plain_1_goal
replace_plaintext(cipher, plain_1_goal, Object(
    position = 1, cipher_0 = cipher[1],
    cipher_1 = cipher[2], plain_1 = plain[1]
))

print("cipher after modification : " + str(bin(cipher[1])))

# ----------------------------------------------------------------------
# receiver
# ----------------------------------------------------------------------

plain_rec = cbc_decrypt(cipher, KEY)
print("decryption done by receiver: " + str([ bin(p) for p in plain_rec ]))

if plain_rec[1] == plain_1_goal: print("plain[1] successfully manipulated")