from cbc import *

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

print("cipher before modification: " + str(bin(cipher[0])))

cipher[1] = cipher[1] ^ plain[1] ^ plain_1_goal

print("cipher after modification : " + str(bin(cipher[0])))

# ----------------------------------------------------------------------
# receiver
# ----------------------------------------------------------------------

plain_rec = cbc_decrypt(cipher, KEY)
print("decryption done by receiver: " + str([ bin(p) for p in plain_rec ]))

if plain_rec[1] == plain_1_goal: print("plain[1] successfully manipulated")