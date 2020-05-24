from cbc import *

# print(bin(text_to_ascii("BB")))
# print(ascii_to_text(text_to_ascii("jaja i bims"))) cbc_split
# print(cbc_encrypt_string("hi i bims jajajja nenene", 13))
print(cbc_decrypt_string(cbc_encrypt_string('<img ignore="', 13), 13))
