from cbc import *

# print(bin(text_to_ascii("BB")))
# print(ascii_to_text(text_to_ascii("jaja i bims"))) cbc_split
# print(cbc_encrypt_string("hi i bims jajajja nenene", 13))
# print(cbc_decrypt_string(cbc_encrypt_string(open("res/sample_message.txt").read(), 872), 872))

key = 872 # both parties have agreed to this key over some protocol

# The sender encrypts this message
with open("res/sample_message.txt") as f:
    cipher = cbc_encrypt_string(f.read(), key)

# The receiver then opens up he message, detects an s/mime header and attempts
# decryption. It is important to note here, that s/mime includes the original
# "Content-Type" header in the encrypted message.
with open("res/simplified_s_mime_mail.txt") as f:
    message = f.read()
    print(message.replace(cipher, cbc_decrypt_string(cipher, key)))
