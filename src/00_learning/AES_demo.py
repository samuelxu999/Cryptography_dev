'''
========================
This model demonstrate AES encryption
========================
'''
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

## set key for encryption
key = get_random_bytes(16)

## AES Encryption
cipher = AES.new(key, AES.MODE_EAX)
nonce = cipher.nonce
message = "This is a message for AES encryption."
ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
print("\nAES Encryption")
print("Message:", message)
print("Output ciphertext:", ciphertext)

## AES Decryption
print("\nAES Decryption")
cipher = AES.new(key, AES.MODE_EAX, nonce)
plaintext = cipher.decrypt_and_verify(ciphertext, tag)
print("Output plain text:", plaintext.decode('utf-8'))