'''
========================
This model demonstrate RSA encryption
========================
'''
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

##------------------- generate key pair ---------------
## get security parameters
key = RSA.generate(2048)

## create private key
private_key = key.export_key()
## save private key at local
file_out = open("private.pem", "wb")
file_out.write(private_key)
file_out.close()

## create public key
public_key = key.publickey().export_key()
## save public key and send to receiver
file_out = open("receiver.pem", "wb")
file_out.write(public_key)
file_out.close()

##------------------- Encryption ---------------
## Set dummy data for encryption
data = "This is a confidential messages.".encode("utf-8")
file_out = open("encrypted_data.bin", "wb")

## get public key for recipient
recipient_key = RSA.import_key(open("receiver.pem").read())
session_key = get_random_bytes(16)

## Encrypt the session key with the public RSA key
cipher_rsa = PKCS1_OAEP.new(recipient_key)
enc_session_key = cipher_rsa.encrypt(session_key)

# Encrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(data)
[ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
file_out.close()

##------------------- Decryption ---------------
## get private key
private_key = RSA.import_key(open("private.pem").read())

## readin encrypted data
file_in = open("encrypted_data.bin", "rb")
enc_session_key, nonce, tag, ciphertext = \
   [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]
file_in.close()

## Decrypt the session key with the private RSA key
cipher_rsa = PKCS1_OAEP.new(private_key)
session_key = cipher_rsa.decrypt(enc_session_key)

## Decrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
data = cipher_aes.decrypt_and_verify(ciphertext, tag)
print(data.decode("utf-8"))
