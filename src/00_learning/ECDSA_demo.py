'''
========================
This model demonstrate signature uasages by usng the ECDSA with the curve secp256k1
========================
'''
import ecdsa
from ecdsa import BadSignatureError
from hashlib import sha256

# SECP256k1 is the Bitcoin elliptic curve
PUK = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=sha256) # The default is sha1
PRK = PUK.get_verifying_key()

#ECDSA Message Signing
print("\nECDSA Message Signing")
message = "Signing Message using ECDSA"
signMessage = PUK.sign(message.encode('utf-8'))
print("Message:", message)
print("Output Signature:")
print(signMessage)

#ECDSA Verify Signature
print("\nECDSA Verify Signature")
try:
	valid = PRK.verify(signMessage, message.encode('utf-8')) # True
	print("Valid Signature?", valid)
except BadSignatureError:
    print("Incorrect signature")

#ECDSA Verify Signature - − If Tampered
print("\nECDSA Verify Signature if Tampered")
tam_message = "Tampered message"
print("Message:", tam_message)
try:
	valid = PRK.verify(signMessage, b"{tam_message}") # False
	print("Tampered?", valid)
except BadSignatureError:
    print("Incorrect signature")