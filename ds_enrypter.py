import hashlib
import hmac
import base64

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random


delimiter = '=='

message = bytes("12:22:30:00,CannedBeans,12/05/15,12/01/15,2").encode('utf-8')

print('Plaintext Message:')
print(message)

message_hash = SHA256.new(message)
#print(message_hash)
s_private_key = RSA.importKey(open('private.pem').read())

signer = PKCS1_v1_5.new(s_private_key)
signature = signer.sign(message_hash)
#print('\nsignature '+signature)

#append signature to message
signed_message = message +delimiter+ signature
# print('\nsigned message\n')
# print(signed_message)

# generate one time session key
session_key = b'Sixteen byte key'

#Encrypt the Data with one-time session key
iv = Random.new().read(AES.block_size)
aes_cipher = AES.new(session_key, AES.MODE_CFB, iv)
b_signed = bytes(signed_message)

aes_enc_msg = iv + aes_cipher.encrypt(b_signed)
# print('aes_enc_msg')
# print(aes_enc_msg)


#Recieve the Public Key of the recipient
r_public_key = RSA.importKey(open('public_r.pem').read())

#Encrypt one-time session key with receivers public key
rsa_cipher = PKCS1_OAEP.new(r_public_key)
encrypted_session_key = rsa_cipher.encrypt(session_key)
# print('encrypted_session_key\n')
# print(encrypted_session_key)

#final message

final_message = aes_enc_msg +delimiter+ encrypted_session_key
#message is ready to sent
file = open('final_enc_msg','w')
try:
	file.write(final_message)
except Exception, e:
	raise e
finally:
	file.close()
print('\nDigitally signed and encrypted message to send saved in final_enc_msg file.')






