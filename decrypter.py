from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

# read the enc message
file = open('final_enc_msg','r')
final_message =file.read()
file.close()
#print('final_message')
#print(final_message)

delimiter = '=='

splited_msg =final_message.split(delimiter)

enc_message = splited_msg[0]
enc_session_key = splited_msg[1]

#Read the Private Key of the recipient
r_private_key = RSA.importKey(open('private_r.pem').read())

#decrypt one-time session key with receivers private key

rsa_cipher = PKCS1_OAEP.new(r_private_key)
decrypted_session_key = rsa_cipher.decrypt(enc_session_key)
#print('decrypted_session_key')
#print(decrypted_session_key)

# decrypting encrypted signed message using aes
iv = Random.new().read(AES.block_size)
aes_cipher = AES.new(decrypted_session_key, AES.MODE_CFB, iv)
dec_signed_msg =aes_cipher.decrypt(enc_message)

ret = str(dec_signed_msg)
dec_signed_msg = ret[AES.block_size:]
# print('signed_message')
# print(dec_signed_msg)

message = dec_signed_msg.split(delimiter)[0]
# Verifying Signature
signature = dec_signed_msg.split(delimiter)[1]
s_public_key = RSA.importKey(open('public.pem').read())
message_hash = SHA256.new(message)
verifier = PKCS1_v1_5.new(s_public_key)
if verifier.verify(message_hash, signature):
 	print "The signature is authentic."
 	print("Data Received:")
 	msg_list = message.split(',')
 	for item in msg_list:
 		print "\t" + item
else:
	print "The signature is not authentic."