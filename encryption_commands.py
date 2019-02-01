from Crypto.PublicKey import RSA
import base64
from Crypto.Cipher import AES
from Crypto import Random


def pad(s):
	return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)


def encrypt_aes(data, key):
	padded = pad(data)
	iv = Random.new().read(16)
	cipher = AES.new(key, AES.MODE_CBC, iv)
	return base64.b64encode(iv + cipher.encrypt(padded))


def decrypt_rsa(data):
	private_key_string = open("private_key.pem", "rb").read()
	private_key = RSA.importKey(private_key_string)
	raw_cipher_data = base64.b64decode(data)
	decrypted = private_key.decrypt(raw_cipher_data)
	return decrypted.split(b'\x00')[-1]


def decrypt_aes(data, key):
	raw_cipher_data = base64.b64decode(data)
	iv = raw_cipher_data[:16]
	cipher = AES.new(key, AES.MODE_CBC, iv)
	return cipher.decrypt(raw_cipher_data[16:])
