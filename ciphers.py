from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import AES
import hashlib
#import nacl.secret
import base64

BS=32
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[:-ord(s[len(s)-1:])]


class AESCipher(object):
	"""docstring for AESCipher"""
	def __init__(self, key):
		self.key = key

	def encrypt(self, raw):
		raw = pad(raw)
		iv = Random.new().read(AES.block_size)
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		return base64.b64encode(iv + cipher.encrypt(raw))

	def decrypt(self, enc):
		enc = base64.b64decode(enc)
		iv = enc[:16]
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		return unpad(cipher.decrypt(enc[16:]))


class RSACipher(object):
	def __init__(self, key, privkey, pubkey):
		self.skey_cipher = AESCipher(hashlib.sha256(str(key)).digest())
		self.privkey = privkey
		self.pubkey = pubkey

	def encrypt_pub(self, data):
		pubkey_obj = RSA.importKey(self.pubkey)
		return base64.b64encode(pubkey_obj.encrypt(data, "")[0])

	def encrypt_skey(self, data):
		return self.skey_cipher.encrypt(data)

	def decrypt_priv(self, data):
		privkey_obj = RSA.importKey(self.privkey)
		return privkey_obj.decrypt(base64.b64decode(data))

	def decrypt_skey(self, data):
		return self.skey_cipher.decrypt(data)

	def create_asymmetric_key(self):
		key = RSA.generate(1024, e=65537)
		pubkey = key.publickey().exportKey('PEM')
		privkey = key.exportKey('PEM')
		return privkey, pubkey

#x = 12
#cipher = RSACipher(x)
#a = cipher.encrypt_pub("hello")
#print(a)
#print("\n")
#b = cipher.encrypt_skey(a)
#print(b)
#print("\n")
#c = cipher.decrypt_skey(b) 
#print(c)
#print("\n")
#d = cipher.decrypt_priv(c)
#print(d)


#s = 12
#print("\n")
#cipher = AESCipher(s)
#print(cipher.key)
#print("\n")
#print(cipher.decrypt(cipher.encrypt("hello")))
