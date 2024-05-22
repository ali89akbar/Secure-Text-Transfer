# import crypto
# import sys
# sys.modules['Crypto'] = crypto
import binascii
import os
import time
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from secretsharing import PlaintextToHexSecretSharer
from secretsharing import SecretSharer


BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS).encode()
unpad = lambda s: s[:-ord(s[len(s)-1:])]


def shamirs_split(file_object):
	text = file_object.read()
	list = PlaintextToHexSecretSharer.split_secret(text,2,2)
	hexcode = SecretSharer.split_secret(list[0][2:],2,2);
	return hexcode,list[1]


def shamirs_join(list,str):
	temp = []
	msg_alpha =  SecretSharer.recover_secret(list[0:2])
	msg_alpha = '1-'+msg_alpha
	temp.append(msg_alpha)
	temp.append(str)
	text = PlaintextToHexSecretSharer.recover_secret(temp[0:2])
	return text


def iv():
    
    return chr(0) * 16






class AESCipher:
    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        cipher = AES.new(self.key, AES.MODE_ECB)
        return base64.b64encode(cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_ECB)
        return self._unpad(cipher.decrypt(enc)).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs).encode()

    def _unpad(self, s):
        return s[:-s[-1]]
