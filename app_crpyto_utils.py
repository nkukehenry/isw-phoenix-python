import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad
import logging
import sys

# Constants
AES_KEY_SIZE   = 32
AES_BLOCK_SIZE = 16
RSA_KEY_SIZE   = 2048
HASH_ALGORITHM = hashlib.sha256()
PADDING_SCHEME = PKCS1_OAEP.new(None)
SIGNATURE_ALGORITHM = pkcs1_15.new(RSA.import_key)

class CryptoUtils:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def encrypt(self, plaintext, terminal_key):
        try:
            key_bytes = base64.b64decode(terminal_key)
            iv = Random.new().read(AES_BLOCK_SIZE)
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES_BLOCK_SIZE))
            return base64.b64encode(iv + ciphertext).decode('utf-8')
        except Exception as e:
            self.logger.error(f"Exception trace {str(e)}")
            raise Exception("Failure to encrypt object")

    def decrypt(self, encrypted_value, terminal_key):
        try:
            key_bytes = base64.b64decode(terminal_key)
            iv = encrypted_value[:AES_BLOCK_SIZE]
            ciphertext = encrypted_value[AES_BLOCK_SIZE:]
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES_BLOCK_SIZE)
            return plaintext.decode('utf-8')
        except Exception as e:
            self.logger.error(f"Exception trace {str(e)}")
            raise Exception("Failure to decrypt object")

    def decrypt_with_private(self, plaintext, private_key):
        try:
            private_key = RSA.import_key(private_key)
            cipher = PKCS1_OAEP.new(private_key)
            message = base64.b64decode(plaintext)
            decrypted_data = cipher.decrypt(message)
            return decrypted_data.decode('utf-8')
        except Exception as e:
            self.logger.error(f"Exception trace {str(e)}")
            raise Exception("Failure to decryptWithPrivate")

    def sign_with_private_key(self, data, private_key):
        try:
            if data == "":
                return ""
            private_key = RSA.import_key(private_key)
            signature = pkcs1_15.new(private_key)
            hashed_data = HASH_ALGORITHM.new(data.encode('utf-8')).digest()
            signature_value = signature.sign(hashed_data)
            return base64.b64encode(signature_value).decode('utf-8')
        except Exception as e:
            self.logger.error(f"Exception trace {str(e)}")
            raise Exception("Failure to signWithPrivateKey")

    def verify_signature(self, signature, message, public_key):
        try:
            public_key = RSA.import_key(public_key)
            signature = base64.b64decode(signature)
            hashed_message = HASH_ALGORITHM.new(message.encode('utf-8')).digest()
            pkcs1_15.new(public_key).verify(hashed_message, signature)
            return True
        except Exception as e:
            self.logger.error(f"Exception trace {str(e)}")
            return False

    @staticmethod
    def get_rsa_private_key(private_key):
        try:
            return RSA.import_key(private_key)
        except Exception as e:
            self.logger.error(f"Exception trace {str(e)}")
            raise Exception("Failure to getRSAPrivate")

    @staticmethod
    def generate_key_pair():
        try:
            key_pair = RSA.generate(RSA_KEY_SIZE)
            return key_pair
        except Exception as e:
            self.logger.error(f"Exception trace {str(e)}")
            raise Exception("Failure to generateKeyPair")

    @staticmethod
    def get_public_key(public_key_content):
        try:
            return RSA.import_key(base64.b64decode(public_key_content))
        except Exception as e:
            self.logger.error(f"Exception trace {str(e)}")
            raise Exception("Failure to getPublicKey")
