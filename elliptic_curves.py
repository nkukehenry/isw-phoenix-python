import base64
import hashlib
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

class EllipticCurveUtils:

    def __init__(self, protocol):
        self.protocol = protocol

    def load_public_key(self, data):
        return ECC.import_key(data)

    def load_private_key(self, data):
        return ECC.import_key(data)

    @staticmethod
    def save_private_key(key):
        return key.export_key(format='PEM').decode('utf-8')

    @staticmethod
    def save_public_key(key):
        return key.export_key(format='PEM').decode('utf-8')

    @staticmethod
    def get_signature(plaintext, private_key):
        h = SHA256.new(plaintext.encode('utf-8'))
        signer = DSS.new(private_key, 'fips-186-3')
        signature = signer.sign(h)
        return base64.b64encode(signature).decode('utf-8')

    def verify_signature(self, signature, plaintext, public_key):
        h = SHA256.new(plaintext.encode('utf-8'))
        verifier = DSS.new(public_key, 'fips-186-3')
        try:
            verifier.verify(h, base64.b64decode(signature))
            return True
        except ValueError:
            return False

    def do_ecdh(self, private_key, public_key):
        priv_key = ECC.import_key(private_key)
        pub_key = ECC.import_key(public_key)
        shared_secret = ECC.ECDH(priv_key).do_exchange(pub_key.pointQ)
        return base64.b64encode(shared_secret).decode('utf-8')

    def generate_keypair(self):
        return ECC.generate(curve=self.protocol)

    @staticmethod
    def get_private_key(pair):
        return EllipticCurveUtils.save_private_key(pair)

    @staticmethod
    def get_public_key(pair):
        return EllipticCurveUtils.save_public_key(pair)
