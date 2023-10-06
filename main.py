import base64
import hashlib
import uuid
import json
import logging
import getpass
from datetime import datetime
from pytz import timezone
import pytz
from app_crpyto_utils import CryptoUtils  # Import CryptoUtils from the crypto_utils module
from auth_utils import AuthUtils  # Import AuthUtils from the auth_utils module
from http_utils import HttpUtil  # Import HttpUtil from the http_utils module
from elliptic_curves import EllipticCurveUtils

# Constants
ROOT_LINK    = "your_root_link"
MY_SERIAL_ID = "your_serial_id"
TERMINAL_ID  = "your_terminal_id"
ACCOUNT_PWD  = "your_account_password"
APP_VERSION  = "your_app_version"

class ClientRegistration:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.base_url = f"{ROOT_LINK}client/"
        self.registration_endpoint_url = f"{self.base_url}clientRegistration"
        self.registration_completion_endpoint_url = f"{self.base_url}completeClientRegistration"

    def main(self):
        key_pair = CryptoUtils.generate_key_pair()
        private_key = base64.b64encode(key_pair.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )).decode('utf-8')
        public_key = base64.b64encode(key_pair.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )).decode('utf-8')

        print(f"private key {private_key}")
        print(f"public key {public_key}")

        curve_utils = EllipticCurveUtils("ECDH")
        key_pair = curve_utils.generate_keypair()
        curve_private_key = curve_utils.get_private_key(key_pair)
        curve_public_key = curve_utils.get_public_key(key_pair)

        response = self.client_registration_request(public_key, curve_public_key, private_key)

        registration_response = json.loads(response)
        if registration_response["responseCode"] != "90000":
            self.logger.info(f"Client Registration failed: {registration_response['responseMessage']}")
        else:
            decrypted_session_key = CryptoUtils.decrypt_with_private(registration_response['serverSessionPublicKey'], private_key)
            terminal_key = curve_utils.do_ecdh(curve_private_key, decrypted_session_key)

            self.logger.info("==============terminalKey==============")
            self.logger.info(f"terminalKey: {terminal_key}")

            auth_token = CryptoUtils.decrypt_with_private(registration_response['authToken'], private_key)
            self.logger.info(f"authToken {auth_token}")

            transaction_reference = registration_response['transactionReference']
            self.logger.info("Enter received OTP:")
            otp = getpass.getpass()

            final_response = self.complete_registration(terminal_key, auth_token, transaction_reference, otp, private_key)

            response = json.loads(final_response)
            if response["responseCode"] == "90000":
                if "clientSecret" in response and len(response["clientSecret"]) > 5:
                    client_secret = CryptoUtils.decrypt_with_private(response["clientSecret"], private_key)
                    self.logger.info(f"clientSecret: {client_secret}")
            else:
                self.logger.info(f"finalResponse: {response['responseMessage']}")

    def client_registration_request(self, public_key, client_session_public_key, private_key):
        setup = {
            "serialId": MY_SERIAL_ID,
            "name": "API Client",
            "nin": "123456",
            "ownerPhoneNumber": "00000",
            "phoneNumber": "00000000",
            "publicKey": public_key,
            "requestReference": str(uuid.uuid4()),
            "terminalId": TERMINAL_ID,
            "gprsCoordinate": "",
            "clientSessionPublicKey": client_session_public_key
        }

        headers = AuthUtils.generate_interswitch_auth("POST", self.registration_endpoint_url, "", "", "", private_key)
        json_data = json.dumps(setup)

        return HttpUtil.post_http_request(self.registration_endpoint_url, headers, json_data)

    def complete_registration(self, terminal_key, auth_token, transaction_reference, otp, private_key):
        complete_reg = {
            "terminalId": TERMINAL_ID,
            "serialId": MY_SERIAL_ID,
            "otp": CryptoUtils.encrypt(otp, terminal_key),
            "requestReference": str(uuid.uuid4()),
            "password": CryptoUtils.encrypt(hashlib.sha512(ACCOUNT_PWD.encode()).hexdigest(), terminal_key),
            "transactionReference": transaction_reference,
            "appVersion": APP_VERSION,
            "gprsCoordinate": ""
        }

        headers = AuthUtils.generate_interswitch_auth("POST", self.registration_completion_endpoint_url,
                                                     "", auth_token, terminal_key, private_key)
        json_data = json.dumps(complete_reg)

        return HttpUtil.post_http_request(self.registration_completion_endpoint_url, headers, json_data)
