import urllib.parse
import base64
import hashlib
import logging
import uuid
from datetime import datetime
from pytz import timezone
import pytz
from app_crpyto_utils import CryptoUtils  # Import CryptoUtils from the crypto_utils module

# Constants
CLIENT_ID = "your_client_id"
CLIENT_SECRET = "your_client_secret"
AUTHORIZATION_REALM = "InterswitchAuth"
ISO_8859_1 = "iso-8859-1"

class AuthUtils:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def generate_interswitch_auth(http_method, resource_url, additional_parameters, auth_token, terminal_key, private_key=""):
        interswitch_auth = {}

        ug_time_zone = timezone("Africa/Kampala")
        calendar = datetime.now(ug_time_zone)
        timestamp = int(calendar.timestamp())

        nonce = uuid.uuid4().hex

        client_id_base64 = base64.b64encode(CLIENT_ID.encode(ISO_8859_1)).decode('utf-8')
        authorization = f"{AUTHORIZATION_REALM} {client_id_base64}"

        encoded_resource_url = urllib.parse.quote(resource_url, encoding=ISO_8859_1)
        signature_cipher = f"{http_method}&{encoded_resource_url}&{timestamp}&{nonce}&{CLIENT_ID}&{CLIENT_SECRET}"

        if additional_parameters and additional_parameters != "":
            signature_cipher += f"&{additional_parameters}"

        print(f"signature cipher {signature_cipher}")  # Change this line to log the signature cipher

        interswitch_auth["Authorization"] = authorization.strip()
        interswitch_auth["Timestamp"] = str(timestamp)
        interswitch_auth["Nonce"] = nonce

        if not private_key:
            interswitch_auth["Signature"] = CryptoUtils.sign_with_private_key(signature_cipher)
        else:
            interswitch_auth["Signature"] = CryptoUtils.sign_with_private_key(signature_cipher, private_key)

        if terminal_key and not terminal_key.isspace():
            auth_token = CryptoUtils.encrypt(auth_token, terminal_key)
        else:
            auth_token = ""

        interswitch_auth["Auth-Token"] = auth_token
        return interswitch_auth
