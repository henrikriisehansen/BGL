import hmac
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Util import Padding
import urllib.parse

BLOCK_SIZE = 16

def encrypt(msg, encrypt_key, hash_key):
    """
    Encrypt and hash a message, then URL-encode the result.

    Args:
        param msg: Bytes to encrypt
        param encrypt_key: Base64 encoded encryption key
        param hash_key: Base64 encoded hash key

    Returns:
        URL-encoded Base64 encoded message
    """
    encrypt_key = base64.b64decode(encrypt_key)
    hash_key = base64.b64decode(hash_key)

    padded_msg = Padding.pad(msg, BLOCK_SIZE, style="pkcs7")

    cipher = AES.new(encrypt_key, AES.MODE_CBC)
    encrypted_msg = cipher.encrypt(padded_msg)

    msg_hash = hmac.new(hash_key, cipher.iv + encrypted_msg, digestmod=hashlib.sha256).digest()
   
    # Convert bytes to string before URL-encoding
    base64_msg = base64.b64encode(cipher.iv + encrypted_msg + msg_hash).decode('utf-8') 

    return urllib.parse.quote(base64_msg) 