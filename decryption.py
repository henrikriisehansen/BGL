import hmac
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Util import Padding
import urllib.parse

BLOCK_SIZE = 16

def decrypt(encrypted_msg, encrypt_key, hash_key):
    """
    Decrypt and verify the integrity of a message.

    Args:
        param encrypted_msg: Base64 encoded message
        param encrypt_key: Base64 encoded encryption key
        param hash_key: Base64 encoded hash key

    Returns:
        Decrypted message bytes, or None if verification fails
    """

    encrypt_key = base64.b64decode(encrypt_key)
    hash_key = base64.b64decode(hash_key)

    urldecoded_msg = urllib.parse.unquote(encrypted_msg)
    encrypted_msg = base64.b64decode(urldecoded_msg)

    iv = encrypted_msg[:BLOCK_SIZE]
    encrypted_data = encrypted_msg[BLOCK_SIZE:-32]  # Exclude IV and MAC
    msg_hash = encrypted_msg[-32:]                 # Extract MAC

    # Verify message integrity
    expected_hash = hmac.new(hash_key, iv + encrypted_data, digestmod=hashlib.sha256).digest()
    if not hmac.compare_digest(msg_hash, expected_hash):
        return None  # Message has been tampered with

    # Decrypt the message
    cipher = AES.new(encrypt_key, AES.MODE_CBC, iv)
    decrypted_padded_msg = cipher.decrypt(encrypted_data)
    return Padding.unpad(decrypted_padded_msg, BLOCK_SIZE, style="pkcs7") 
