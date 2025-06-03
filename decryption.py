import binascii
import hmac
import hashlib
import base64
import string
from Crypto.Cipher import AES
from Crypto.Util import Padding
import urllib.parse

BLOCK_SIZE = 16

class DecryptionError(Exception):
    """Base class for custom decryption errors."""
    pass

class EncodingError(DecryptionError):
    """Raised when the input is not properly URL or Base64 encoded."""
    pass

class IntegrityError(DecryptionError):
    """Raised when the message fails integrity verification."""
    pass

class PaddingError(DecryptionError):
    """Raised when the padding is invalid."""
    pass

class JSONFormatError(DecryptionError):
    """Raised when the decrypted message is not valid JSON."""
    pass


def decrypt(encrypted_msg, encrypt_key, hash_key):
    """Decrypts and verifies the integrity of a message.

    Args:
        encrypted_msg: Base64 encoded, URL encoded message
        encrypt_key: Base64 encoded encryption key
        hash_key: Base64 encoded hash key

    Returns:
        Decrypted message bytes.

    Raises:
        EncodingError: If the input is not URL encoded.
        IntegrityError: If message integrity verification fails.
        PaddingError: If the padding is invalid.
    """

    encrypt_key = base64.b64decode(encrypt_key)
    hash_key = base64.b64decode(hash_key)

    if not is_url_encoded(encrypted_msg):
        raise EncodingError("Message is not URL encoded.")

    try:
        urldecoded_msg = urllib.parse.unquote(encrypted_msg)
        encrypted_msg = base64.b64decode(urldecoded_msg)
    except (binascii.Error, ValueError) as e:
        raise EncodingError(f"Invalid base64 encoding: {e}")
    
    iv = encrypted_msg[:BLOCK_SIZE]
    encrypted_data = encrypted_msg[BLOCK_SIZE:-32] 
    msg_hash = encrypted_msg[-32:]

    # Verify message integrity
    expected_hash = hmac.new(hash_key, iv + encrypted_data, digestmod=hashlib.sha256).digest()
    if not hmac.compare_digest(msg_hash, expected_hash):
        raise IntegrityError("Message integrity verification failed.\nDouble-check that the sender are using the exact same authentication key/hash key.")
    
   
    # Decrypt the message
    try:
        cipher = AES.new(encrypt_key, AES.MODE_CBC, iv)
        decrypted_padded_msg = cipher.decrypt(encrypted_data)
        decrypted_msg = Padding.unpad(decrypted_padded_msg, BLOCK_SIZE, style="pkcs7")
    except ValueError as e:
        raise PaddingError(f"Invalid padding: {e} Double-Check Encryption: Make sure the original encryption process is using PKCS#7 padding correctly.Verify Data Integrity: Ensure the encrypted message hasn't been tampered with during transmission or storage. You can use checksums or message authentication codes (MACs) for this. Confirm Keys: Absolutely make sure you are using the correct decryption key.") from e

    return decrypted_msg 

def is_url_encoded(encrypted_msg):
    """
    Attempts to decode a string and checks for errors.

    Args:
        encrypted_msg: The string to check.

    Returns:
        True if successfully decoded (likely URL encoded), False otherwise.
    """

    decoded = urllib.parse.unquote(encrypted_msg)
    return decoded != encrypted_msg  # True if encoded, False if not
    

   




















































































# import hmac
# import hashlib
# import base64
# from Crypto.Cipher import AES
# from Crypto.Util import Padding
# import urllib.parse

# BLOCK_SIZE = 16

# def decrypt(encrypted_msg, encrypt_key, hash_key):
#     """
#     Decrypt and verify the integrity of a message.

#     Args:
#         param encrypted_msg: Base64 encoded message
#         param encrypt_key: Base64 encoded encryption key
#         param hash_key: Base64 encoded hash key

#     Returns:
#         Decrypted message bytes, or None if verification fails
#     """

#     encrypt_key = base64.b64decode(encrypt_key)
#     hash_key = base64.b64decode(hash_key)

#     if not is_url_encoded(encrypted_msg):
#         raise Exception("URL is not url encoded!") # Or raise an appropriate error
    
#     urldecoded_msg = urllib.parse.unquote(encrypted_msg)
#     encrypted_msg = base64.b64decode(urldecoded_msg)

#     iv = encrypted_msg[:BLOCK_SIZE]
#     encrypted_data = encrypted_msg[BLOCK_SIZE:-32]  # Exclude IV and MAC
#     msg_hash = encrypted_msg[-32:]                 # Extract MAC

#     # Verify message integrity
#     expected_hash = hmac.new(hash_key, iv + encrypted_data, digestmod=hashlib.sha256).digest()
#     if not hmac.compare_digest(msg_hash, expected_hash):
        
#         return "Unable to Verify message integrity"

#     # Decrypt the message
#     cipher = AES.new(encrypt_key, AES.MODE_CBC, iv)
#     decrypted_padded_msg = cipher.decrypt(encrypted_data)
#     return Padding.unpad(decrypted_padded_msg, BLOCK_SIZE, style="pkcs7") 

# def is_url_encoded(encrypted_msg):
#     """
#     Attempts to decode a string and checks for errors.

#     Args:
#         encrypted_msg: The string to check.

#     Returns:
#         True if successfully decoded (likely URL encoded), False otherwise.
#     """
#     try:
#         urllib.parse.unquote_plus(encrypted_msg)
#         return True
#     except UnicodeDecodeError:
#         return False
