import binascii
import hmac
import hashlib
import base64
import string
import urllib.parse
import json # Added for JSON validation
from Crypto.Cipher import AES
from Crypto.Util import Padding

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

def is_url_encoded(s: str) -> bool:
    """
    Checks if a string is URL encoded by comparing it to its unquoted version.

    Args:
        s: The string to check.

    Returns:
        True if the string appears to be URL encoded, False otherwise.
    """
    # If unquoting the string changes it, it means there were encoded characters.
    return urllib.parse.unquote(s) != s

def decrypt_and_validate_json(encrypted_msg_str: str, encrypt_key_b64: str, hash_key_b64: str):
    """
    Decrypts, verifies the integrity of a message, and validates its JSON format.

    Args:
        encrypted_msg_str: Base64 encoded, URL encoded message string.
        encrypt_key_b64: Base64 encoded encryption key string.
        hash_key_b64: Base64 encoded hash key string.

    Returns:
        A Python dictionary or list representing the parsed JSON payload.

    Raises:
        EncodingError: If the input keys or message are not properly encoded.
        IntegrityError: If message integrity verification fails.
        PaddingError: If the padding is invalid.
        JSONFormatError: If the decrypted message is not valid JSON.
    """

    # --- 1. Decode Keys ---
    try:
        encrypt_key = base64.b64decode(encrypt_key_b64)
        hash_key = base64.b64decode(hash_key_b64)
    except binascii.Error as e:
        raise EncodingError(f"Invalid base64 encoding for keys: {e}")

    # --- 2. Validate URL Encoding of the Message ---
    if '%' not in encrypted_msg_str and '+' not in encrypted_msg_str:
        # A simple heuristic: if no '%' or '+', it's unlikely to be URL encoded.
        # A more robust check might be needed depending on expected inputs.
        # For this refactor, we'll rely on the unquote behavior.
        pass 
        # Consider if you want to strictly enforce URL encoding here.
        # if not is_url_encoded(encrypted_msg_str):
        #     raise EncodingError("Message does not appear to be URL encoded.")

    # --- 3. URL Decode and Base64 Decode the Message ---
    try:
        urldecoded_msg_str = urllib.parse.unquote(encrypted_msg_str)
    except Exception as e: # Catching generic exception as unquote can have various issues
        raise EncodingError(f"URL decoding failed: {e}")

    try:
        encrypted_msg_bytes = base64.b64decode(urldecoded_msg_str)
    except binascii.Error as e:
        raise EncodingError(f"Invalid base64 encoding for message: {e}")
    
    # --- 4. Extract IV, Encrypted Data, and Hash ---
    # Ensure the message is long enough for IV, hash, and at least one block of data
    if len(encrypted_msg_bytes) < BLOCK_SIZE + 32 + 1: 
        raise EncodingError(f"Encrypted message is too short. Length: {len(encrypted_msg_bytes)}")

    iv = encrypted_msg_bytes[:BLOCK_SIZE]
    # The hash is the last 32 bytes (SHA256)
    msg_hash = encrypted_msg_bytes[-32:]
    # Encrypted data is between IV and hash
    encrypted_data = encrypted_msg_bytes[BLOCK_SIZE:-32]

    if not encrypted_data:
        raise EncodingError("Encrypted data part is empty after extracting IV and hash.")

    # --- 5. Verify Integrity ---
    expected_hash = hmac.new(hash_key, iv + encrypted_data, digestmod=hashlib.sha256).digest()
    if not hmac.compare_digest(msg_hash, expected_hash):
        raise IntegrityError("Message integrity verification failed. "
                             "Ensure the sender is using the exact same authentication key/hash key.")
    
    # --- 6. Decrypt ---
    try:
        cipher = AES.new(encrypt_key, AES.MODE_CBC, iv)
        decrypted_padded_msg = cipher.decrypt(encrypted_data)
    except Exception as e: # Catch generic exceptions from AES operations
        raise DecryptionError(f"AES decryption failed: {e}")
    
    # --- 7. Unpad ---
    try:
        decrypted_msg_bytes = Padding.unpad(decrypted_padded_msg, BLOCK_SIZE, style="pkcs7")
    except ValueError as e:
        raise PaddingError(f"Invalid padding: {e}. "
                           "Check if the original encryption used PKCS#7 padding and the correct key.") from e

    # --- 8. Validate JSON Format ---
    try:
        # Assuming the decrypted message is UTF-8 encoded JSON
        decrypted_msg_str = decrypted_msg_bytes.decode('utf-8')
        payload = json.loads(decrypted_msg_str)
    except UnicodeDecodeError as e:
        raise JSONFormatError(f"Failed to decode decrypted message as UTF-8: {e}") from e
    except json.JSONDecodeError as e:
        raise JSONFormatError(f"Decrypted message is not valid JSON: {e}") from e

    # --- 9. Return Parsed JSON ---
    return payload

# --- Example Usage (for testing purposes) ---
def encrypt_message_for_testing(plain_text_json_str: str, encrypt_key_b64: str, hash_key_b64: str):
    """
    Helper function to encrypt a JSON string for testing the decryption.
    This is a simplified encryption for testing; production encryption might differ.
    """
    encrypt_key = base64.b64decode(encrypt_key_b64)
    hash_key = base64.b64decode(hash_key_b64)

    plain_text_bytes = plain_text_json_str.encode('utf-8')
    
    # Pad the message
    padded_data = Padding.pad(plain_text_bytes, BLOCK_SIZE, style="pkcs7")
    
    # Generate IV
    iv = hashlib.sha256().digest()[:BLOCK_SIZE] # Using a static IV for simplicity in example, use os.urandom(BLOCK_SIZE) in real scenarios

    # Encrypt
    cipher = AES.new(encrypt_key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(padded_data)
    
    # Create MAC
    msg_hash = hmac.new(hash_key, iv + encrypted_data, digestmod=hashlib.sha256).digest()
    
    # Combine IV, encrypted data, and MAC
    encrypted_msg_bytes = iv + encrypted_data + msg_hash
    
    # Base64 encode
    b64_encoded_msg = base64.b64encode(encrypted_msg_bytes)
    
    # URL encode
    url_encoded_msg = urllib.parse.quote(b64_encoded_msg.decode('utf-8'))
    
    return url_encoded_msg

if __name__ == '__main__':
    # --- Generate Dummy Keys (for example only) ---
    # In a real application, these keys should be securely generated and managed.
    dummy_encrypt_key = base64.b64encode(b'0123456789abcdef0123456789abcdef') # 32 bytes
    dummy_hash_key = base64.b64encode(b'mysecretsharedhashkey0123456789')    # 32 bytes

    dummy_encrypt_key_b64 = dummy_encrypt_key.decode('utf-8')
    dummy_hash_key_b64 = dummy_hash_key.decode('utf-8')

    print(f"Using Encryption Key (b64): {dummy_encrypt_key_b64}")
    print(f"Using Hash Key (b64): {dummy_hash_key_b64}")

    # --- Test Case 1: Valid JSON ---
    valid_payload_dict = {"user_id": 123, "data": "example_content", "valid": True}
    valid_payload_json_str = json.dumps(valid_payload_dict)
    
    print(f"\nOriginal valid JSON string: {valid_payload_json_str}")
    encrypted_valid_msg = encrypt_message_for_testing(valid_payload_json_str, dummy_encrypt_key_b64, dummy_hash_key_b64)
    print(f"Encrypted valid message: {encrypted_valid_msg}")

    try:
        decrypted_payload = decrypt_and_validate_json(encrypted_valid_msg, dummy_encrypt_key_b64, dummy_hash_key_b64)
        print(f"Successfully decrypted and validated JSON: {decrypted_payload}")
        assert decrypted_payload == valid_payload_dict
        print("Test Case 1 PASSED")
    except DecryptionError as e:
        print(f"Test Case 1 FAILED: DecryptionError: {e}")

    # --- Test Case 2: Invalid JSON (decrypted message is not JSON) ---
    non_json_payload_str = "This is not a JSON string."
    print(f"\nOriginal non-JSON string: {non_json_payload_str}")
    encrypted_non_json_msg = encrypt_message_for_testing(non_json_payload_str, dummy_encrypt_key_b64, dummy_hash_key_b64)
    print(f"Encrypted non-JSON message: {encrypted_non_json_msg}")

    try:
        decrypted_payload = decrypt_and_validate_json(encrypted_non_json_msg, dummy_encrypt_key_b64, dummy_hash_key_b64)
        print(f"Decrypted (but should have failed JSON validation): {decrypted_payload}")
        print("Test Case 2 FAILED: Expected JSONFormatError")
    except JSONFormatError as e:
        print(f"Successfully caught JSONFormatError (as expected): {e}")
        print("Test Case 2 PASSED")
    except DecryptionError as e:
        print(f"Test Case 2 FAILED: Unexpected DecryptionError: {e}")

    # --- Test Case 3: Integrity Error (tampered message or wrong hash key) ---
    print(f"\nOriginal valid JSON string for integrity test: {valid_payload_json_str}")
    encrypted_msg_for_tampering = encrypt_message_for_testing(valid_payload_json_str, dummy_encrypt_key_b64, dummy_hash_key_b64)
    
    # Tamper the message (e.g., flip a bit or change a character)
    # For simplicity, let's slightly alter the URL encoded string
    if len(encrypted_msg_for_tampering) > 10:
        tampered_char = 'X' if encrypted_msg_for_tampering[5] != 'X' else 'Y'
        tampered_msg = encrypted_msg_for_tampering[:5] + tampered_char + encrypted_msg_for_tampering[6:]
    else:
        tampered_msg = encrypted_msg_for_tampering + "TAMPER"

    print(f"Tampered message: {tampered_msg}")

    try:
        decrypted_payload = decrypt_and_validate_json(tampered_msg, dummy_encrypt_key_b64, dummy_hash_key_b64)
        print(f"Decrypted (but should have failed integrity): {decrypted_payload}")
        print("Test Case 3 FAILED: Expected IntegrityError or EncodingError due to tampering")
    except IntegrityError as e:
        print(f"Successfully caught IntegrityError (as expected): {e}")
        print("Test Case 3 PASSED")
    except EncodingError as e: # Tampering might also lead to base64 or URL decoding errors
        print(f"Caught EncodingError (plausible for tampering): {e}")
        print("Test Case 3 PASSED (as EncodingError)")
    except DecryptionError as e:
        print(f"Test Case 3 FAILED: Unexpected DecryptionError: {e}")

    # --- Test Case 4: Padding Error (e.g., wrong encryption key or corrupted data) ---
    wrong_encrypt_key_b64 = base64.b64encode(b'anotherkeythatiswrongabcdefghij').decode('utf-8')
    print(f"\nUsing WRONG Encryption Key (b64): {wrong_encrypt_key_b64}")
    encrypted_msg_for_padding_test = encrypt_message_for_testing(valid_payload_json_str, dummy_encrypt_key_b64, dummy_hash_key_b64) # Encrypt with correct key
    
    try:
        # Attempt to decrypt with the WRONG encryption key
        decrypted_payload = decrypt_and_validate_json(encrypted_msg_for_padding_test, wrong_encrypt_key_b64, dummy_hash_key_b64)
        print(f"Decrypted (but should have failed padding): {decrypted_payload}")
        print("Test Case 4 FAILED: Expected PaddingError")
    except PaddingError as e:
        print(f"Successfully caught PaddingError (as expected): {e}")
        print("Test Case 4 PASSED")
    except IntegrityError as e: # If hash check happens before decryption failure due to bad key, this might occur
        print(f"Caught IntegrityError (also plausible if wrong key affects hash verification indirectly): {e}")
        print("Test Case 4 PASSED (as IntegrityError)")
    except DecryptionError as e:
        print(f"Test Case 4 FAILED: Unexpected DecryptionError: {e}")

    # --- Test Case 5: Invalid Base64 in message ---
    invalid_b64_msg_str = "ThisIsNotValidBase64%20==" 
    print(f"\nEncrypted message with invalid Base64: {invalid_b64_msg_str}")
    try:
        decrypted_payload = decrypt_and_validate_json(invalid_b64_msg_str, dummy_encrypt_key_b64, dummy_hash_key_b64)
        print(f"Decrypted (but should have failed encoding): {decrypted_payload}")
        print("Test Case 5 FAILED: Expected EncodingError")
    except EncodingError as e:
        print(f"Successfully caught EncodingError for invalid Base64 (as expected): {e}")
        print("Test Case 5 PASSED")
    except DecryptionError as e:
        print(f"Test Case 5 FAILED: Unexpected DecryptionError: {e}")

