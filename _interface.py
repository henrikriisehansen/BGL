import customtkinter
import json
import os
import re
import webbrowser
import string
from pprint import pformat

# Assuming encryption.py has:
# def encrypt(plain_text_bytes: bytes, encrypt_key_b64: str, hash_key_b64: str) -> str:
#     # ... returns URL-safe, Base64 encoded string
#     # ... might raise exceptions for bad keys or other issues
from encryption import encrypt 

# Assuming decryption.py has a function like decrypt_and_validate_json,
# which we'll call decrypt_payload here for clarity in the app.
# This function should return a parsed Python object (dict/list) or raise:
#   decryption.JSONFormatError, decryption.IntegrityError, 
#   decryption.PaddingError, decryption.EncodingError
from _decryption import decrypt_and_validate_json as decrypt_payload
from _decryption import DecryptionError, JSONFormatError, IntegrityError, PaddingError, EncodingError # Assuming these are defined

BaseUrl = "https://www.trustpilot.com/evaluate-bgl/"

class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.title("Business Generated Link Tool")
        self.geometry("1000x720") # Slightly increased height for better spacing
        self.default_font = customtkinter.CTkFont(family="Roboto", size=13)
        self.title_font = customtkinter.CTkFont(family="Roboto", size=14, weight="bold")

        # Configure main grid (1 row, 2 columns for left and right frames)
        self.grid_columnconfigure((0, 1), weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Create and place left and right frames
        self.left_frame = customtkinter.CTkFrame(self, corner_radius=10)
        self.left_frame.grid(row=0, column=0, padx=(20, 10), pady=20, sticky="nsew")
        self.right_frame = customtkinter.CTkFrame(self, corner_radius=10)
        self.right_frame.grid(row=0, column=1, padx=(10, 20), pady=20, sticky="nsew")

        self._create_left_frame_widgets()
        self._create_right_frame_widgets()

        self._load_initial_values()

    def _create_left_frame_widgets(self):
        """Creates and grids widgets for the left (encryption) frame."""
        self.left_frame.grid_columnconfigure(0, weight=1)
        # Configure rows to allow spacing and expansion of the textbox
        for i in range(12): # Approximate number of rows needed
             self.left_frame.grid_rowconfigure(i, weight=0) # Default no weight
        self.left_frame.grid_rowconfigure(8, weight=1) # Payload textbox row gets weight

        row_idx = 0

        # --- Encrypt Button ---
        self.encrypt_btn = customtkinter.CTkButton(self.left_frame, text="Encrypt Payload", command=self.encrypt_btn_clicked, font=self.title_font)
        self.encrypt_btn.grid(row=row_idx, column=0, padx=20, pady=(20, 10), sticky="ew")
        row_idx += 1

        # --- Encryption Key ---
        self.encryptionkey_label = customtkinter.CTkLabel(self.left_frame, text="Encryption Key (Base64)", font=self.default_font)
        self.encryptionkey_label.grid(row=row_idx, column=0, padx=20, pady=(10, 0), sticky="w")
        row_idx += 1
        self.encryptionkey_entry = customtkinter.CTkEntry(self.left_frame, placeholder_text="Enter Base64 encryption key")
        self.encryptionkey_entry.grid(row=row_idx, column=0, padx=20, pady=(0, 10), sticky="ew")
        row_idx += 1

        # --- Authentication Key ---
        self.authenticationkey_label = customtkinter.CTkLabel(self.left_frame, text="Authentication Key (Base64)", font=self.default_font)
        self.authenticationkey_label.grid(row=row_idx, column=0, padx=20, pady=(5, 0), sticky="w")
        row_idx += 1
        self.authenticationkey_entry = customtkinter.CTkEntry(self.left_frame, placeholder_text="Enter Base64 authentication key")
        self.authenticationkey_entry.grid(row=row_idx, column=0, padx=20, pady=(0, 10), sticky="ew")
        row_idx += 1

        # --- Domain ---
        self.domain_label = customtkinter.CTkLabel(self.left_frame, text="Domain", font=self.default_font)
        self.domain_label.grid(row=row_idx, column=0, padx=20, pady=(5, 0), sticky="w")
        row_idx += 1
        self.domain_entry = customtkinter.CTkEntry(self.left_frame, placeholder_text="Enter domain (e.g., example.com)")
        self.domain_entry.grid(row=row_idx, column=0, padx=20, pady=(0, 10), sticky="ew")
        row_idx += 1

        # --- Payload ---
        self.payload_input_label = customtkinter.CTkLabel(self.left_frame, text="Payload (JSON format)", font=self.default_font)
        self.payload_input_label.grid(row=row_idx, column=0, padx=20, pady=(5, 0), sticky="w")
        row_idx += 1
        self.payload_input_textbox = customtkinter.CTkTextbox(self.left_frame, border_width=1, corner_radius=8, height=150)
        self.payload_input_textbox.grid(row=row_idx, column=0, padx=20, pady=(0, 10), sticky="nsew")
        row_idx += 1
        
        initial_payload_dict = {
            "email": "customer@example.com", "name": "John Doe", "ref": "order123",
            "skus": ["sku1", "sku2"], "tags": ["tagA", "tagB"]
        }
        self.payload_input_textbox.insert("0.0", json.dumps(initial_payload_dict, indent=2))


        # --- Generated Link ---
        self.generated_link_title_label = customtkinter.CTkLabel(self.left_frame, text="Generated Business Link", font=self.default_font)
        self.generated_link_title_label.grid(row=row_idx, column=0, padx=20, pady=(10, 0), sticky="w")
        row_idx += 1
        
        link_actions_frame = customtkinter.CTkFrame(self.left_frame, fg_color="transparent")
        link_actions_frame.grid(row=row_idx, column=0, padx=20, pady=(0,5), sticky="ew")
        link_actions_frame.grid_columnconfigure((0,1), weight=0) # Buttons don't expand
        link_actions_frame.grid_columnconfigure(2, weight=1) # Spacer

        self.copy_link_btn = customtkinter.CTkButton(link_actions_frame, width=100, text="Copy Link", command=self.copy_link_callback)
        self.copy_link_btn.grid(row=0, column=0, sticky="w")
        self.open_link_btn = customtkinter.CTkButton(link_actions_frame, width=100, text="Open Link", command=self.open_link_btn_clicked)
        self.open_link_btn.grid(row=0, column=1, padx=(10,0), sticky="w")
        row_idx += 1

        self.generated_link_entry = customtkinter.CTkEntry(self.left_frame, placeholder_text="Encrypted link will appear here", state="readonly")
        self.generated_link_entry.grid(row=row_idx, column=0, padx=20, pady=(0, 20), sticky="ew")
        row_idx += 1


    def _create_right_frame_widgets(self):
        """Creates and grids widgets for the right (decryption) frame."""
        self.right_frame.grid_columnconfigure(0, weight=1)
        for i in range(10): # Approximate number of rows
            self.right_frame.grid_rowconfigure(i, weight=0)
        self.right_frame.grid_rowconfigure(5, weight=1) # Decrypted payload textbox gets weight

        row_idx = 0

        # --- Decrypt Button ---
        self.decrypt_btn = customtkinter.CTkButton(self.right_frame, text="Decrypt Payload", command=self.decrypt_btn_clicked, font=self.title_font)
        self.decrypt_btn.grid(row=row_idx, column=0, padx=20, pady=(20, 10), sticky="ew")
        row_idx += 1

        # --- Payload to Decrypt ---
        self.payload_to_decrypt_label = customtkinter.CTkLabel(self.right_frame, text="Encrypted Payload String (from URL 'p' parameter)", font=self.default_font)
        self.payload_to_decrypt_label.grid(row=row_idx, column=0, padx=20, pady=(10, 0), sticky="w")
        row_idx += 1
        self.payload_to_decrypt_entry = customtkinter.CTkEntry(self.right_frame, placeholder_text="Paste encrypted payload string here")
        self.payload_to_decrypt_entry.grid(row=row_idx, column=0, padx=20, pady=(0, 5), sticky="ew")
        row_idx += 1

        # --- Clear Button ---
        self.clear_decryption_input_btn = customtkinter.CTkButton(self.right_frame, width=100, text="Clear Input", command=self.clear_decryption_input_btn_clicked)
        self.clear_decryption_input_btn.grid(row=row_idx, column=0, padx=20, pady=(0, 10), sticky="w")
        row_idx += 1
        
        # --- Decrypted Payload / Error Message ---
        self.output_area_label = customtkinter.CTkLabel(self.right_frame, text="Decrypted Payload / Status", font=self.default_font)
        self.output_area_label.grid(row=row_idx, column=0, padx=20, pady=(10, 0), sticky="w")
        row_idx += 1
        self.output_area_textbox = customtkinter.CTkTextbox(self.right_frame, border_width=1, corner_radius=8, height=200, state="disabled") # Start disabled
        self.output_area_textbox.grid(row=row_idx, column=0, padx=20, pady=(0, 20), sticky="nsew")
        row_idx += 1

    def _load_initial_values(self):
        """Loads initial values from environment variables or defaults."""
        self.encryptionkey_entry.insert(0, os.getenv("ENCRYPTION_KEY", ""))
        self.authenticationkey_entry.insert(0, os.getenv("AUTHENTICATION_KEY", ""))
        self.domain_entry.insert(0, os.getenv("DOMAIN_NAME", "example.com"))

    def _display_message_in_output_area(self, message: str, is_error: bool = False):
        """Helper to display messages or data in the right-hand output textbox."""
        self.output_area_textbox.configure(state="normal") # Enable to modify
        self.output_area_textbox.delete("0.0", "end")
        self.output_area_textbox.insert("0.0", message)
        if is_error:
            self.output_area_textbox.configure(text_color="red")
        else:
            # Reset to default text color (CTk might have specific way, or rely on theme)
            # For simplicity, let's assume default theme color is fine.
            # You might need to store default color and reapply if changing it explicitly.
            # self.output_area_textbox.configure(text_color=customtkinter.ThemeManager.theme["CTkTextbox"]["text_color"])
            pass # Use default color
        self.output_area_textbox.configure(state="disabled") # Disable again

    def _is_base64(self, s: str) -> bool:
        """Checks if a string could be Base64 encoded."""
        if not s or not isinstance(s, str):
            return False
        # Basic regex for Base64: allows A-Z, a-z, 0-9, +, /, and optional trailing = or ==
        # This doesn't validate padding length strictly but is a good first pass.
        return bool(re.fullmatch(r"^[A-Za-z0-9+/]*={0,2}$", s.strip()))

    def validate_inputs_for_encryption(self) -> bool:
        """Validates inputs required for encryption."""
        enc_key = self.encryptionkey_entry.get().strip()
        auth_key = self.authenticationkey_entry.get().strip()
        domain = self.domain_entry.get().strip()
        payload_str = self.payload_input_textbox.get("1.0", "end-1c").strip()

        if not enc_key:
            self._display_message_in_output_area("Encryption Key cannot be empty.", is_error=True)
            return False
        if not self._is_base64(enc_key):
            self._display_message_in_output_area("Warning: Encryption Key does not look like valid Base64.", is_error=True)
            # Not returning False, as some libs might be tolerant. Actual b64decode will fail later if invalid.
        
        if not auth_key:
            self._display_message_in_output_area("Authentication Key cannot be empty.", is_error=True)
            return False
        if not self._is_base64(auth_key):
            self._display_message_in_output_area("Warning: Authentication Key does not look like valid Base64.", is_error=True)

        if not domain:
            self._display_message_in_output_area("Domain cannot be empty.", is_error=True)
            return False
        
        if not payload_str:
            self._display_message_in_output_area("Payload cannot be empty.", is_error=True)
            return False
        try:
            json.loads(payload_str) # Validate if payload is JSON
        except json.JSONDecodeError as e:
            self._display_message_in_output_area(f"Payload is not valid JSON: {e}", is_error=True)
            return False
        return True

    def encrypt_btn_clicked(self):
        if not self.validate_inputs_for_encryption():
            return

        enc_key = self.encryptionkey_entry.get().strip()
        auth_key = self.authenticationkey_entry.get().strip()
        domain = self.domain_entry.get().strip()
        payload_str = self.payload_input_textbox.get("1.0", "end-1c").strip() # end-1c to exclude trailing newline

        try:
            # Encrypt function should handle encoding payload_str to bytes if needed
            encrypted_msg_param = encrypt(payload_str.encode('utf-8'), enc_key, auth_key)
            
            full_link = f"{BaseUrl}{domain}?p={encrypted_msg_param}"
            
            self.generated_link_entry.configure(state="normal")
            self.generated_link_entry.delete(0, "end")
            self.generated_link_entry.insert(0, full_link)
            self.generated_link_entry.configure(state="readonly")

            self.payload_to_decrypt_entry.delete(0, "end")
            self.payload_to_decrypt_entry.insert(0, encrypted_msg_param)
            self._display_message_in_output_area("Payload encrypted successfully. Link generated.", is_error=False)

        except Exception as e: # Catch any exception from encrypt or key processing
            self._display_message_in_output_area(f"Encryption Error: {e}", is_error=True)
            self.generated_link_entry.configure(state="normal")
            self.generated_link_entry.delete(0, "end")
            self.generated_link_entry.configure(state="readonly")


    def decrypt_btn_clicked(self):
        encrypted_payload_str = self.payload_to_decrypt_entry.get().strip()
        enc_key = self.encryptionkey_entry.get().strip() # Use same keys as encryption for decryption
        auth_key = self.authenticationkey_entry.get().strip()

        if not encrypted_payload_str:
            self._display_message_in_output_area("Payload to decrypt cannot be empty.", is_error=True)
            return
        if not enc_key:
            self._display_message_in_output_area("Encryption Key cannot be empty for decryption.", is_error=True)
            return
        if not auth_key:
            self._display_message_in_output_area("Authentication Key cannot be empty for decryption.", is_error=True)
            return

        try:
            # :
            decrypted_data_obj = decrypt_payload(encrypted_payload_str, enc_key, auth_key)
            
            # Pretty format the Python object (dict/list) as a string for display
            formatted_decrypted_data = pformat(decrypted_data_obj, indent=2)
            self._display_message_in_output_area(f"Decryption Successful:\n{formatted_decrypted_data}", is_error=False)
        
        # Specific errors from decryption module
        except JSONFormatError as e:
            self._display_message_in_output_area(f"JSON Format Error: {e}", is_error=True)
        except IntegrityError as e:
            self._display_message_in_output_area(f"Integrity Error: {e}", is_error=True)
        except PaddingError as e:
            self._display_message_in_output_area(f"Padding Error: {e}", is_error=True)
        except EncodingError as e: # Catches Base64 or URL decoding issues within decrypt_payload
            self._display_message_in_output_area(f"Encoding Error: {e}", is_error=True)
        except DecryptionError as e: # Catch-all for other decryption specific errors
            self._display_message_in_output_area(f"Decryption Failed: {e}", is_error=True)
        except Exception as e: # Generic fallback for unexpected errors
            self._display_message_in_output_area(f"An Unexpected Error Occurred: {e}", is_error=True)

    def clear_decryption_input_btn_clicked(self):
        self.payload_to_decrypt_entry.delete(0, "end")
        self._display_message_in_output_area("Decryption input cleared.", is_error=False)
    
    def copy_link_callback(self):
        generated_link = self.generated_link_entry.get()
        if generated_link:
            self.clipboard_clear()
            self.clipboard_append(generated_link)
            self.update() # Required on some systems for clipboard to update
            self._display_message_in_output_area("Link copied to clipboard.", is_error=False)
        else:
            self._display_message_in_output_area("No link generated to copy.", is_error=True)

    def open_link_btn_clicked(self):
        link_to_open = self.generated_link_entry.get()
        if link_to_open:
            try:
                webbrowser.open_new_tab(link_to_open)
                self._display_message_in_output_area(f"Attempting to open link in browser.", is_error=False)
            except Exception as e:
                self._display_message_in_output_area(f"Could not open link: {e}", is_error=True)
        else:
            self._display_message_in_output_area("No link generated to open.", is_error=True)

