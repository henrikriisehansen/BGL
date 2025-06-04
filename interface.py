import random
import string
from encryption import encrypt
from decryption import decrypt,DecryptionError,EncodingError,IntegrityError,PaddingError,JSONFormatError

import customtkinter
import json
import os
import re
import webbrowser
from pprint import pformat

BaseUrl = "https://www.trustpilot.com/evaluate-bgl/"


class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        # configure window
        self.title("Business Genearated link")
        self.geometry("1000x680")
        self.font  = customtkinter.CTkFont(family="roboto", size=13, weight="bold")

        # configure grid layout (2x10 grid)
        self.grid_columnconfigure((0, 1), weight=1)
        self.grid_rowconfigure((0,1,2,3,4,5,6,7,8,9,10,11), weight=1)

        self.encrypt_btn = customtkinter.CTkButton(self,text="Encrypt", command=self.encrypt_btn_clicked)
        self.encrypt_btn.grid(row=0, column=0,padx=20,pady=5,sticky="ew")

        self.encryptionkey_label = customtkinter.CTkLabel(self, text="Encryption key", fg_color="transparent",font=self.font)
        self.encryptionkey_label.grid(row=1, column=0, padx=20, pady=5, sticky="ws")

        self.encryptionkey_Entry = customtkinter.CTkEntry(self, placeholder_text="Encryption key")
        self.encryptionkey_Entry.grid(row=2, column=0, padx=20, pady=5, sticky="ewn")

        self.authenticationKey_label = customtkinter.CTkLabel(self, text="Authentication key", fg_color="transparent",font=self.font)
        self.authenticationKey_label.grid(row=3, column=0, padx=20, pady=5, sticky="ws")

        self.authenticationKey_Entry = customtkinter.CTkEntry(self, placeholder_text="Authentication key")
        self.authenticationKey_Entry.grid(row=4, column=0, padx=20, pady=5, sticky="ewn")

        self.domain_label = customtkinter.CTkLabel(self, text="Domain", fg_color="transparent",font=self.font)
        self.domain_label.grid(row=5, column=0, padx=20, pady=5, sticky="ws")

        self.domain_Entry = customtkinter.CTkEntry(self, placeholder_text="Domain")
        self.domain_Entry.grid(row=6, column=0, padx=20, pady=5, sticky="ewn")

        self.payload_label = customtkinter.CTkLabel(self, text="Payload", fg_color="transparent",font=self.font)
        self.payload_label.grid(row=7, column=0, padx=20, pady=5, sticky="ws")

        self.payload = customtkinter.CTkTextbox(self, fg_color="transparent",border_width=1,corner_radius=10)
        self.payload.grid(row=8, column=0, padx=20, pady=5, sticky="ewn")
        
        
        self.payload_str = json.dumps({
            "email": "",
            "name": "",
            "ref": "",
            "skus": ["sku1", "sku2", "sku3"],
            "tags": ["tag1", "tag2", "tag3"]
        },indent=1) 


        self.payload.insert(0.0, self.payload_str)
       
        self.link = customtkinter.CTkLabel(self,text="Business generated link",fg_color="transparent",font=self.font)
        self.link.grid(row=9, column=0, padx=20, pady=5, sticky="ws")

        self.copy_link = customtkinter.CTkButton(self, width=80, text="copy link", command=self.copy_link_callback)
        self.copy_link.grid(row=10, column=0, padx=20, pady=5, sticky="w")

        self.link_btn = customtkinter.CTkButton(self,width=80, text="open link", command=self.link_btn_clicked)
        self.link_btn.grid(row=10, column=0, padx=20, pady=5, sticky="e")

        self.link = customtkinter.CTkEntry(self, placeholder_text="business generated link")
        self.link.grid(row=11, column=0,padx=20, pady=5, sticky="ewn")

        # right column
        self.decrypt_btn = customtkinter.CTkButton(self,text="Decrypt", command=self.decrypt_btn_clicked)
        self.decrypt_btn.grid(row=0, column=1,padx=20,pady=5,sticky="ew")

        self.payload_to_decrypt_label = customtkinter.CTkLabel(self, text="Payload to decrypt", fg_color="transparent",font=self.font)
        self.payload_to_decrypt_label.grid(row=1, column=1, padx=20, pady=5, sticky="w")

        self.payload_to_decrypt_entry = customtkinter.CTkEntry(self, placeholder_text="Payload to decrypt")
        self.payload_to_decrypt_entry.grid(row=2, column=1, padx=20, pady=5, sticky="ewn")

        self.clear_btn = customtkinter.CTkButton(self, width=80, text="Clear", command=self.clear_btn_clicked)
        self.clear_btn.grid(row=3, column=1, padx=20, pady=5, sticky="w")

        self.decrypted_payload_label = customtkinter.CTkLabel(self, text="Decrypted payload / Error message", fg_color="transparent",font=self.font)
        self.decrypted_payload_label.grid(row=7, column=1, padx=20, pady=5, sticky="ws")

        self.decrypted_payload = customtkinter.CTkTextbox(self, fg_color="transparent",border_width=1,corner_radius=10)
        self.decrypted_payload.grid(row=8, column=1, padx=20, pady=5, sticky="ewn")

        # test creadentials
        self.encryptionkey_Entry.insert(0, os.getenv("encryptionkey"))
        self.authenticationKey_Entry.insert(0, os.getenv("authenticationkey"))
        self.domain_Entry.insert(0, os.getenv("domain"))

    def clear_btn_clicked(self):
        self.payload_to_decrypt_entry.delete(0,"end")

    def clear_decrypted_payload(self):

        """Clears the decrypted payload area."""

        self.decrypted_payload.configure(state="normal")  # Enable to modify    
        # self.decrypted_payload.configure(text_color=customtkinter.ThemeManager.theme["CTkTextbox"]["text_color"])
        self.decrypted_payload.delete(0.0, "end")

    def encrypt_btn_clicked(self):

        """Encrypts the payload and generates a business link."""

        if not self.validate_inputs_for_encryption():
            return
        
        self.clear_decrypted_payload() 
        

        # Check if the encryption key, authentication key, and domain are provided
        if not self.encryptionkey_Entry.get() or not self.authenticationKey_Entry.get() or not self.domain_Entry.get():
            self.decrypted_payload.delete(0.0, "end")
            self.decrypted_payload.insert(0.0, "Please fill in all fields.")
            return
        # Check if the payload is valid JSON
        try:
            payload_data = json.loads(self.payload.get(1.0, "end"))
        except json.JSONDecodeError as e:
            self.decrypted_payload.delete(0.0, "end")
            self.decrypted_payload.insert(0.0, f"Invalid JSON payload: {e}")
            return
        try:
            self.encrypted_msg = encrypt(self.payload.get(1.0, "end").encode("utf-8"), self.encryptionkey_Entry.get(), self.authenticationKey_Entry.get())
        except Exception as e:
            self.decrypted_payload.delete(0.0, "end")
            self.decrypted_payload.insert(0.0, e)
            return
        else:
            self.link.delete(0, "end")
            self.link.insert(0, f"{BaseUrl}{self.domain_Entry.get()}?p={self.encrypted_msg}")
            self.payload_to_decrypt_entry.delete(0,"end")
            self.payload_to_decrypt_entry.insert(0, self.encrypted_msg)
        
    def decrypt_btn_clicked(self):

        """Decrypts the payload and displays the result."""
        encrypted_payload_str = self.payload_to_decrypt_entry.get().strip()
        enc_key = self.encryptionkey_Entry.get().strip()
        auth_key = self.authenticationKey_Entry.get().strip()

        if not encrypted_payload_str:
            self._display_message_in_output_area("Payload to decrypt cannot be empty.", is_error=True)
            return
        if not enc_key:
            self._display_message_in_output_area("Encryption Key cannot be empty for decryption.", is_error=True)
            return
        if not auth_key:
            self._display_message_in_output_area("Authentication Key cannot be empty for decryption.", is_error=True)
            return
        
 
        # try:
        #     self.decrypted_msg = decrypt(encrypted_payload_str, enc_key, auth_key)


           
            # self.decrypted_payload.delete(0.0, "end")
            # self.decrypted_payload.insert(0.0, self.decrypted_msg.decode("utf-8")) 
            
        # except Exception as e:
        #     self.decrypted_payload.delete(0.0, "end")
        #     self.decrypted_payload.insert(0.0, e)

        try:
            # Attempt to decrypt the payload
            decrypted_data_obj = decrypt(encrypted_payload_str, enc_key, auth_key)
            formatted_decrypted_data = decrypted_data_obj.decode('utf-8')
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

    def _display_message_in_output_area(self, message: str, is_error: bool = False):
        """Helper to display messages or data in the right-hand output textbox."""
        self.decrypted_payload.configure(state="normal") # Enable to modify
        self.decrypted_payload.delete("0.0", "end")
        self.decrypted_payload.insert("0.0", message)

        print(f"Displaying message: {message}")  # Debugging output
        if is_error:
            self.decrypted_payload.configure(text_color="red")
        else:
            # Use default color
            pass
            # self.decrypted_payload.delete("0.0", "end")
           
           
        self.decrypted_payload.configure(state="disabled") # Disable again
        

    def validate_inputs_for_encryption(self) -> bool:

        """Validates inputs required for encryption."""
        enc_key = self.encryptionkey_Entry.get().strip()
        auth_key = self.authenticationKey_Entry.get().strip()
        domain = self.domain_Entry.get().strip()
        payload_str = self.payload.get("1.0", "end-1c").strip()

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
        
    def random_string(self):
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
    
    def _is_base64(self, s: str) -> bool:
        """Checks if a string could be Base64 encoded."""
        if not s or not isinstance(s, str):
            return False
        # Basic regex for Base64: allows A-Z, a-z, 0-9, +, /, and optional trailing = or ==
        # This doesn't validate padding length strictly but is a good first pass.
        return bool(re.fullmatch(r"^[A-Za-z0-9+/]*={0,2}$", s.strip()))
    
    def copy_link_callback(self):

        self.clipboard_clear()
        self.clipboard_append(self.link.get())
        self.update()

    def is_base64(self,string):
        pattern = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')
        return bool(pattern.fullmatch(string))
    
    def link_btn_clicked(self):
        webbrowser.open_new(f"{self.link.get()}")
