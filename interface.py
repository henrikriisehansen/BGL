import random
import string
from encryption import encrypt
from decryption import decrypt
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
            "email": f"hrh+{self.random_string()}@trustpilot.com",
            "name": "henrik",
            "ref": f"{self.random_string()}",
            "skus": ["sku1", "sku2", "sku3"],
            "tags": ["tag1", "tag2", "tag3"]
        },indent=1) 
        
        # self.payload_str = json.dumps({
        #     "email": "",
        #     "name": "",
        #     "ref": "",
        #     "skus": ["sku1", "sku2", "sku3"],
        #     "tags": ["tag1", "tag2", "tag3"]
        # },indent=1) 


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

    def encrypt_btn_clicked(self):
        
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
 
        try:
            self.decrypted_msg = decrypt(self.payload_to_decrypt_entry.get(), self.encryptionkey_Entry.get(), self.authenticationKey_Entry.get())
            
            self.decrypted_payload.delete(0.0, "end")
            self.decrypted_payload.insert(0.0, self.decrypted_msg.decode("utf-8")) 
            
        except Exception as e:
            self.decrypted_payload.delete(0.0, "end")
            self.decrypted_payload.insert(0.0, e)
        
        
    def random_string(self):
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
    
    def copy_link_callback(self):

        self.clipboard_clear()
        self.clipboard_append(self.link.get())
        self.update()

    def is_base64(self,string):
        pattern = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')
        return bool(pattern.fullmatch(string))
    
    def link_btn_clicked(self):
        webbrowser.open_new(f"{self.link.get()}")
