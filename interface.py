from encryption import encrypt
from decryption import decrypt
import customtkinter
import json

BaseUrl = "https://www.trustpilot.com/evaluate-bgl/"


class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.title("Business Genearated link")
        self.geometry("800x600")
        self.grid_columnconfigure((0, 1), weight=1)

        self.button = customtkinter.CTkButton(self, width=400, text="Encrypt", command=self.button_callback)
        self.button.grid(row=0, column=0, padx=20, pady=20, sticky="w")
        
        self.encryptionkey_label = customtkinter.CTkLabel(self, text="Encryption key", fg_color="transparent")
        self.encryptionkey_label.grid(row=1, column=0, padx=20, pady=5, sticky="w")

        self.encryptionkey_Entry = customtkinter.CTkEntry(self, width=400, placeholder_text="Encryption key")
        self.encryptionkey_Entry.grid(row=2, column=0, padx=20, pady=5, sticky="w")

        self.authenticationKey_label = customtkinter.CTkLabel(self, text="Authentication key", fg_color="transparent")
        self.authenticationKey_label.grid(row=3, column=0, padx=20, pady=5, sticky="w")

        self.authenticationKey_Entry = customtkinter.CTkEntry(self, width=400, placeholder_text="Authentication key")
        self.authenticationKey_Entry.grid(row=4, column=0, padx=20, pady=5, sticky="w")

        self.domain_label = customtkinter.CTkLabel(self, text="Domain", fg_color="transparent")
        self.domain_label.grid(row=5, column=0, padx=20, pady=5, sticky="w")

        self.domain_Entry = customtkinter.CTkEntry(self, width=400, placeholder_text="Domain")
        self.domain_Entry.grid(row=6, column=0, padx=20, pady=5, sticky="w")

        self.textbox = customtkinter.CTkTextbox(self, width=400,height=200,fg_color="transparent",border_width=1,corner_radius=10)
        self.textbox.grid(row=7, column=0, padx=20, pady=5,sticky="w")
        
        self.textbox.insert(0.0, json.dumps({
            "email": "hrh+werwerwerwr234243@trustpilot.com",
            "name": "henrik",
            "ref": "1234",
            "skus": ["sku1", "sku2", "sku3"],
            "tags": ["tag1", "tag2", "tag3"]
        },indent=1))

        # test creadentials
        self.encryptionkey_Entry.insert(0, "B5EXjitZol4J/wnEk47mf3LTKaemRc9xZA8w5uuzu1k=")
        self.authenticationKey_Entry.insert(0, "r+Ju4699AH6nHNLIfhZd5Tzfdf1c6cVOuVCthRYQsdI=")
        self.domain_Entry.insert(0, "test-enterprise-privacy.tp-testing.com")

    def button_callback(self):
        
        encrypted_msg = encrypt(self.textbox.get(1.0, "end").encode("utf-8"), self.encryptionkey_Entry.get(), self.authenticationKey_Entry.get())

        print(f"https://www.trustpilot.com/evaluate-bgl/{self.domain_Entry.get()}?p={encrypted_msg}")

        # decrypted_msg = decrypt(encrypted_msg, self.encryptionkey_Entry.get(), self.authenticationKey_Entry.get())
        # print(f"decrypted_msg: %s" % decrypted_msg.decode())