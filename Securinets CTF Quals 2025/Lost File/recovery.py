import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# All key components
command_line_arg = "hmmisitreallyts"
computer_name = "RAGDOLLF-F9AC5A"
secret_part_content = "sigmadroid"

# Filenames
encrypted_file_name = "to_encrypt.txt.enc"
decrypted_file_name = "to_encrypt.txt.decrypted"

def decrypt_file():
    """
    Decrypts the file based on the three-part key.
    """
    try:
        # Step 1: Assemble the full string for key generation
        combined_string = f"{command_line_arg}|{computer_name}|{secret_part_content}"
        print(f"[+] Combined string for hashing: {combined_string}")

        # Step 2: Calculate the SHA-256 hash
        sha256_hash = hashlib.sha256(combined_string.encode()).digest()
        print(f"[+] SHA-256 hash (hex): {sha256_hash.hex()}")

        # Step 3: Extract the AES Key and IV
        aes_key = sha256_hash      # The entire 32-byte hash is the key
        aes_iv = sha256_hash[:16]  # The first 16 bytes are the IV
        print(f"[+] AES Key: {aes_key.hex()}")
        print(f"[+] AES IV: {aes_iv.hex()}")

        # Step 4: Read and decrypt the file
        with open(encrypted_file_name, 'rb') as f:
            ciphertext = f.read()
        print(f"[+] Encrypted file '{encrypted_file_name}' read successfully.")
        
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)
        decrypted_padded_data = cipher.decrypt(ciphertext)
        decrypted_data = unpad(decrypted_padded_data, AES.block_size)
        print("\n[+] FILE DECRYPTED SUCCESSFULLY!")

        # Step 5: Save the result
        with open(decrypted_file_name, 'wb') as f:
            f.write(decrypted_data)
        print(f"[+] Decrypted data saved to '{decrypted_file_name}'.")
        
        print("\n--- File Content ---")
        print(decrypted_data.decode('utf-8', errors='ignore'))
        print("--------------------")

    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    decrypt_file()