# Securinets CTF Quals 2025 - Lost File 302 Write-up

7z archive: [lostfile.7z](https://drive.google.com/file/d/1Vxd6M50--nzqK-9snaj1oujwK7va26Tx/view)

![Lost File Challenge](images/Lost_File.png)

## Introduction

In this challenge, we were provided with two artifacts: a disk image `disk.ad1` and a memory dump `mem.vmem`. The story is that a friend ran an executable which encrypted an important file. Our goal is to recover the encrypted file by finding the lost encryption key.

## Step 1: Disk Forensics

We begin by analyzing the `disk.ad1` image to understand the file landscape.

### 1.1. Mounting the Image

Using **FTK Imager**, we mount `disk.ad1` as a logical drive (E:). This allows us to browse its file structure, including any deleted files.

### 1.2. Filesystem Exploration

On the user's desktop (`E:\[root]\Documents and Settings\RagdollFan2005\Desktop`), we identify two key files:
*   `locker_sim.exe` — The executable, presumed to be the encryptor.
*   `to_encrypt.txt.enc` — Our encrypted target file.

Next, we investigate the Recycle Bin (`E:\[root]\RECYCLER\S-1-5-21-682003330-706699826-1417001333-1003`), where we find some interesting artifacts.

![Recycle Bin Contents](images/1.jpg)

### 1.3. Recovering the Deleted File

Inside the Recycle Bin, we find:
- **`INFO2`**: A metadata file used by Windows XP to store information about deleted files.
- **`Dc1.txt`**: A renamed, deleted file.

Using the `strings` utility, we analyze `INFO2` to find the original path of the deleted file.

![Analyzing INFO2](images/3.jpg)

The output, `C:\Documents and Settings\RagdollFan2005\Desktop\secret_part.txt`, confirms that a file named `secret_part.txt` was deleted from the desktop. Therefore, `Dc1.txt` must be our deleted file. Opening it reveals its content:

![Contents of Dc1.txt](images/2.jpg)

**Third Key Component:** `sigmadroid`

## Step 2: Reverse Engineering `locker_sim.exe`

To understand how the encryption key is generated, we analyze the `locker_sim.exe` executable in a disassembler (like IDA). An analysis of the `_main` function reveals the entire key generation algorithm.

**Key Findings from the Code:**
1.  **Source String Generation:** The program constructs a single long string from three parts, joined by a `|` delimiter:
    *   An argument passed via the command line.
    *   The computer name, read from the registry.
    *   The content of the `secret_part.txt` file.
    *   String format: `<arg>|<computer_name>|<secret_part_content>`

2.  **Key and IV Generation:**
    *   A **SHA-256** hash is computed from the resulting string.
    *   **AES Key:** The entire 32-byte SHA-256 hash.
    *   **Initialization Vector (IV):** The first 16 bytes of the same hash.

3.  **Encryption:** The file `to_encrypt.txt` is encrypted using the **AES-256** algorithm in **CBC** mode.

```assembly
; The program assembles three pieces of data into one string
.text:00401D7C                 mov     dword ptr [esp+8], offset aSSS ; "%s|%s|%s"
.text:00401D8B                 mov     eax, [ebp+pbData]
.text:00401D8E                 mov     [esp], eax      ; Buffer
.text:00401D91                 call    _snprintf

; Then, a SHA-256 hash is calculated from this string
.text:00401DE4                 call    _sha256_buf

; The hash is used as the key for AES-256 encryption
.text:00401F98                 call    _aes256_encrypt_simple
```

## Step 3: Memory Forensics

Now that we know the algorithm, we need to find the two missing components from the `mem.vmem` dump using **Volatility**.

### 3.1. Finding the Computer Name

We use the `envars` plugin to inspect the environment variables.
```bash
./volatility -f mem.vmem --profile=WinXPSP3x86 envars
```
In the output, we find the `COMPUTERNAME` variable:

![Finding the Computer Name](images/4.jpg)

**Second Key Component:** `RAGDOLLF-F9AC5A`

### 3.2. Finding the Command Line Argument

Since the `locker_sim.exe` process has already terminated, the `cmdline` and `cmdscan` plugins yield no results. We use the `consoles` plugin, which scans console input/output buffers.

```bash
./volatility -f mem.vmem --profile=WinXPSP3x86 consoles
```
This command finds the full command line used to launch the program, including our final unknown component.

![Finding the argument via consoles](images/5.jpg)

**First Key Component:** `hmmisitreallyts`

## Step 4: Decryption

We have assembled all three parts:
1.  **Argument:** `hmmisitreallyts`
2.  **Computer Name:** `RAGDOLLF-F9AC5A`
3.  **`secret_part.txt` content:** `sigmadroid`

We combine them: `hmmisitreallyts|RAGDOLLF-F9AC5A|sigmadroid`

### The `recovery.py` Script

To automate the process, we use a Python script with the `pycryptodome` library.

```python
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
```

Running the script successfully decrypts the file.

![Script Execution Result](images/6.png)

## Step 5: Getting the Flag

The decrypted file contains a long Base64 encoded string.
```
Vm14U1MwMUhTbkJpTVdGc1dsZG9WMWxVUm5KVmJGWnpWR3hhVjAxV1ZteGFXRUpoVmpGYVdGb3hTbWhsVm5CUVZteEtWMWx0ZEZkaVJtUnpXbGRvVmxkRlJsaFdWM1JMVm14V2ExSXhXbGRYYlhob1ZqRktjVkZ0Um1sWlZFNUVWVEphVDJOc1duSlRiR1JGVm14c1dGb3hTbWhsVm5CUVZteHdWMWxXWkZobFIwWkxXVmRTZVZkdFVuSlhiRXAwVjJ4YWMySkVUbGhoUjBaWFYxZDRjVlpzUW5KbFZsSlhWbTE0YVZkV1dtcGFWbWhhVmpGU2NWWnNjRmxVYlhaWFYxZDRWMkl4V2xWWGJYcFdZVEpHVjFZeFNraFdiR2hoVmxSS1YxWnNhR0ZXVjNSM1ZtMTQ=
```

We use **CyberChef** for decoding. Applying the **"From Base64"** operation 5 times in a row reveals the final flag.

![Decoding the Flag in CyberChef](images/7.png)

### **Flag:** `Securinets{screen_registry=mft??}`

## Conclusion

This challenge was an excellent example of a multi-faceted investigation, requiring skills in disk forensics, memory forensics, and reverse engineering to reconstruct the full picture of the incident.