import hashlib
import sys

# --- Your data from the website ---
KNOWN_ID = "e6b72deaa0d03d35"
KNOWN_SIG = "3b58587e19723b59defda57f8e2e9e4e500a32234e78598d1fd944a31c95dc38"
TARGET_URL = "http://52.59.124.14:5005/view.php"

def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

def get_key_offset(byte_val):
    return (byte_val % 3) * 8

def recover_key(data_str, sig_hex):
    try:
        sig = bytes.fromhex(sig_hex)
    except ValueError:
        print("[-] Signature format error")
        return {}
        
    # Emulating hash('sha256', $d, 1) from PHP
    h = hashlib.sha256(data_str.encode()).digest()

    O = [sig[i:i+8] for i in range(0, 32, 8)]
    B = [h[i:i+8] for i in range(0, 32, 8)]
    
    key_parts = {}

    # Block 0: K = O[0] ^ B[0]
    p0 = get_key_offset(B[0][0])
    key_parts[p0] = xor_bytes(O[0], B[0])
    
    # Remaining blocks: K = O[i] ^ B[i] ^ O[i-1]
    for i in range(1, 4):
        p = get_key_offset(B[i][0])
        k = xor_bytes(xor_bytes(O[i], B[i]), O[i-1])
        key_parts[p] = k
        
    return key_parts

def sign_new_data(data_str, key_parts):
    # Reassembling the full key from parts
    if len(key_parts) < 3:
        return None
        
    m = key_parts[0] + key_parts[8] + key_parts[16]
    h = hashlib.sha256(data_str.encode()).digest()
    o = b''
    
    for i in range(4):
        s = i * 8
        b_block = h[s:s+8]
        p = (h[s] % 3) * 8
        c_block = m[p:p+8]
        
        if i == 0:
            val = xor_bytes(b_block, c_block)
        else:
            prev_o = o[s-8:s]
            val = xor_bytes(xor_bytes(b_block, c_block), prev_o)
        o += val
        
    return o.hex()

if __name__ == "__main__":
    print(f"[*] Analyzing ID: {KNOWN_ID}")
    keys = recover_key(KNOWN_ID, KNOWN_SIG)
    
    print(f"[*] Key parts recovered: {len(keys)}/3")
    print(f"    Found offsets: {list(keys.keys())}")

    if len(keys) < 3:
        print("[-] Warning: This paste was not enough to recover the full key.")
        print("[-] Create another paste on the site and add its data to the script.")
    else:
        print("[+] Key fully recovered! Generating payloads:\n")
        
        # List of targets to check
        targets = ["flag"]
        
        for t in targets:
            sig = sign_new_data(t, keys)
            url = f"{TARGET_URL}?id={t}&sig={sig}"
            print(f"Target: {t}")
            print(f"URL: {url}\n")