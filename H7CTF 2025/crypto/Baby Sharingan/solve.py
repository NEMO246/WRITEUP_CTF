def xor_hex_strings(hex_str1, hex_str2):
    """XORs two hex strings and returns a hex result."""
    bytes1 = bytes.fromhex(hex_str1)
    bytes2 = bytes.fromhex(hex_str2)
    
    length = min(len(bytes1), len(bytes2))
    xored_bytes = bytearray(length)
    
    for i in range(length):
        xored_bytes[i] = bytes1[i] ^ bytes2[i]
        
    return xored_bytes.hex()

def hex_to_ascii(hex_str):
    """Converts hex to ASCII, ignoring errors."""
    try:
        return bytes.fromhex(hex_str).decode('utf-8', errors='ignore')
    except ValueError:
        return "[Error decoding hex]"

# --- Data from the challenge ---
c1 = "03763f242b333d48701023217121112b31713c065279236767395317714c3f1a36604d"
p1 = "4b414b4153484920434f50494553204556455259204a5554535520484520534545532e"
c2 = "1c7f31453b34243113113a267e33113d33662714376056647d383b7f6725201a3d674322613130341b7e3b2b56"
p2 = "54484520434f5059204e494e4a4120535452494b455320574954482053494c454e5420505245434953494f4e2e"

# --- Calculation ---
print("[*] Recovering Key 1 (Leaf Scroll)...")
key1_hex = xor_hex_strings(p1, c1)
print(f"    HEX:   {key1_hex}")
print(f"    ASCII: {hex_to_ascii(key1_hex)}\n")

print("[*] Recovering Key 2 (ANBU Report)...")
key2_hex = xor_hex_strings(p2, c2)
print(f"    HEX:   {key2_hex}")
print(f"    ASCII: {hex_to_ascii(key2_hex)}\n")