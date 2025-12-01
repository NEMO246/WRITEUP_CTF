import base64

def get_key_seed():
    """Returns the hardcoded key (from method K())."""
    return 0x5f9d7bc3

def get_encrypted_data():
    """Assembles and decodes the Base64 string (from method E())."""
    part1 = "fH6Da4rCaxDW/"
    part2 = "lvs32vwcvJcmy"
    part3 = "9TgPQaLHfJuw=="
    
    base64_string = part1 + part2 + part3
    return base64.b64decode(base64_string)

def xorshift(n):
    """Performs the Xorshift operation to generate pseudo-random numbers (from method X())."""
    # & 0xffffffff simulates a 32-bit unsigned integer
    n &= 0xffffffff
    n ^= (n << 13) & 0xffffffff
    n ^= (n >> 17) & 0xffffffff
    n ^= (n << 5) & 0xffffffff
    return n

def generate_permutation_table(length, seed):
    """Generates the permutation table (from method P())."""
    arr = list(range(length))
    
    # The initial seed is XORed with a constant before use.
    current_seed = seed ^ 0xA5A5A5A5
    
    # Fisher-Yates shuffle algorithm
    for i in range(length - 1, 0, -1):
        current_seed = xorshift(current_seed)
        j = current_seed % (i + 1)
        arr[i], arr[j] = arr[j], arr[i]
        
    return arr

def key_to_bytes(key):
    """Splits the 32-bit key into an array of 4 bytes (from method B())."""
    b0 = key & 0xff
    b1 = (key >> 8) & 0xff
    b2 = (key >> 16) & 0xff
    b3 = (key >> 24) & 0xff
    return [b0, b1, b2, b3]

def decrypt_flag():
    """The main function that performs all the steps to decrypt the flag."""
    
    key_seed = get_key_seed()
    encrypted_bytes = get_encrypted_data()
    data_length = len(encrypted_bytes)
    
    key_bytes = key_to_bytes(key_seed)
    permutation_table = generate_permutation_table(data_length, key_seed)
    
    # The rotation amount for the circular shift is determined from the key
    ror_amount = (key_seed >> 27) & 7
    
    decrypted_bytes = [0] * data_length
    
    # Main decryption loop
    for i in range(data_length):
        # 1. Get the encrypted byte according to the permutation table
        permuted_index = permutation_table[i]
        encrypted_byte = encrypted_bytes[permuted_index]
        
        # 2. Subtract the index
        temp_byte = (encrypted_byte - i) & 0xff
        
        # 3. Perform a circular right shift (ROR)
        rotated_byte = ((temp_byte >> ror_amount) | (temp_byte << (8 - ror_amount))) & 0xff
        
        # 4. XOR with the corresponding key byte
        key_byte = key_bytes[i % 4]
        decrypted_byte = rotated_byte ^ key_byte
        
        decrypted_bytes[i] = decrypted_byte

    # 5. Convert the byte array to a string
    return bytes(decrypted_bytes).decode('utf-8')

# --- Run the program ---
if __name__ == "__main__":
    try:
        flag = decrypt_flag()
        print("Decryption complete.")
        print(f"Flag: {flag}")
    except Exception as e:
        print(f"An error occurred: {e}")