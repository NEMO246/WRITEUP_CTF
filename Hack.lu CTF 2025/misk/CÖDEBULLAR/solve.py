import os
import glob
import hashlib

hash_to_bit_map = {
    '9b6e11ad1b835cd3fb4e4c4999bbcb5b': '0',
    '1cecd8652db95bdb9f5aa3929395115c': '1',
    '0ae91c6d107ae8e01895a611f69b9076': '0',
    'ab43bd902c2bf3afbe6aa57f3aa48fa4': '1',
    '746416a03e4d829898a75eb38bf1620c': '0',
    'ff50ea5e40ca336ec5d16c7883bd6d91': '0',
    'c53416c34afde69145c102886caaa718': '0',
    '4e2c98391db9b709c061de3155a9c5a8': '1',
    'f167917abe2400b1302cc956750a4ad2': '1',
    '1670914879f249f5e010e905cc15a38b': '1',
    '5e8669a685f90ad76ff1e42664bcceeb': '1',
    '361f909edca550bda7c3a500c4e23d2c': '0',
    '5360c0811ae9c834841a1df11435ef39': '1',
    'e5271ec9c7dd3d439048a45967f15aca': '0',
    '5f0cfd2d38e3dcb286168ab55611dd7f': '0',
    '460e7d9bc00a4d9b39eed107859e47b7': '1',
    '12ac15351319e2e13d385b7b1360b421': '1',
    '90ee178e82079f07dc8686b958d643ce': '0',
    '0ba665f502e05b7694b25fc524081908': '0',
    '56da50eb4e1380a8c8f4d4c1a24b1902': '1',
    '0b4bb18662e48c9f25a6ddfd03b72e4e': '1',
    '028e84fb5ac820c8b56c6111570e6e59': '1',
    'bc6b23051aa32592fda8e28d8ee2eb4d': '1',
    '779691412dd42f96f30cd7159d7bede0': '0',
    '235e88ac5da4564e63869bd16eed6923': '1', 
    'e2926976ffb002760c9c22ce60a4fe67': '0',
    'ab1a5c131af9add1fca5a2c51ad59c82': '0',
    '1adbd84414a9670947fde51c7e50793b': '1',
    'cace94a2d4fd007e9785559449f784df': '0',
    '9355b4e9ec7d67c5561b7b22fe94b435': '0',
    'ca337d78c310867a5611646356272df3': '1',
    'c66bd7d67171f5247a12b3acfebe01d9': '0',
}

def get_file_hash(filepath):
    """Calculates the MD5 hash of a file"""
    hasher = hashlib.md5()
    with open(filepath, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

def decode_bits_to_text(binary_string):
    """Converts a binary string into ASCII text"""
    text = ""
    for i in range(0, len(binary_string), 8):
        byte = binary_string[i:i+8]
        if len(byte) == 8:
            try:
                char_code = int(byte, 2)
                text += chr(char_code)
            except Exception:
                text += "?" # Add '?' for non-printable chars
    return text

def main():
    encoded_dir = './encoded'
    
    if not hash_to_bit_map:
        print("Error: 'hash_to_bit_map' is empty. Please run manual_mapper.py first.")
        return

    files = glob.glob(os.path.join(encoded_dir, '*.jpeg'))
    
    # Critically important: sort files numerically
    try:
        files.sort(key=lambda x: int(os.path.basename(x).split('.')[0]))
    except ValueError as e:
        print(f"Error sorting files: {e}")
        return

    print(f"Found {len(files)} files to decode...")
    
    binary_string = ""
    for filepath in files:
        file_hash = get_file_hash(filepath)
        
        if file_hash in hash_to_bit_map:
            bit = hash_to_bit_map[file_hash]
            binary_string += bit
        else:
            print(f"\n! ERROR: Unknown file hash: {file_hash} (for file {filepath})")
            print("! Please add this hash to 'hash_to_bit_map'.")
            return

    print(f"Assembled binary string of length: {len(binary_string)} bits")
    
    # Decode the string
    flag_text = decode_bits_to_text(binary_string)
    
    print("\n--- RESULT ---")
    print(flag_text)

if __name__ == "__main__":
    main()