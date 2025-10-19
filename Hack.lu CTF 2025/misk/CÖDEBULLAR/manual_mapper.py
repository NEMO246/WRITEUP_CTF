import os
import glob
import hashlib

def get_file_hash(filepath):
    """Calculates the MD5 hash of a file"""
    hasher = hashlib.md5()
    with open(filepath, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

encoded_dir = './encoded'
hash_to_bit_map = {}
seen_hashes = set()

# Get and sort all files numerically
files = glob.glob(os.path.join(encoded_dir, '*.jpeg'))
try:
    files.sort(key=lambda x: int(os.path.basename(x).split('.')[0]))
except ValueError:
    print(f"Error sorting files. Ensure filenames are like '0000.jpeg'.")
    exit()

print("Starting manual hash mapping...")
print(f"A total of 32 unique hashes were found.\n")

for filepath in files:
    file_hash = get_file_hash(filepath)
    
    # If this is a new, unseen hash
    if file_hash not in seen_hashes:
        print(f"\n--- NEW HASH FOUND ({len(seen_hashes) + 1}/32) ---")
        print(f"File to inspect: {filepath}")
        print(f"Hash: {file_hash}")
        
        # Ask user for classification
        bit = ""
        while bit not in ('0', '1'):
            bit = input("What's in the picture? (0 = meatball, 1 = hotdog): ")
        
        hash_to_bit_map[file_hash] = bit
        seen_hashes.add(file_hash)
        print(f"-> Saved: '{file_hash}' is '{bit}'")
        
    if len(seen_hashes) == 32:
        print("\n--- All 32 unique hashes have been mapped. ---")
        break

print("\n\n--- COMPLETE DICTIONARY FOR DECODER ---")
print("Copy this dictionary into your decoder.py script:\n")
print("hash_to_bit_map = {")
for file_hash, bit in hash_to_bit_map.items():
    print(f"    '{file_hash}': '{bit}',")
print("}")